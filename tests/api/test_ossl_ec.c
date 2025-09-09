/* test_ossl_ec.c
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

#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdh.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_ec.h>

/*******************************************************************************
 * EC OpenSSL compatibility API Testing
 ******************************************************************************/

#if defined(HAVE_ECC) && !defined(OPENSSL_NO_PK)

int test_wolfSSL_EC_GROUP(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    EC_GROUP *group = NULL;
    EC_GROUP *group2 = NULL;
    EC_GROUP *group3 = NULL;
#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP *group4 = NULL;
#endif
    WOLFSSL_BIGNUM* order = NULL;
    int group_bits;
    int i;
    static const int knownEccNids[] = {
        NID_X9_62_prime192v1,
        NID_X9_62_prime192v2,
        NID_X9_62_prime192v3,
        NID_X9_62_prime239v1,
        NID_X9_62_prime239v2,
        NID_X9_62_prime239v3,
        NID_X9_62_prime256v1,
        NID_secp112r1,
        NID_secp112r2,
        NID_secp128r1,
        NID_secp128r2,
        NID_secp160r1,
        NID_secp160r2,
        NID_secp224r1,
        NID_secp384r1,
        NID_secp521r1,
        NID_secp160k1,
        NID_secp192k1,
        NID_secp224k1,
        NID_secp256k1,
        NID_brainpoolP160r1,
        NID_brainpoolP192r1,
        NID_brainpoolP224r1,
        NID_brainpoolP256r1,
        NID_brainpoolP320r1,
        NID_brainpoolP384r1,
        NID_brainpoolP512r1,
    };
    int knowEccNidsLen = (int)(sizeof(knownEccNids) / sizeof(*knownEccNids));
    static const int knownEccEnums[] = {
        ECC_SECP192R1,
        ECC_PRIME192V2,
        ECC_PRIME192V3,
        ECC_PRIME239V1,
        ECC_PRIME239V2,
        ECC_PRIME239V3,
        ECC_SECP256R1,
        ECC_SECP112R1,
        ECC_SECP112R2,
        ECC_SECP128R1,
        ECC_SECP128R2,
        ECC_SECP160R1,
        ECC_SECP160R2,
        ECC_SECP224R1,
        ECC_SECP384R1,
        ECC_SECP521R1,
        ECC_SECP160K1,
        ECC_SECP192K1,
        ECC_SECP224K1,
        ECC_SECP256K1,
        ECC_BRAINPOOLP160R1,
        ECC_BRAINPOOLP192R1,
        ECC_BRAINPOOLP224R1,
        ECC_BRAINPOOLP256R1,
        ECC_BRAINPOOLP320R1,
        ECC_BRAINPOOLP384R1,
        ECC_BRAINPOOLP512R1,
    };
    int knowEccEnumsLen = (int)(sizeof(knownEccEnums) / sizeof(*knownEccEnums));

    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(group2 = EC_GROUP_dup(group));
    ExpectNotNull(group3 = wolfSSL_EC_GROUP_new_by_curve_name(NID_secp384r1));
#ifndef HAVE_ECC_BRAINPOOL
    ExpectNotNull(group4 = wolfSSL_EC_GROUP_new_by_curve_name(
        NID_brainpoolP256r1));
#endif

    ExpectNull(EC_GROUP_dup(NULL));

    ExpectIntEQ(wolfSSL_EC_GROUP_get_curve_name(NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_curve_name(group), NID_X9_62_prime256v1);

    ExpectIntEQ((group_bits = EC_GROUP_order_bits(NULL)), 0);
    ExpectIntEQ((group_bits = EC_GROUP_order_bits(group)), 256);
#ifndef HAVE_ECC_BRAINPOOL
    ExpectIntEQ((group_bits = EC_GROUP_order_bits(group4)), 0);
#endif

    ExpectIntEQ(wolfSSL_EC_GROUP_get_degree(NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_degree(group), 256);

    ExpectNotNull(order = BN_new());
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(group, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(NULL, order, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_GROUP_get_order(group, order, NULL), 1);
    wolfSSL_BN_free(order);

    ExpectNotNull(EC_GROUP_method_of(group));

    ExpectIntEQ(EC_METHOD_get_field_type(NULL), 0);
    ExpectIntEQ(EC_METHOD_get_field_type(EC_GROUP_method_of(group)),
        NID_X9_62_prime_field);

    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(NULL, NULL, NULL), -1);
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(group, NULL, NULL), -1);
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(NULL, group, NULL), -1);
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(group, group3, NULL), 1);

#ifndef NO_WOLFSSL_STUB
    wolfSSL_EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
#endif

#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP_free(group4);
#endif
    EC_GROUP_free(group3);
    EC_GROUP_free(group2);
    EC_GROUP_free(group);

    for (i = 0; i < knowEccNidsLen; i++) {
        group = NULL;
        ExpectNotNull(group = EC_GROUP_new_by_curve_name(knownEccNids[i]));
        ExpectIntGT(wolfSSL_EC_GROUP_get_degree(group), 0);
        EC_GROUP_free(group);
    }
    for (i = 0; i < knowEccEnumsLen; i++) {
        group = NULL;
        ExpectNotNull(group = EC_GROUP_new_by_curve_name(knownEccEnums[i]));
        ExpectIntEQ(wolfSSL_EC_GROUP_get_curve_name(group), knownEccNids[i]);
        EC_GROUP_free(group);
    }
#endif
   return EXPECT_RESULT();
}

int test_wolfSSL_PEM_read_bio_ECPKParameters(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    EC_GROUP *group = NULL;
    BIO* bio = NULL;
#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && \
    ECC_MIN_KEY_SZ <= 384 && !defined(NO_ECC_SECP)
    EC_GROUP *ret = NULL;
    static char ec_nc_p384[] = "-----BEGIN EC PARAMETERS-----\n"
                               "BgUrgQQAIg==\n"
                               "-----END EC PARAMETERS-----";
#endif
    static char ec_nc_bad_1[] = "-----BEGIN EC PARAMETERS-----\n"
                                "MAA=\n"
                                "-----END EC PARAMETERS-----";
    static char ec_nc_bad_2[] = "-----BEGIN EC PARAMETERS-----\n"
                                "BgA=\n"
                                "-----END EC PARAMETERS-----";
    static char ec_nc_bad_3[] = "-----BEGIN EC PARAMETERS-----\n"
                                "BgE=\n"
                                "-----END EC PARAMETERS-----";
    static char ec_nc_bad_4[] = "-----BEGIN EC PARAMETERS-----\n"
                                "BgE*\n"
                                "-----END EC PARAMETERS-----";

    /* Test that first parameter, bio, being NULL fails. */
    ExpectNull(PEM_read_bio_ECPKParameters(NULL, NULL, NULL, NULL));

    /* Test that reading named parameters works. */
    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntEQ(BIO_read_filename(bio, eccKeyFile), WOLFSSL_SUCCESS);
    ExpectNotNull(group = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    ExpectIntEQ(EC_GROUP_get_curve_name(group), NID_X9_62_prime256v1);
    BIO_free(bio);
    bio = NULL;
    EC_GROUP_free(group);
    group = NULL;

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && \
    ECC_MIN_KEY_SZ <= 384 && !defined(NO_ECC_SECP)
    /* Test that reusing group works. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_p384,
        sizeof(ec_nc_p384)));
    ExpectNotNull(group = PEM_read_bio_ECPKParameters(bio, &group, NULL, NULL));
    ExpectIntEQ(EC_GROUP_get_curve_name(group), NID_secp384r1);
    BIO_free(bio);
    bio = NULL;
    EC_GROUP_free(group);
    group = NULL;

    /* Test that returning through group works. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_p384,
        sizeof(ec_nc_p384)));
    ExpectNotNull(ret = PEM_read_bio_ECPKParameters(bio, &group, NULL, NULL));
    ExpectIntEQ(ret == group, 1);
    ExpectIntEQ(EC_GROUP_get_curve_name(group), NID_secp384r1);
    BIO_free(bio);
    bio = NULL;
    EC_GROUP_free(group);
    group = NULL;
#endif

    /* Test 0x30, 0x00 (not and object id) fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_1,
        sizeof(ec_nc_bad_1)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    /* Test 0x06, 0x00 (empty object id) fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_2,
        sizeof(ec_nc_bad_2)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    /* Test 0x06, 0x01 (badly formed object id) fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_3,
        sizeof(ec_nc_bad_3)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    /* Test invalid PEM encoding - invalid character. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_nc_bad_4,
        sizeof(ec_nc_bad_4)));
    ExpectNull(PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL));
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_i2d_ECPKParameters(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    EC_GROUP* grp = NULL;
    unsigned char p256_oid[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    unsigned char *der = p256_oid;
    unsigned char out_der[sizeof(p256_oid)];

    XMEMSET(out_der, 0, sizeof(out_der));
    ExpectNotNull(d2i_ECPKParameters(&grp, (const unsigned char **)&der,
            sizeof(p256_oid)));
    der = out_der;
    ExpectIntEQ(i2d_ECPKParameters(grp, &der), sizeof(p256_oid));
    ExpectBufEQ(p256_oid, out_der, sizeof(p256_oid));
    EC_GROUP_free(grp);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_POINT(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_SP_MATH) && \
  (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2)))

#ifdef OPENSSL_EXTRA
    BN_CTX* ctx = NULL;
    EC_GROUP* group = NULL;
#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP* group2 = NULL;
#endif
    EC_POINT* Gxy = NULL;
    EC_POINT* new_point = NULL;
    EC_POINT* set_point = NULL;
    EC_POINT* get_point = NULL;
    EC_POINT* infinity = NULL;
    BIGNUM* k = NULL;
    BIGNUM* Gx = NULL;
    BIGNUM* Gy = NULL;
    BIGNUM* Gz = NULL;
    BIGNUM* X = NULL;
    BIGNUM* Y = NULL;
    BIGNUM* set_point_bn = NULL;
    char* hexStr = NULL;

    const char* kTest = "F4F8338AFCC562C5C3F3E1E46A7EFECD"
                        "17AF381913FF7A96314EA47055EA0FD0";
    /* NISTP256R1 Gx/Gy */
    const char* kGx   = "6B17D1F2E12C4247F8BCE6E563A440F2"
                        "77037D812DEB33A0F4A13945D898C296";
    const char* kGy   = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16"
                        "2BCE33576B315ECECBB6406837BF51F5";
    const char* uncompG
                      = "046B17D1F2E12C4247F8BCE6E563A440F2"
                        "77037D812DEB33A0F4A13945D898C296"
                        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16"
                        "2BCE33576B315ECECBB6406837BF51F5";
    const char* compG
                      = "036B17D1F2E12C4247F8BCE6E563A440F2"
                        "77037D812DEB33A0F4A13945D898C296";

#ifndef HAVE_SELFTEST
    EC_POINT *tmp = NULL;
    size_t bin_len;
    unsigned int blen = 0;
    unsigned char* buf = NULL;
    unsigned char bufInf[1] = { 0x00 };

    const unsigned char binUncompG[] = {
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
    };
    const unsigned char binUncompGBad[] = {
        0x09, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
    };

#ifdef HAVE_COMP_KEY
    const unsigned char binCompG[] = {
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    };
#endif
#endif

    ExpectNotNull(ctx = BN_CTX_new());
    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
#ifndef HAVE_ECC_BRAINPOOL
    /* Used to make groups curve_idx == -1. */
    ExpectNotNull(group2 = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1));
#endif

    ExpectNull(EC_POINT_new(NULL));
    ExpectNotNull(Gxy = EC_POINT_new(group));
    ExpectNotNull(new_point = EC_POINT_new(group));
    ExpectNotNull(set_point = EC_POINT_new(group));
    ExpectNotNull(X = BN_new());
    ExpectNotNull(Y = BN_new());
    ExpectNotNull(set_point_bn = BN_new());

    ExpectNotNull(infinity = EC_POINT_new(group));

    /* load test values */
    ExpectIntEQ(BN_hex2bn(&k,  kTest), WOLFSSL_SUCCESS);
    ExpectIntEQ(BN_hex2bn(&Gx, kGx),   WOLFSSL_SUCCESS);
    ExpectIntEQ(BN_hex2bn(&Gy, kGy),   WOLFSSL_SUCCESS);
    ExpectIntEQ(BN_hex2bn(&Gz, "1"),   WOLFSSL_SUCCESS);

    /* populate coordinates for input point */
    if (Gxy != NULL) {
        Gxy->X = Gx;
        Gxy->Y = Gy;
        Gxy->Z = Gz;
    }

    /* Test handling of NULL point. */
    EC_POINT_clear_free(NULL);

    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, NULL,
        NULL, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, NULL,
        NULL, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, Gxy,
        NULL, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, NULL,
        X, NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, NULL,
        NULL, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(NULL, Gxy,
        X, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, NULL,
        X, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, Gxy,
        NULL, Y, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, Gxy,
        X, NULL, ctx), 0);
    /* Getting point at infinity returns an error. */
    ExpectIntEQ(wolfSSL_EC_POINT_get_affine_coordinates_GFp(group, infinity,
        X, Y, ctx), 0);

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    ExpectIntEQ(EC_POINT_add(NULL, NULL, NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, NULL, NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, new_point, NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, NULL, new_point, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, NULL, NULL, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(NULL, new_point, new_point, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, NULL, new_point, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, new_point, NULL, Gxy, ctx), 0);
    ExpectIntEQ(EC_POINT_add(group, new_point, new_point, NULL, ctx), 0);

    ExpectIntEQ(EC_POINT_mul(NULL, NULL, Gx, Gxy, k, ctx), 0);
    ExpectIntEQ(EC_POINT_mul(NULL, new_point, Gx, Gxy, k, ctx), 0);
    ExpectIntEQ(EC_POINT_mul(group, NULL, Gx, Gxy, k, ctx), 0);

    ExpectIntEQ(EC_POINT_add(group, new_point, new_point, Gxy, ctx), 1);
    /* perform point multiplication */
    ExpectIntEQ(EC_POINT_mul(group, new_point, Gx, Gxy, k, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
    ExpectIntEQ(EC_POINT_mul(group, new_point, NULL, Gxy, k, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
    ExpectIntEQ(EC_POINT_mul(group, new_point, Gx, NULL, NULL, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
    ExpectIntEQ(EC_POINT_mul(group, new_point, NULL, NULL, NULL, ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 1);
    ExpectIntEQ(BN_is_zero(new_point->Y), 1);
    ExpectIntEQ(BN_is_zero(new_point->Z), 1);
    /* Set point to something. */
    ExpectIntEQ(EC_POINT_add(group, new_point, Gxy, Gxy, ctx), 1);
#else
    ExpectIntEQ(EC_POINT_set_affine_coordinates_GFp(group, new_point, Gx, Gy,
        ctx), 1);
    ExpectIntEQ(BN_is_zero(new_point->X), 0);
    ExpectIntEQ(BN_is_zero(new_point->Y), 0);
    ExpectIntEQ(BN_is_zero(new_point->Z), 0);
#endif

    /* check if point X coordinate is zero */
    ExpectIntEQ(BN_is_zero(new_point->X), 0);

#if defined(USE_ECC_B_PARAM) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
    ExpectIntEQ(EC_POINT_is_on_curve(group, new_point, ctx), 1);
#endif

    /* extract the coordinates from point */
    ExpectIntEQ(EC_POINT_get_affine_coordinates_GFp(group, new_point, X, Y,
        ctx), WOLFSSL_SUCCESS);

    /* check if point X coordinate is zero */
    ExpectIntEQ(BN_is_zero(X), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* set the same X and Y points in another object */
    ExpectIntEQ(EC_POINT_set_affine_coordinates_GFp(group, set_point, X, Y,
        ctx), WOLFSSL_SUCCESS);

    /* compare points as they should be the same */
    ExpectIntEQ(EC_POINT_cmp(NULL, NULL, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, NULL, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(NULL, new_point, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(NULL, NULL, set_point, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(NULL, new_point, set_point, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, NULL, set_point, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, new_point, NULL, ctx), -1);
    ExpectIntEQ(EC_POINT_cmp(group, new_point, set_point, ctx), 0);

    /* Test copying */
    ExpectIntEQ(EC_POINT_copy(NULL, NULL), 0);
    ExpectIntEQ(EC_POINT_copy(NULL, set_point), 0);
    ExpectIntEQ(EC_POINT_copy(new_point, NULL), 0);
    ExpectIntEQ(EC_POINT_copy(new_point, set_point), 1);

    /* Test inverting */
    ExpectIntEQ(EC_POINT_invert(NULL, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_invert(NULL, new_point, ctx), 0);
    ExpectIntEQ(EC_POINT_invert(group, NULL, ctx), 0);
    ExpectIntEQ(EC_POINT_invert(group, new_point, ctx), 1);

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    {
        EC_POINT* orig_point = NULL;
        ExpectNotNull(orig_point = EC_POINT_new(group));
        ExpectIntEQ(EC_POINT_add(group, orig_point, set_point, set_point, NULL),
                    1);
        /* new_point should be set_point inverted so adding it will revert
         * the point back to set_point */
        ExpectIntEQ(EC_POINT_add(group, orig_point, orig_point, new_point,
                                 NULL), 1);
        ExpectIntEQ(EC_POINT_cmp(group, orig_point, set_point, NULL), 0);
        EC_POINT_free(orig_point);
    }
#endif

    /* Test getting affine converts from projective. */
    ExpectIntEQ(EC_POINT_copy(set_point, new_point), 1);
    /* Force non-affine coordinates */
    ExpectIntEQ(BN_add(new_point->Z, (WOLFSSL_BIGNUM*)BN_value_one(),
        (WOLFSSL_BIGNUM*)BN_value_one()), 1);
    if (new_point != NULL) {
        new_point->inSet = 0;
    }
    /* extract the coordinates from point */
    ExpectIntEQ(EC_POINT_get_affine_coordinates_GFp(group, new_point, X, Y,
        ctx), WOLFSSL_SUCCESS);
    /* check if point ordinates have changed. */
    ExpectIntNE(BN_cmp(X, set_point->X), 0);
    ExpectIntNE(BN_cmp(Y, set_point->Y), 0);

    /* Test check for infinity */
#ifndef WOLF_CRYPTO_CB_ONLY_ECC
    ExpectIntEQ(EC_POINT_is_at_infinity(NULL, NULL), 0);
    ExpectIntEQ(EC_POINT_is_at_infinity(NULL, infinity), 0);
    ExpectIntEQ(EC_POINT_is_at_infinity(group, NULL), 0);
    ExpectIntEQ(EC_POINT_is_at_infinity(group, infinity), 1);
    ExpectIntEQ(EC_POINT_is_at_infinity(group, Gxy), 0);
#else
    ExpectIntEQ(EC_POINT_is_at_infinity(group, infinity), 0);
#endif

    ExpectPtrEq(EC_POINT_point2bn(group, set_point,
        POINT_CONVERSION_UNCOMPRESSED, set_point_bn, ctx), set_point_bn);

    /* check bn2hex */
    hexStr = BN_bn2hex(k);
    ExpectStrEQ(hexStr, kTest);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
     defined(XFPRINTF)
    BN_print_fp(stderr, k);
    fprintf(stderr, "\n");
#endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    hexStr = BN_bn2hex(Gx);
    ExpectStrEQ(hexStr, kGx);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
     defined(XFPRINTF)
    BN_print_fp(stderr, Gx);
    fprintf(stderr, "\n");
#endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    hexStr = BN_bn2hex(Gy);
    ExpectStrEQ(hexStr, kGy);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
     defined(XFPRINTF)
    BN_print_fp(stderr, Gy);
    fprintf(stderr, "\n");
#endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    /* Test point to hex */
    ExpectNull(EC_POINT_point2hex(NULL, NULL, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
    ExpectNull(EC_POINT_point2hex(NULL, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
    ExpectNull(EC_POINT_point2hex(group, NULL, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
#ifndef HAVE_ECC_BRAINPOOL
    /* Group not supported in wolfCrypt. */
    ExpectNull(EC_POINT_point2hex(group2, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        ctx));
#endif

    hexStr = EC_POINT_point2hex(group, Gxy, POINT_CONVERSION_UNCOMPRESSED, ctx);
    ExpectNotNull(hexStr);
    ExpectStrEQ(hexStr, uncompG);
    ExpectNotNull(get_point = EC_POINT_hex2point(group, hexStr, NULL, ctx));
    ExpectIntEQ(EC_POINT_cmp(group, Gxy, get_point, ctx), 0);
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);

    hexStr = EC_POINT_point2hex(group, Gxy, POINT_CONVERSION_COMPRESSED, ctx);
    ExpectNotNull(hexStr);
    ExpectStrEQ(hexStr, compG);
    #ifdef HAVE_COMP_KEY
    ExpectNotNull(get_point = EC_POINT_hex2point
                                            (group, hexStr, get_point, ctx));
    ExpectIntEQ(EC_POINT_cmp(group, Gxy, get_point, ctx), 0);
    #endif
    XFREE(hexStr, NULL, DYNAMIC_TYPE_ECC);
    EC_POINT_free(get_point);

#ifndef HAVE_SELFTEST
    /* Test point to oct */
    ExpectIntEQ(EC_POINT_point2oct(NULL, NULL, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx), 0);
    ExpectIntEQ(EC_POINT_point2oct(NULL, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx), 0);
    ExpectIntEQ(EC_POINT_point2oct(group, NULL, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx), 0);
    bin_len = EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx);
    ExpectIntEQ(bin_len, sizeof(binUncompG));
    ExpectNotNull(buf = (unsigned char*)XMALLOC(bin_len, NULL,
         DYNAMIC_TYPE_ECC));
    ExpectIntEQ(EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_UNCOMPRESSED,
        buf, bin_len, ctx), bin_len);
    ExpectIntEQ(XMEMCMP(buf, binUncompG, sizeof(binUncompG)), 0);
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC);

    /* Infinity (x=0, y=0) encodes as '0x00'. */
    ExpectIntEQ(EC_POINT_point2oct(group, infinity,
        POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx), 1);
    ExpectIntEQ(EC_POINT_point2oct(group, infinity,
        POINT_CONVERSION_UNCOMPRESSED, bufInf, 0, ctx), 0);
    ExpectIntEQ(EC_POINT_point2oct(group, infinity,
        POINT_CONVERSION_UNCOMPRESSED, bufInf, 1, ctx), 1);
    ExpectIntEQ(bufInf[0], 0);

    wolfSSL_EC_POINT_dump(NULL, NULL);
    /* Test point i2d */
    ExpectIntEQ(ECPoint_i2d(NULL, NULL, NULL, &blen), 0);
    ExpectIntEQ(ECPoint_i2d(NULL, Gxy, NULL, &blen), 0);
    ExpectIntEQ(ECPoint_i2d(group, NULL, NULL, &blen), 0);
    ExpectIntEQ(ECPoint_i2d(group, Gxy, NULL, NULL), 0);
    ExpectIntEQ(ECPoint_i2d(group, Gxy, NULL, &blen), 1);
    ExpectIntEQ(blen, sizeof(binUncompG));
    ExpectNotNull(buf = (unsigned char*)XMALLOC(blen, NULL, DYNAMIC_TYPE_ECC));
    blen--;
    ExpectIntEQ(ECPoint_i2d(group, Gxy, buf, &blen), 0);
    blen++;
    ExpectIntEQ(ECPoint_i2d(group, Gxy, buf, &blen), 1);
    ExpectIntEQ(XMEMCMP(buf, binUncompG, sizeof(binUncompG)), 0);
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC);

#ifdef HAVE_COMP_KEY
    /* Test point to oct compressed */
    bin_len = EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_COMPRESSED, NULL,
        0, ctx);
    ExpectIntEQ(bin_len, sizeof(binCompG));
    ExpectNotNull(buf = (unsigned char*)XMALLOC(bin_len, NULL,
        DYNAMIC_TYPE_ECC));
    ExpectIntEQ(EC_POINT_point2oct(group, Gxy, POINT_CONVERSION_COMPRESSED, buf,
        bin_len, ctx), bin_len);
    ExpectIntEQ(XMEMCMP(buf, binCompG, sizeof(binCompG)), 0);
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC);
#endif

    /* Test point BN */
    ExpectNull(wolfSSL_EC_POINT_point2bn(NULL, NULL,
        POINT_CONVERSION_UNCOMPRESSED, NULL, ctx));
    ExpectNull(wolfSSL_EC_POINT_point2bn(NULL, Gxy,
        POINT_CONVERSION_UNCOMPRESSED, NULL, ctx));
    ExpectNull(wolfSSL_EC_POINT_point2bn(group, NULL,
        POINT_CONVERSION_UNCOMPRESSED, NULL, ctx));
    ExpectNull(wolfSSL_EC_POINT_point2bn(group, Gxy, 0, NULL, ctx));

    /* Test oct to point */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(EC_POINT_oct2point(NULL, NULL, binUncompG, sizeof(binUncompG),
        ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(NULL, tmp, binUncompG, sizeof(binUncompG),
        ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(group, NULL, binUncompG, sizeof(binUncompG),
        ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(group, tmp, binUncompGBad,
        sizeof(binUncompGBad), ctx), 0);
    ExpectIntEQ(EC_POINT_oct2point(group, tmp, binUncompG, sizeof(binUncompG),
        ctx), 1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;

    /* Test setting BN ordinates. */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, NULL, NULL,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, NULL, NULL,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, tmp, NULL,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, NULL, Gx,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, NULL, NULL,
        Gy, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(NULL, tmp, Gx, Gy,
        ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, NULL, Gx, Gy,
        ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, tmp, NULL,
        Gy, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, tmp, Gx,
        NULL, ctx), 0);
    ExpectIntEQ(wolfSSL_EC_POINT_set_affine_coordinates_GFp(group, tmp, Gx, Gy,
        ctx), 1);
    EC_POINT_free(tmp);
    tmp = NULL;

    /* Test point d2i */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), NULL, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), NULL, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), group, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), NULL, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(NULL, sizeof(binUncompG), group, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), NULL, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), group, NULL), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompGBad, sizeof(binUncompG), group, tmp), 0);
    ExpectIntEQ(ECPoint_d2i(binUncompG, sizeof(binUncompG), group, tmp), 1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;

#ifdef HAVE_COMP_KEY
    /* Test oct compressed to point */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(EC_POINT_oct2point(group, tmp, binCompG, sizeof(binCompG), ctx),
        1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;

    /* Test point d2i - compressed */
    ExpectNotNull(tmp = EC_POINT_new(group));
    ExpectIntEQ(ECPoint_d2i(binCompG, sizeof(binCompG), group, tmp), 1);
    ExpectIntEQ(EC_POINT_cmp(group, tmp, Gxy, ctx), 0);
    EC_POINT_free(tmp);
    tmp = NULL;
#endif
#endif

    /* test BN_mod_add */
    ExpectIntEQ(BN_mod_add(new_point->Z, (WOLFSSL_BIGNUM*)BN_value_one(),
        (WOLFSSL_BIGNUM*)BN_value_one(), (WOLFSSL_BIGNUM*)BN_value_one(), NULL),
        1);
    ExpectIntEQ(BN_is_zero(new_point->Z), 1);

    /* cleanup */
    BN_free(X);
    BN_free(Y);
    BN_free(k);
    BN_free(set_point_bn);
    EC_POINT_free(infinity);
    EC_POINT_free(new_point);
    EC_POINT_free(set_point);
    EC_POINT_clear_free(Gxy);
#ifndef HAVE_ECC_BRAINPOOL
    EC_GROUP_free(group2);
#endif
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
#endif
#endif /* !WOLFSSL_SP_MATH && ( !HAVE_FIPS || HAVE_FIPS_VERSION > 2) */
    return EXPECT_RESULT();
}

int test_wolfSSL_SPAKE(void)
{
    EXPECT_DECLS;

#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && !defined(WOLFSSL_ATECC508A) \
    && !defined(WOLFSSL_ATECC608A) && !defined(HAVE_SELFTEST) && \
       !defined(WOLFSSL_SP_MATH) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    BIGNUM* x = NULL; /* kdc priv */
    BIGNUM* y = NULL; /* client priv */
    BIGNUM* w = NULL; /* shared value */
    byte M_bytes[] = {
        /* uncompressed */
        0x04,
        /* x */
        0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24,
        0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95,
        0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
        /* y */
        0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65,
        0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0,
        0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20
    };
    EC_POINT* M = NULL; /* shared value */
    byte N_bytes[] = {
        /* uncompressed */
        0x04,
        /* x */
        0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f,
        0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2,
        0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
        /* y */
        0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33,
        0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5,
        0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7
    };
    EC_POINT* N = NULL; /* shared value */
    EC_POINT* T = NULL; /* kdc pub */
    EC_POINT* tmp1 = NULL; /* kdc pub */
    EC_POINT* tmp2 = NULL; /* kdc pub */
    EC_POINT* S = NULL; /* client pub */
    EC_POINT* client_secret = NULL;
    EC_POINT* kdc_secret = NULL;
    EC_GROUP* group = NULL;
    BN_CTX* bn_ctx = NULL;

    /* Values taken from a test run of Kerberos 5 */

    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(bn_ctx = BN_CTX_new());

    ExpectNotNull(M = EC_POINT_new(group));
    ExpectNotNull(N = EC_POINT_new(group));
    ExpectNotNull(T = EC_POINT_new(group));
    ExpectNotNull(tmp1 = EC_POINT_new(group));
    ExpectNotNull(tmp2 = EC_POINT_new(group));
    ExpectNotNull(S = EC_POINT_new(group));
    ExpectNotNull(client_secret = EC_POINT_new(group));
    ExpectNotNull(kdc_secret = EC_POINT_new(group));
    ExpectIntEQ(BN_hex2bn(&x, "DAC3027CD692B4BDF0EDFE9B7D0E4E7"
                              "E5D8768A725EAEEA6FC68EC239A17C0"), 1);
    ExpectIntEQ(BN_hex2bn(&y, "6F6A1D394E26B1655A54B26DCE30D49"
                              "90CC47EBE08F809EF3FF7F6AEAABBB5"), 1);
    ExpectIntEQ(BN_hex2bn(&w, "1D992AB8BA851B9BA05353453D81EE9"
                              "506AB395478F0AAB647752CF117B36250"), 1);
    ExpectIntEQ(EC_POINT_oct2point(group, M, M_bytes, sizeof(M_bytes), bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_oct2point(group, N, N_bytes, sizeof(N_bytes), bn_ctx),
                1);

    /* Function pattern similar to ossl_keygen and ossl_result in krb5 */

    /* kdc */
    /* T=x*P+w*M */
    /* All in one function call */
    ExpectIntEQ(EC_POINT_mul(group, T, x, M, w, bn_ctx), 1);
    /* Spread into separate calls */
    ExpectIntEQ(EC_POINT_mul(group, tmp1, x, NULL, NULL, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_mul(group, tmp2, NULL, M, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, tmp1, tmp1, tmp2, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_cmp(group, T, tmp1, bn_ctx), 0);
    /* client */
    /* S=y*P+w*N */
    /* All in one function call */
    ExpectIntEQ(EC_POINT_mul(group, S, y, N, w, bn_ctx), 1);
    /* Spread into separate calls */
    ExpectIntEQ(EC_POINT_mul(group, tmp1, y, NULL, NULL, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_mul(group, tmp2, NULL, N, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, tmp1, tmp1, tmp2, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_cmp(group, S, tmp1, bn_ctx), 0);
    /* K=y*(T-w*M) */
    ExpectIntEQ(EC_POINT_mul(group, client_secret, NULL, M, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_invert(group, client_secret, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, client_secret, T, client_secret, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_mul(group, client_secret, NULL, client_secret, y,
                             bn_ctx), 1);
    /* kdc */
    /* K=x*(S-w*N) */
    ExpectIntEQ(EC_POINT_mul(group, kdc_secret, NULL, N, w, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_invert(group, kdc_secret, bn_ctx), 1);
    ExpectIntEQ(EC_POINT_add(group, kdc_secret, S, kdc_secret, bn_ctx),
                1);
    ExpectIntEQ(EC_POINT_mul(group, kdc_secret, NULL, kdc_secret, x, bn_ctx),
                1);

    /* kdc_secret == client_secret */
    ExpectIntEQ(EC_POINT_cmp(group, client_secret, kdc_secret, bn_ctx), 0);

    BN_free(x);
    BN_free(y);
    BN_free(w);
    EC_POINT_free(M);
    EC_POINT_free(N);
    EC_POINT_free(T);
    EC_POINT_free(tmp1);
    EC_POINT_free(tmp2);
    EC_POINT_free(S);
    EC_POINT_free(client_secret);
    EC_POINT_free(kdc_secret);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_KEY_generate(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    WOLFSSL_EC_KEY* key = NULL;
#ifndef HAVE_ECC_BRAINPOOL
    WOLFSSL_EC_GROUP* group = NULL;
#endif

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), 1);
    wolfSSL_EC_KEY_free(key);
    key = NULL;

#ifndef HAVE_ECC_BRAINPOOL
    ExpectNotNull(group = wolfSSL_EC_GROUP_new_by_curve_name(
        NID_brainpoolP256r1));
    ExpectNotNull(key = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_set_group(key, group), 1);
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), 0);
    wolfSSL_EC_KEY_free(key);
    wolfSSL_EC_GROUP_free(group);
#endif
#endif
    return EXPECT_RESULT();
}

int test_EC_i2d(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(HAVE_FIPS)
    EC_KEY *key = NULL;
    EC_KEY *copy = NULL;
    int len = 0;
    unsigned char *buf = NULL;
    unsigned char *p = NULL;
    const unsigned char *tmp = NULL;
    const unsigned char octBad[] = {
        0x09, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
    };

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key), 1);
    ExpectIntGT((len = i2d_EC_PUBKEY(key, NULL)), 0);
    ExpectNotNull(buf = (unsigned char*)XMALLOC(len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    p = buf;
    ExpectIntEQ(i2d_EC_PUBKEY(key, &p), len);

    ExpectNull(o2i_ECPublicKey(NULL, NULL, -1));
    ExpectNull(o2i_ECPublicKey(&copy, NULL, -1));
    ExpectNull(o2i_ECPublicKey(&key, NULL, -1));
    ExpectNull(o2i_ECPublicKey(NULL, &tmp, -1));
    ExpectNull(o2i_ECPublicKey(NULL, NULL, 0));
    ExpectNull(o2i_ECPublicKey(&key, NULL, 0));
    ExpectNull(o2i_ECPublicKey(&key, &tmp, 0));
    tmp = buf;
    ExpectNull(o2i_ECPublicKey(NULL, &tmp, 0));
    ExpectNull(o2i_ECPublicKey(&copy, &tmp, 0));
    ExpectNull(o2i_ECPublicKey(NULL, &tmp, -1));
    ExpectNull(o2i_ECPublicKey(&key, &tmp, -1));

    ExpectIntEQ(i2o_ECPublicKey(NULL, NULL), 0);
    ExpectIntEQ(i2o_ECPublicKey(NULL, &buf), 0);

    tmp = buf;
    ExpectNull(d2i_ECPrivateKey(NULL, &tmp, 0));
    ExpectNull(d2i_ECPrivateKey(NULL, &tmp, 1));
    ExpectNull(d2i_ECPrivateKey(&copy, &tmp, 0));
    ExpectNull(d2i_ECPrivateKey(&copy, &tmp, 1));
    ExpectNull(d2i_ECPrivateKey(&key, &tmp, 0));

    {
        EC_KEY *pubkey = NULL;
        BIO* bio = NULL;

        ExpectNotNull(bio = BIO_new(BIO_s_mem()));
        ExpectIntGT(BIO_write(bio, buf, len), 0);
        ExpectNotNull(d2i_EC_PUBKEY_bio(bio, &pubkey));

        BIO_free(bio);
        EC_KEY_free(pubkey);
    }

    ExpectIntEQ(i2d_ECPrivateKey(NULL, &p), 0);
    ExpectIntEQ(i2d_ECPrivateKey(NULL, NULL), 0);

    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer(NULL, NULL, -1), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, NULL, -1, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, NULL, -1, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, buf, -1, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, NULL, 0, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, NULL, -1,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(NULL, buf, len,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, NULL, len,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, buf, -1,
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, buf, len, 0), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, buf, len,
        WOLFSSL_EC_KEY_LOAD_PRIVATE), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, octBad, sizeof(octBad),
        WOLFSSL_EC_KEY_LOAD_PRIVATE), -1);
    ExpectIntEQ(wolfSSL_EC_KEY_LoadDer_ex(key, octBad, sizeof(octBad),
        WOLFSSL_EC_KEY_LOAD_PUBLIC), -1);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    buf = NULL;
    buf = NULL;

    ExpectIntGT((len = i2d_ECPrivateKey(key, NULL)), 0);
    ExpectNotNull(buf = (unsigned char*)XMALLOC(len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    p = buf;
    ExpectIntEQ(i2d_ECPrivateKey(key, &p), len);

    p = NULL;
    ExpectIntEQ(i2d_ECPrivateKey(key, &p), len);
    XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    p = NULL;

    /* Bad point is also an invalid private key. */
    tmp = octBad;
    ExpectNull(d2i_ECPrivateKey(&copy, &tmp, sizeof(octBad)));
    tmp = buf;
    ExpectNotNull(d2i_ECPrivateKey(&copy, &tmp, len));
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    buf = NULL;
    buf = NULL;

    ExpectIntGT((len = i2o_ECPublicKey(key, NULL)), 0);
    ExpectNotNull(buf = (unsigned char*)XMALLOC(len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    p = buf;
    ExpectIntGT((len = i2o_ECPublicKey(key, &p)), 0);
    p = NULL;
    ExpectIntGT((len = i2o_ECPublicKey(key, &p)), 0);
    tmp = buf;
    ExpectNotNull(o2i_ECPublicKey(&copy, &tmp, len));
    tmp = octBad;
    ExpectNull(o2i_ECPublicKey(&key, &tmp, sizeof(octBad)));

    ExpectIntEQ(EC_KEY_check_key(NULL), 0);
    ExpectIntEQ(EC_KEY_check_key(key), 1);

    XFREE(p, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);

    EC_KEY_free(key);
    EC_KEY_free(copy);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_curve(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    int nid = NID_secp160k1;
    const char* nid_name = NULL;

    ExpectNull(EC_curve_nid2nist(NID_sha256));

    ExpectNotNull(nid_name = EC_curve_nid2nist(nid));
    ExpectIntEQ(XMEMCMP(nid_name, "K-160", XSTRLEN("K-160")), 0);

    ExpectIntEQ(EC_curve_nist2nid("INVALID"), 0);
    ExpectIntEQ(EC_curve_nist2nid(nid_name), nid);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_KEY_dup(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS)
    WOLFSSL_EC_KEY* ecKey = NULL;
    WOLFSSL_EC_KEY* dupKey = NULL;
    ecc_key* srcKey = NULL;
    ecc_key* destKey = NULL;

    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);

    /* Valid cases */
    ExpectNotNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    ExpectIntEQ(EC_KEY_check_key(dupKey), 1);

    /* Compare pubkey */
    if (ecKey != NULL) {
        srcKey = (ecc_key*)ecKey->internal;
    }
    if (dupKey != NULL) {
        destKey = (ecc_key*)dupKey->internal;
    }
    ExpectIntEQ(wc_ecc_cmp_point(&srcKey->pubkey, &destKey->pubkey), 0);

    /* compare EC_GROUP */
    ExpectIntEQ(wolfSSL_EC_GROUP_cmp(ecKey->group, dupKey->group, NULL), MP_EQ);

    /* compare EC_POINT */
    ExpectIntEQ(wolfSSL_EC_POINT_cmp(ecKey->group, ecKey->pub_key, \
                dupKey->pub_key, NULL), MP_EQ);

    /* compare BIGNUM */
    ExpectIntEQ(wolfSSL_BN_cmp(ecKey->priv_key, dupKey->priv_key), MP_EQ);
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* Invalid cases */
    /* NULL key */
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(NULL));
    /* NULL ecc_key */
    if (ecKey != NULL) {
        wc_ecc_free((ecc_key*)ecKey->internal);
        XFREE(ecKey->internal, NULL, DYNAMIC_TYPE_ECC);
        ecKey->internal = NULL; /* Set ecc_key to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* NULL Group */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    if (ecKey != NULL) {
        wolfSSL_EC_GROUP_free(ecKey->group);
        ecKey->group = NULL; /* Set group to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* NULL public key */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    if (ecKey != NULL) {
        wc_ecc_del_point((ecc_point*)ecKey->pub_key->internal);
        ecKey->pub_key->internal = NULL; /* Set ecc_point to NULL */
    }

    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    if (ecKey != NULL) {
        wolfSSL_EC_POINT_free(ecKey->pub_key);
        ecKey->pub_key = NULL; /* Set pub_key to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* NULL private key */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);

    if (ecKey != NULL) {
        wolfSSL_BN_free(ecKey->priv_key);
        ecKey->priv_key = NULL; /* Set priv_key to NULL */
    }
    ExpectNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));

    wolfSSL_EC_KEY_free(ecKey);
    ecKey = NULL;
    wolfSSL_EC_KEY_free(dupKey);
    dupKey = NULL;

    /* Test EC_KEY_up_ref */
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(ecKey), WOLFSSL_SUCCESS);
    /* reference count doesn't follow duplicate */
    ExpectNotNull(dupKey = wolfSSL_EC_KEY_dup(ecKey));
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(dupKey), WOLFSSL_SUCCESS); /* +1 */
    ExpectIntEQ(wolfSSL_EC_KEY_up_ref(dupKey), WOLFSSL_SUCCESS); /* +2 */
    wolfSSL_EC_KEY_free(dupKey); /* 3 */
    wolfSSL_EC_KEY_free(dupKey); /* 2 */
    wolfSSL_EC_KEY_free(dupKey); /* 1, free */
    wolfSSL_EC_KEY_free(ecKey);  /* 2 */
    wolfSSL_EC_KEY_free(ecKey);  /* 1, free */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_KEY_set_group(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(NO_ECC_SECP) && \
    defined(OPENSSL_EXTRA)
    EC_KEY   *key    = NULL;
    EC_GROUP *group  = NULL;
    const EC_GROUP *group2 = NULL;

    ExpectNotNull(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(key = EC_KEY_new());

    ExpectNull(EC_KEY_get0_group(NULL));
    ExpectIntEQ(EC_KEY_set_group(NULL, NULL), 0);
    ExpectIntEQ(EC_KEY_set_group(key, NULL), 0);
    ExpectIntEQ(EC_KEY_set_group(NULL, group), 0);

    ExpectIntEQ(EC_KEY_set_group(key, group), WOLFSSL_SUCCESS);
    ExpectNotNull(group2 = EC_KEY_get0_group(key));
    ExpectIntEQ(EC_GROUP_cmp(group2, group, NULL), 0);

    EC_GROUP_free(group);
    EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_KEY_set_conv_form(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(OPENSSL_EXTRA) && !defined(NO_BIO) && \
    !defined(NO_FILESYSTEM)
    BIO* bio = NULL;
    EC_KEY* key = NULL;

    /* Error condition: NULL key. */
    ExpectIntLT(EC_KEY_get_conv_form(NULL), 0);

    ExpectNotNull(bio = BIO_new_file("./certs/ecc-keyPub.pem", "rb"));
    ExpectNotNull(key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL));
    /* Conversion form defaults to uncompressed. */
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_UNCOMPRESSED);
#ifdef HAVE_COMP_KEY
    /* Explicitly set to compressed. */
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_COMPRESSED);
#else
    /* Will still work just won't change anything. */
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_UNCOMPRESSED);
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    ExpectIntEQ(EC_KEY_get_conv_form(key), POINT_CONVERSION_UNCOMPRESSED);
#endif
    EC_KEY_set_conv_form(NULL, POINT_CONVERSION_UNCOMPRESSED);

    BIO_free(bio);
    EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_KEY_private_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    WOLFSSL_EC_KEY* key = NULL;
    WOLFSSL_BIGNUM* priv = NULL;
    WOLFSSL_BIGNUM* priv2 = NULL;
    WOLFSSL_BIGNUM* bn = NULL;

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectNotNull(priv = wolfSSL_BN_new());
    ExpectNotNull(priv2 = wolfSSL_BN_new());
    ExpectIntNE(BN_set_word(priv, 2), 0);
    ExpectIntNE(BN_set_word(priv2, 2), 0);

    ExpectNull(wolfSSL_EC_KEY_get0_private_key(NULL));
    /* No private key set. */
    ExpectNull(wolfSSL_EC_KEY_get0_private_key(key));

    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(key, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(NULL, priv), 0);

    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(key, priv), 1);
    ExpectNotNull(bn = wolfSSL_EC_KEY_get0_private_key(key));
    ExpectPtrNE(bn, priv);
    ExpectIntEQ(wolfSSL_EC_KEY_set_private_key(key, priv2), 1);
    ExpectNotNull(bn = wolfSSL_EC_KEY_get0_private_key(key));
    ExpectPtrNE(bn, priv2);

    wolfSSL_BN_free(priv2);
    wolfSSL_BN_free(priv);
    wolfSSL_EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_KEY_public_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    WOLFSSL_EC_KEY* key = NULL;
    WOLFSSL_EC_POINT* pub = NULL;
    WOLFSSL_EC_POINT* point = NULL;

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

    ExpectNull(wolfSSL_EC_KEY_get0_public_key(NULL));
    ExpectNotNull(wolfSSL_EC_KEY_get0_public_key(key));

    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), 1);

    ExpectNotNull(pub = wolfSSL_EC_KEY_get0_public_key(key));

    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(key, NULL), 0);
    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(NULL, pub), 0);

    ExpectIntEQ(wolfSSL_EC_KEY_set_public_key(key, pub), 1);
    ExpectNotNull(point = wolfSSL_EC_KEY_get0_public_key(key));
    ExpectPtrEq(point, pub);

    wolfSSL_EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_KEY_print_fp(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && ((defined(HAVE_ECC224) && defined(HAVE_ECC256)) || \
    defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 224 && \
    defined(OPENSSL_EXTRA) && defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
    EC_KEY* key = NULL;

    /* Bad file pointer. */
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(NULL, key, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL key. */
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, NULL, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectNotNull((key = wolfSSL_EC_KEY_new_by_curve_name(NID_secp224r1)));
    /* Negative indent. */
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, -1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, 4), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, 4), WOLFSSL_SUCCESS);
    wolfSSL_EC_KEY_free(key);

    ExpectNotNull((key = wolfSSL_EC_KEY_new_by_curve_name(
        NID_X9_62_prime256v1)));
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(key), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EC_KEY_print_fp(stderr, key, 4), WOLFSSL_SUCCESS);
    wolfSSL_EC_KEY_free(key);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EC_get_builtin_curves(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    EC_builtin_curve* curves = NULL;
    size_t crv_len = 0;
    size_t i = 0;

    ExpectIntGT((crv_len = EC_get_builtin_curves(NULL, 0)), 0);
    ExpectNotNull(curves = (EC_builtin_curve*)XMALLOC(
        sizeof(EC_builtin_curve) * crv_len, NULL, DYNAMIC_TYPE_TMP_BUFFER));

    ExpectIntEQ((EC_get_builtin_curves(curves, 0)), crv_len);
    ExpectIntEQ(EC_get_builtin_curves(curves, crv_len), crv_len);

    for (i = 0; EXPECT_SUCCESS() && (i < crv_len); i++) {
        if (curves[i].comment != NULL) {
            ExpectStrEQ(OBJ_nid2sn(curves[i].nid), curves[i].comment);
        }
    }

    if (crv_len > 1) {
        ExpectIntEQ(EC_get_builtin_curves(curves, crv_len - 1), crv_len - 1);
    }

    XFREE(curves, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */
    return EXPECT_RESULT();
}

int test_wolfSSL_ECDSA_SIG(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    WOLFSSL_ECDSA_SIG* sig = NULL;
    WOLFSSL_ECDSA_SIG* sig2 = NULL;
    WOLFSSL_BIGNUM* r = NULL;
    WOLFSSL_BIGNUM* s = NULL;
    const WOLFSSL_BIGNUM* r2 = NULL;
    const WOLFSSL_BIGNUM* s2 = NULL;
    const unsigned char* cp = NULL;
    unsigned char* p = NULL;
    unsigned char outSig[8];
    unsigned char sigData[8] =
                             { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    unsigned char sigDataBad[8] =
                             { 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };

    wolfSSL_ECDSA_SIG_free(NULL);

    ExpectNotNull(sig = wolfSSL_ECDSA_SIG_new());
    ExpectNotNull(r = wolfSSL_BN_new());
    ExpectNotNull(s = wolfSSL_BN_new());
    ExpectIntEQ(wolfSSL_BN_set_word(r, 1), 1);
    ExpectIntEQ(wolfSSL_BN_set_word(s, 1), 1);

    wolfSSL_ECDSA_SIG_get0(NULL, NULL, NULL);
    wolfSSL_ECDSA_SIG_get0(NULL, &r2, NULL);
    wolfSSL_ECDSA_SIG_get0(NULL, NULL, &s2);
    wolfSSL_ECDSA_SIG_get0(NULL, &r2, &s2);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, r, NULL), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, NULL, s), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(NULL, r, s), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, NULL, s), 0);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, r, NULL), 0);

    r2 = NULL;
    s2 = NULL;
    wolfSSL_ECDSA_SIG_get0(NULL, &r2, &s2);
    ExpectNull(r2);
    ExpectNull(s2);
    ExpectIntEQ(wolfSSL_ECDSA_SIG_set0(sig, r, s), 1);
    if (EXPECT_FAIL()) {
        wolfSSL_BN_free(r);
        wolfSSL_BN_free(s);
    }
    wolfSSL_ECDSA_SIG_get0(sig, &r2, &s2);
    ExpectPtrEq(r2, r);
    ExpectPtrEq(s2, s);
    r2 = NULL;
    wolfSSL_ECDSA_SIG_get0(sig, &r2, NULL);
    ExpectPtrEq(r2, r);
    s2 = NULL;
    wolfSSL_ECDSA_SIG_get0(sig, NULL, &s2);
    ExpectPtrEq(s2, s);

    /* r and s are freed when sig is freed. */
    wolfSSL_ECDSA_SIG_free(sig);
    sig = NULL;

    ExpectNull(wolfSSL_d2i_ECDSA_SIG(NULL, NULL, sizeof(sigData)));
    cp = sigDataBad;
    ExpectNull(wolfSSL_d2i_ECDSA_SIG(NULL, &cp, sizeof(sigDataBad)));
    cp = sigData;
    ExpectNotNull((sig = wolfSSL_d2i_ECDSA_SIG(NULL, &cp, sizeof(sigData))));
    ExpectIntEQ((cp == sigData + 8), 1);
    cp = sigData;
    ExpectNull(wolfSSL_d2i_ECDSA_SIG(&sig, NULL, sizeof(sigData)));
    ExpectNotNull((sig2 = wolfSSL_d2i_ECDSA_SIG(&sig, &cp, sizeof(sigData))));
    ExpectIntEQ((sig == sig2), 1);
    cp = outSig;

    p = outSig;
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(NULL, &p), 0);
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(sig, NULL), 8);
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(sig, &p), sizeof(sigData));
    ExpectIntEQ((p == outSig + 8), 1);
    ExpectIntEQ(XMEMCMP(sigData, outSig, 8), 0);

    p = NULL;
    ExpectIntEQ(wolfSSL_i2d_ECDSA_SIG(sig, &p), 8);
#ifndef WOLFSSL_I2D_ECDSA_SIG_ALLOC
    ExpectNull(p);
#else
    ExpectNotNull(p);
    ExpectIntEQ(XMEMCMP(p, outSig, 8), 0);
    XFREE(p, NULL, DYNAMIC_TYPE_OPENSSL);
#endif

    wolfSSL_ECDSA_SIG_free(sig);
#endif
    return EXPECT_RESULT();
}

int test_ECDSA_size_sign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    EC_KEY* key = NULL;
    ECDSA_SIG* ecdsaSig = NULL;
    int id;
    byte hash[WC_MAX_DIGEST_SIZE];
    byte hash2[WC_MAX_DIGEST_SIZE];
    byte sig[ECC_MAX_SIG_SIZE];
    unsigned int sigSz = sizeof(sig);

    XMEMSET(hash, 123, sizeof(hash));
    XMEMSET(hash2, 234, sizeof(hash2));

    id = wc_ecc_get_curve_id_from_name("SECP256R1");
    ExpectIntEQ(id, ECC_SECP256R1);

    ExpectNotNull(key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key), 1);

    ExpectIntGE(ECDSA_size(NULL), 0);

    ExpectIntEQ(ECDSA_sign(0, hash, sizeof(hash), sig, &sigSz, NULL), 0);
    ExpectIntEQ(ECDSA_sign(0, NULL, sizeof(hash), sig, &sigSz, key), 0);
    ExpectIntEQ(ECDSA_sign(0, hash, sizeof(hash), NULL, &sigSz, key), 0);
    ExpectIntEQ(ECDSA_verify(0, hash, sizeof(hash), sig, (int)sigSz, NULL), 0);
    ExpectIntEQ(ECDSA_verify(0, NULL, sizeof(hash), sig, (int)sigSz, key), 0);
    ExpectIntEQ(ECDSA_verify(0, hash, sizeof(hash), NULL, (int)sigSz, key), 0);

    ExpectIntEQ(ECDSA_sign(0, hash, sizeof(hash), sig, &sigSz, key), 1);
    ExpectIntGE(ECDSA_size(key), sigSz);
    ExpectIntEQ(ECDSA_verify(0, hash, sizeof(hash), sig, (int)sigSz, key), 1);
    ExpectIntEQ(ECDSA_verify(0, hash2, sizeof(hash2), sig, (int)sigSz, key), 0);

    ExpectNull(ECDSA_do_sign(NULL, sizeof(hash), NULL));
    ExpectNull(ECDSA_do_sign(NULL, sizeof(hash), key));
    ExpectNull(ECDSA_do_sign(hash, sizeof(hash), NULL));
    ExpectNotNull(ecdsaSig = ECDSA_do_sign(hash, sizeof(hash), key));
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), NULL, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), NULL, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), ecdsaSig, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), NULL, key), -1);
    ExpectIntEQ(ECDSA_do_verify(NULL, sizeof(hash), ecdsaSig, key), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), NULL, key), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), ecdsaSig, NULL), -1);
    ExpectIntEQ(ECDSA_do_verify(hash, sizeof(hash), ecdsaSig, key), 1);
    ExpectIntEQ(ECDSA_do_verify(hash2, sizeof(hash2), ecdsaSig, key), 0);
    ECDSA_SIG_free(ecdsaSig);

    EC_KEY_free(key);
#endif /* OPENSSL_EXTRA && !NO_ECC256 && !NO_ECC_SECP */
    return EXPECT_RESULT();
}

int test_ECDH_compute_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ECC256) && !defined(NO_ECC_SECP) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    EC_KEY* key1 = NULL;
    EC_KEY* key2 = NULL;
    EC_POINT* pub1 = NULL;
    EC_POINT* pub2 = NULL;
    byte secret1[32];
    byte secret2[32];
    int i;

    ExpectNotNull(key1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key1), 1);
    ExpectNotNull(pub1 = wolfSSL_EC_KEY_get0_public_key(key1));
    ExpectNotNull(key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ExpectIntEQ(EC_KEY_generate_key(key2), 1);
    ExpectNotNull(pub2 = wolfSSL_EC_KEY_get0_public_key(key2));

    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), NULL, NULL, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), NULL, NULL, NULL),
        0);
    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), pub2, NULL, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), NULL, key1, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(NULL, sizeof(secret1), pub2, key1, NULL), 0);
    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), NULL, key1, NULL),
        0);
    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), pub2, NULL, NULL),
        0);

    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1) - 16, pub2, key1,
        NULL), 0);

    ExpectIntEQ(ECDH_compute_key(secret1, sizeof(secret1), pub2, key1, NULL),
        sizeof(secret1));
    ExpectIntEQ(ECDH_compute_key(secret2, sizeof(secret2), pub1, key2, NULL),
        sizeof(secret2));

    for (i = 0; i < (int)sizeof(secret1); i++) {
        ExpectIntEQ(secret1[i], secret2[i]);
    }

    EC_KEY_free(key2);
    EC_KEY_free(key1);
#endif /* OPENSSL_EXTRA && !NO_ECC256 && !NO_ECC_SECP &&
        * !WOLF_CRYPTO_CB_ONLY_ECC */
    return EXPECT_RESULT();
}

#endif /* HAVE_ECC && !OPENSSL_NO_PK */


