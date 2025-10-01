/* test_ossl_bn.c
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

#include <wolfssl/openssl/bn.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_bn.h>

/*******************************************************************************
 * BN OpenSSL compatibility API Testing
 ******************************************************************************/

int test_wolfSSL_BN_CTX(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
    WOLFSSL_BN_CTX* bn_ctx = NULL;

    ExpectNotNull(bn_ctx = BN_CTX_new());

    ExpectNull(BN_CTX_get(NULL));
    ExpectNotNull(BN_CTX_get(bn_ctx));
    ExpectNotNull(BN_CTX_get(bn_ctx));
    ExpectNotNull(BN_CTX_get(bn_ctx));
    ExpectNotNull(BN_CTX_get(bn_ctx));
    ExpectNotNull(BN_CTX_get(bn_ctx));
    ExpectNotNull(BN_CTX_get(bn_ctx));

#ifndef NO_WOLFSSL_STUB
    /* No implementation. */
    BN_CTX_start(NULL);
    BN_CTX_start(bn_ctx);
    BN_CTX_init(NULL);
#endif

    BN_CTX_free(NULL);
    BN_CTX_free(bn_ctx);
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_ASN) */
    return EXPECT_RESULT();
}

int test_wolfSSL_BN(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM* c = NULL;
    BIGNUM* d = NULL;
    BIGNUM emptyBN;

    /* Setup */
    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    /* internal not set emptyBN. */

    ExpectNotNull(a = BN_new());
    ExpectNotNull(b = BN_new());
    ExpectNotNull(c = BN_dup(b));
    ExpectNotNull(d = BN_new());

    /* Invalid parameter testing. */
    BN_free(NULL);
    ExpectNull(BN_dup(NULL));
    ExpectNull(BN_dup(&emptyBN));

    ExpectNull(BN_copy(NULL, NULL));
    ExpectNull(BN_copy(b, NULL));
    ExpectNull(BN_copy(NULL, c));
    ExpectNull(BN_copy(b, &emptyBN));
    ExpectNull(BN_copy(&emptyBN, c));

    BN_clear(NULL);
    BN_clear(&emptyBN);

    ExpectIntEQ(BN_num_bytes(NULL), 0);
    ExpectIntEQ(BN_num_bytes(&emptyBN), 0);

    ExpectIntEQ(BN_num_bits(NULL), 0);
    ExpectIntEQ(BN_num_bits(&emptyBN), 0);

    ExpectIntEQ(BN_is_negative(NULL), 0);
    ExpectIntEQ(BN_is_negative(&emptyBN), 0);
    /* END Invalid Parameters */

    ExpectIntEQ(BN_set_word(a, 3), SSL_SUCCESS);
    ExpectIntEQ(BN_set_word(b, 2), SSL_SUCCESS);
    ExpectIntEQ(BN_set_word(c, 5), SSL_SUCCESS);

    ExpectIntEQ(BN_num_bits(a), 2);
    ExpectIntEQ(BN_num_bytes(a), 1);

#if !defined(WOLFSSL_SP_MATH) && (!defined(WOLFSSL_SP_MATH_ALL) || \
                                               defined(WOLFSSL_SP_INT_NEGATIVE))
    ExpectIntEQ(BN_set_word(a, 1), SSL_SUCCESS);
    ExpectIntEQ(BN_set_word(b, 5), SSL_SUCCESS);
    ExpectIntEQ(BN_is_word(a, (WOLFSSL_BN_ULONG)BN_get_word(a)), SSL_SUCCESS);
    ExpectIntEQ(BN_is_word(a, 3), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(BN_sub(c, a, b), SSL_SUCCESS);
#if defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY)
    {
        /* Do additional tests on negative BN conversions. */
        char*         ret = NULL;
        ASN1_INTEGER* asn1 = NULL;
        BIGNUM*       tmp = NULL;

        /* Sanity check we have a negative BN. */
        ExpectIntEQ(BN_is_negative(c), 1);
        ExpectNotNull(ret = BN_bn2dec(c));
        ExpectIntEQ(XMEMCMP(ret, "-4", sizeof("-4")), 0);
        XFREE(ret, NULL, DYNAMIC_TYPE_OPENSSL);
        ret = NULL;

        /* Convert to ASN1_INTEGER and back to BN. */
        ExpectNotNull(asn1 = BN_to_ASN1_INTEGER(c, NULL));
        ExpectNotNull(tmp = ASN1_INTEGER_to_BN(asn1, NULL));

        /* After converting back BN should be negative and correct. */
        ExpectIntEQ(BN_is_negative(tmp), 1);
        ExpectNotNull(ret = BN_bn2dec(tmp));
        ExpectIntEQ(XMEMCMP(ret, "-4", sizeof("-4")), 0);
        XFREE(ret, NULL, DYNAMIC_TYPE_OPENSSL);
        ASN1_INTEGER_free(asn1);
        BN_free(tmp);
    }
#endif
    ExpectIntEQ(BN_get_word(c), 4);
#endif

    ExpectIntEQ(BN_set_word(a, 3), 1);
    ExpectIntEQ(BN_set_word(b, 3), 1);
    ExpectIntEQ(BN_set_word(c, 4), 1);

    /* NULL == NULL, NULL < num, num > NULL */
    ExpectIntEQ(BN_cmp(NULL, NULL), 0);
    ExpectIntEQ(BN_cmp(&emptyBN, &emptyBN), 0);
    ExpectIntLT(BN_cmp(NULL, b), 0);
    ExpectIntLT(BN_cmp(&emptyBN, b), 0);
    ExpectIntGT(BN_cmp(a, NULL), 0);
    ExpectIntGT(BN_cmp(a, &emptyBN), 0);

    ExpectIntEQ(BN_cmp(a, b), 0);
    ExpectIntLT(BN_cmp(a, c), 0);
    ExpectIntGT(BN_cmp(c, b), 0);

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
    ExpectIntEQ(BN_print_fp(XBADFILE, NULL), 0);
    ExpectIntEQ(BN_print_fp(XBADFILE, &emptyBN), 0);
    ExpectIntEQ(BN_print_fp(stderr, NULL), 0);
    ExpectIntEQ(BN_print_fp(stderr, &emptyBN), 0);
    ExpectIntEQ(BN_print_fp(XBADFILE, a), 0);

    ExpectIntEQ(BN_print_fp(stderr, a), 1);
#endif

    BN_clear(a);

    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_clear_free(d);
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_ASN) */
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_init(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
#if !defined(USE_INTEGER_HEAP_MATH) && !defined(HAVE_WOLF_BIGINT)
    BIGNUM* ap = NULL;
    BIGNUM bv;
    BIGNUM cv;
    BIGNUM dv;

    ExpectNotNull(ap = BN_new());

    BN_init(NULL);
    XMEMSET(&bv, 0, sizeof(bv));
    ExpectNull(BN_dup(&bv));

    BN_init(&bv);
    BN_init(&cv);
    BN_init(&dv);

    ExpectIntEQ(BN_set_word(ap, 3), SSL_SUCCESS);
    ExpectIntEQ(BN_set_word(&bv, 2), SSL_SUCCESS);
    ExpectIntEQ(BN_set_word(&cv, 5), SSL_SUCCESS);

    /* a^b mod c = */
    ExpectIntEQ(BN_mod_exp(&dv, NULL, &bv, &cv, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(BN_mod_exp(&dv, ap, &bv, &cv, NULL), WOLFSSL_SUCCESS);

    /* check result  3^2 mod 5 */
    ExpectIntEQ(BN_get_word(&dv), 4);

    /* a*b mod c = */
    ExpectIntEQ(BN_mod_mul(&dv, NULL, &bv, &cv, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(BN_mod_mul(&dv, ap, &bv, &cv, NULL), SSL_SUCCESS);

    /* check result  3*2 mod 5 */
    ExpectIntEQ(BN_get_word(&dv), 1);

    {
        BN_MONT_CTX* montCtx = NULL;
        ExpectNotNull(montCtx = BN_MONT_CTX_new());

        ExpectIntEQ(BN_MONT_CTX_set(montCtx, &cv, NULL), SSL_SUCCESS);
        ExpectIntEQ(BN_set_word(&bv, 2), SSL_SUCCESS);
        ExpectIntEQ(BN_set_word(&cv, 5), SSL_SUCCESS);
        ExpectIntEQ(BN_mod_exp_mont_word(&dv, 3, &bv, &cv, NULL, NULL),
                    WOLFSSL_SUCCESS);
        /* check result  3^2 mod 5 */
        ExpectIntEQ(BN_get_word(&dv), 4);

        BN_MONT_CTX_free(montCtx);
    }

    BN_free(ap);
#endif
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_ASN) */
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_enc_dec(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && !defined(WOLFSSL_SP_MATH)
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM* c = NULL;
    BIGNUM emptyBN;
    char* str = NULL;
    const char* emptyStr = "";
    const char* numberStr = "12345";
    const char* badStr = "g12345";
#if defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY)
    const char* twoStr = "2";
#endif
    unsigned char binNum[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    unsigned char outNum[5];

    /* Setup */
    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(a = BN_new());
    ExpectNotNull(b = BN_new());

    /* Invalid parameters */
    ExpectIntEQ(BN_bn2bin(NULL, NULL), -1);
    ExpectIntEQ(BN_bn2bin(&emptyBN, NULL), -1);
    ExpectIntEQ(BN_bn2bin(NULL, outNum), -1);
    ExpectIntEQ(BN_bn2bin(&emptyBN, outNum), -1);
    ExpectNull(BN_bn2hex(NULL));
    ExpectNull(BN_bn2hex(&emptyBN));
    ExpectNull(BN_bn2dec(NULL));
    ExpectNull(BN_bn2dec(&emptyBN));

    ExpectNotNull(c = BN_bin2bn(NULL, 0, NULL));
    BN_clear(c);
    BN_free(c);
    c = NULL;

    ExpectNotNull(BN_bin2bn(NULL, sizeof(binNum), a));
    BN_free(a);
    a = NULL;
    ExpectNotNull(a = BN_new());
    ExpectIntEQ(BN_set_word(a, 2), 1);
    ExpectNull(BN_bin2bn(binNum, -1, a));
    ExpectNull(BN_bin2bn(binNum, -1, NULL));
    ExpectNull(BN_bin2bn(binNum, sizeof(binNum), &emptyBN));

    ExpectIntEQ(BN_hex2bn(NULL, NULL), 0);
    ExpectIntEQ(BN_hex2bn(NULL, numberStr), 0);
    ExpectIntEQ(BN_hex2bn(&a, NULL), 0);
    ExpectIntEQ(BN_hex2bn(&a, emptyStr), 0);
    ExpectIntEQ(BN_hex2bn(&a, badStr), 0);
    ExpectIntEQ(BN_hex2bn(&c, badStr), 0);

    ExpectIntEQ(BN_dec2bn(NULL, NULL), 0);
    ExpectIntEQ(BN_dec2bn(NULL, numberStr), 0);
    ExpectIntEQ(BN_dec2bn(&a, NULL), 0);
    ExpectIntEQ(BN_dec2bn(&a, emptyStr), 0);
    ExpectIntEQ(BN_dec2bn(&a, badStr), 0);
    ExpectIntEQ(BN_dec2bn(&c, badStr), 0);

    ExpectIntEQ(BN_set_word(a, 2), 1);

    ExpectIntEQ(BN_bn2bin(a, NULL), 1);
    ExpectIntEQ(BN_bn2bin(a, outNum), 1);
    ExpectNotNull(BN_bin2bn(outNum, 1, b));
    ExpectIntEQ(BN_cmp(a, b), 0);
    ExpectNotNull(BN_bin2bn(binNum, sizeof(binNum), b));
    ExpectIntEQ(BN_cmp(a, b), -1);

    ExpectNotNull(str = BN_bn2hex(a));
    ExpectNotNull(BN_hex2bn(&b, str));
    ExpectIntEQ(BN_cmp(a, b), 0);
    ExpectNotNull(BN_hex2bn(&b, numberStr));
    ExpectIntEQ(BN_cmp(a, b), -1);
    XFREE(str, NULL, DYNAMIC_TYPE_OPENSSL);
    str = NULL;

#if defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY)
    ExpectNotNull(str = BN_bn2dec(a));
    ExpectStrEQ(str, twoStr);
    XFREE(str, NULL, DYNAMIC_TYPE_OPENSSL);
    str = NULL;

#ifndef NO_RSA
    ExpectNotNull(str = BN_bn2dec(a));
    ExpectNotNull(BN_dec2bn(&b, str));
    ExpectIntEQ(BN_cmp(a, b), 0);
    ExpectNotNull(BN_dec2bn(&b, numberStr));
    ExpectIntEQ(BN_cmp(a, b), -1);
    XFREE(str, NULL, DYNAMIC_TYPE_OPENSSL);
    str = NULL;
#else
    /* No implementation - fail with good parameters. */
    ExpectIntEQ(BN_dec2bn(&a, numberStr), 0);
#endif
#endif

    BN_free(b);
    BN_free(a);
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_ASN) */
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_word(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && !defined(WOLFSSL_SP_MATH)
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM* c = NULL;
    BIGNUM av;

    ExpectNotNull(a = BN_new());
    ExpectNotNull(b = BN_new());
    ExpectNotNull(c = BN_new());
    XMEMSET(&av, 0, sizeof(av));

    /* Invalid parameter. */
    ExpectIntEQ(BN_add_word(NULL, 3), 0);
    ExpectIntEQ(BN_add_word(&av, 3), 0);
    ExpectIntEQ(BN_sub_word(NULL, 3), 0);
    ExpectIntEQ(BN_sub_word(&av, 3), 0);
    ExpectIntEQ(BN_set_word(NULL, 3), 0);
    ExpectIntEQ(BN_set_word(&av, 3), 0);
    ExpectIntEQ(BN_get_word(NULL), 0);
    ExpectIntEQ(BN_get_word(&av), 0);
    ExpectIntEQ(BN_is_word(NULL, 3), 0);
    ExpectIntEQ(BN_is_word(&av, 3), 0);
#if defined(WOLFSSL_KEY_GEN) && (!defined(NO_RSA) || !defined(NO_DH) || \
    !defined(NO_DSA))
    ExpectIntEQ(BN_mod_word(NULL, 3), -1);
    ExpectIntEQ(BN_mod_word(&av, 3), -1);
#endif
    ExpectIntEQ(BN_one(NULL), 0);
    ExpectIntEQ(BN_one(&av), 0);
    BN_zero(NULL);
    BN_zero(&av);
    ExpectIntEQ(BN_is_one(NULL), 0);
    ExpectIntEQ(BN_is_one(&av), 0);
    ExpectIntEQ(BN_is_zero(NULL), 0);
    ExpectIntEQ(BN_is_zero(&av), 0);

    ExpectIntEQ(BN_set_word(a, 3), 1);
    ExpectIntEQ(BN_set_word(b, 2), 1);
    ExpectIntEQ(BN_set_word(c, 5), 1);

    /* a + 3 = */
    ExpectIntEQ(BN_add_word(a, 3), 1);

    /* check result 3 + 3*/
    ExpectIntEQ(BN_get_word(a), 6);
    ExpectIntEQ(BN_is_word(a, 6), 1);
    ExpectIntEQ(BN_is_word(a, 5), 0);

    /* set a back to 3 */
    ExpectIntEQ(BN_set_word(a, 3), 1);

    /* a - 3 = */
    ExpectIntEQ(BN_sub_word(a, 3), 1);

    /* check result 3 - 3*/
    ExpectIntEQ(BN_get_word(a), 0);

    ExpectIntEQ(BN_one(a), 1);
    ExpectIntEQ(BN_is_word(a, 1), 1);
    ExpectIntEQ(BN_is_word(a, 0), 0);
    ExpectIntEQ(BN_is_one(a), 1);
    ExpectIntEQ(BN_is_zero(a), 0);
    BN_zero(a);
    ExpectIntEQ(BN_is_word(a, 0), 1);
    ExpectIntEQ(BN_is_word(a, 1), 0);
    ExpectIntEQ(BN_is_zero(a), 1);
    ExpectIntEQ(BN_is_one(a), 0);

#if defined(WOLFSSL_KEY_GEN) && (!defined(NO_RSA) || !defined(NO_DH) || \
    !defined(NO_DSA))
    ExpectIntEQ(BN_set_word(a, 5), 1);
    ExpectIntEQ(BN_mod_word(a, 3), 2);
    ExpectIntEQ(BN_mod_word(a, 0), -1);
#endif

    ExpectIntEQ(BN_set_word(a, 5), 1);
    ExpectIntEQ(BN_mul_word(a, 5), 1);
    /* check result 5 * 5 */
    ExpectIntEQ(BN_get_word(a), 25);
#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    ExpectIntEQ(BN_div_word(a, 5), 1);
    /* check result 25 / 5 */
    ExpectIntEQ(BN_get_word(a), 5);
#endif

    BN_free(c);
    BN_free(b);
    BN_free(a);
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_ASN) */
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_bits(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
    BIGNUM* a = NULL;
    BIGNUM emptyBN;

    /* Setup */
    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(a = BN_new());

    /* Invalid parameters. */
    ExpectIntEQ(BN_set_bit(NULL, 1), 0);
    ExpectIntEQ(BN_set_bit(&emptyBN, 1), 0);
    ExpectIntEQ(BN_set_bit(a, -1), 0);
    ExpectIntEQ(BN_clear_bit(NULL, 1), 0);
    ExpectIntEQ(BN_clear_bit(&emptyBN, 1), 0);
    ExpectIntEQ(BN_clear_bit(a, -1), 0);
    ExpectIntEQ(BN_is_bit_set(NULL, 1), 0);
    ExpectIntEQ(BN_is_bit_set(&emptyBN, 1), 0);
    ExpectIntEQ(BN_is_bit_set(a, -1), 0);
    ExpectIntEQ(BN_is_odd(NULL), 0);
    ExpectIntEQ(BN_is_odd(&emptyBN), 0);

    ExpectIntEQ(BN_set_word(a, 0), 1);
    ExpectIntEQ(BN_is_zero(a), 1);
    ExpectIntEQ(BN_set_bit(a, 0x45), 1);
    ExpectIntEQ(BN_is_zero(a), 0);
    ExpectIntEQ(BN_is_bit_set(a, 0x45), 1);
    ExpectIntEQ(BN_clear_bit(a, 0x45), 1);
    ExpectIntEQ(BN_is_bit_set(a, 0x45), 0);
    ExpectIntEQ(BN_is_zero(a), 1);

    ExpectIntEQ(BN_set_bit(a, 0), 1);
    ExpectIntEQ(BN_is_odd(a), 1);
    ExpectIntEQ(BN_clear_bit(a, 0), 1);
    ExpectIntEQ(BN_is_odd(a), 0);
    ExpectIntEQ(BN_set_bit(a, 1), 1);
    ExpectIntEQ(BN_is_odd(a), 0);

    ExpectIntEQ(BN_set_bit(a, 129), 1);
    ExpectIntEQ(BN_get_word(a), WOLFSSL_BN_MAX_VAL);

#ifndef NO_WOLFSSL_STUB
    ExpectIntEQ(BN_mask_bits(a, 1), 0);
#endif

    BN_free(a);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_shift(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM emptyBN;

    /* Setup */
    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(a = BN_new());
    ExpectNotNull(b = BN_new());

    /* Invalid parameters. */
    ExpectIntEQ(BN_lshift(NULL, NULL, 1), 0);
    ExpectIntEQ(BN_lshift(&emptyBN, NULL, 1), 0);
    ExpectIntEQ(BN_lshift(NULL, &emptyBN, 1), 0);
    ExpectIntEQ(BN_lshift(b, NULL, 1), 0);
    ExpectIntEQ(BN_lshift(b, &emptyBN, 1), 0);
    ExpectIntEQ(BN_lshift(NULL, a, 1), 0);
    ExpectIntEQ(BN_lshift(&emptyBN, a, 1), 0);
    ExpectIntEQ(BN_lshift(b, a, -1), 0);

    ExpectIntEQ(BN_rshift(NULL, NULL, 1), 0);
    ExpectIntEQ(BN_rshift(&emptyBN, NULL, 1), 0);
    ExpectIntEQ(BN_rshift(NULL, &emptyBN, 1), 0);
    ExpectIntEQ(BN_rshift(b, NULL, 1), 0);
    ExpectIntEQ(BN_rshift(b, &emptyBN, 1), 0);
    ExpectIntEQ(BN_rshift(NULL, a, 1), 0);
    ExpectIntEQ(BN_rshift(&emptyBN, a, 1), 0);
    ExpectIntEQ(BN_rshift(b, a, -1), 0);

    ExpectIntEQ(BN_set_word(a, 1), 1);
    ExpectIntEQ(BN_lshift(b, a, 1), 1);
    ExpectIntEQ(BN_is_word(b, 2), 1);
    ExpectIntEQ(BN_lshift(a, a, 1), 1);
    ExpectIntEQ(BN_is_word(a, 2), 1);
    ExpectIntEQ(BN_rshift(b, a, 1), 1);
    ExpectIntEQ(BN_is_word(b, 1), 1);
    ExpectIntEQ(BN_rshift(a, a, 1), 1);
    ExpectIntEQ(BN_is_word(a, 1), 1);

    BN_free(b);
    BN_free(a);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_math(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM* r = NULL;
    BIGNUM* rem = NULL;
    BIGNUM emptyBN;
    BN_ULONG val1;
    BN_ULONG val2;

    /* Setup */
    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(a = BN_new());
    ExpectNotNull(b = BN_new());
    ExpectNotNull(r = BN_new());
    ExpectNotNull(rem = BN_new());

    /* Invalid parameters. */
    ExpectIntEQ(BN_add(NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_add(r, NULL, NULL), 0);
    ExpectIntEQ(BN_add(NULL, a, NULL), 0);
    ExpectIntEQ(BN_add(NULL, NULL, b), 0);
    ExpectIntEQ(BN_add(r, a, NULL), 0);
    ExpectIntEQ(BN_add(r, NULL, b), 0);
    ExpectIntEQ(BN_add(NULL, a, b), 0);

    ExpectIntEQ(BN_add(&emptyBN, &emptyBN, &emptyBN), 0);
    ExpectIntEQ(BN_add(r, &emptyBN, &emptyBN), 0);
    ExpectIntEQ(BN_add(&emptyBN, a, &emptyBN), 0);
    ExpectIntEQ(BN_add(&emptyBN, &emptyBN, b), 0);
    ExpectIntEQ(BN_add(r, a, &emptyBN), 0);
    ExpectIntEQ(BN_add(r, &emptyBN, b), 0);
    ExpectIntEQ(BN_add(&emptyBN, a, b), 0);

    ExpectIntEQ(BN_sub(NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_sub(r, NULL, NULL), 0);
    ExpectIntEQ(BN_sub(NULL, a, NULL), 0);
    ExpectIntEQ(BN_sub(NULL, NULL, b), 0);
    ExpectIntEQ(BN_sub(r, a, NULL), 0);
    ExpectIntEQ(BN_sub(r, NULL, b), 0);
    ExpectIntEQ(BN_sub(NULL, a, b), 0);

    ExpectIntEQ(BN_sub(&emptyBN, &emptyBN, &emptyBN), 0);
    ExpectIntEQ(BN_sub(r, &emptyBN, &emptyBN), 0);
    ExpectIntEQ(BN_sub(&emptyBN, a, &emptyBN), 0);
    ExpectIntEQ(BN_sub(&emptyBN, &emptyBN, b), 0);
    ExpectIntEQ(BN_sub(r, a, &emptyBN), 0);
    ExpectIntEQ(BN_sub(r, &emptyBN, b), 0);
    ExpectIntEQ(BN_sub(&emptyBN, a, b), 0);

    ExpectIntEQ(BN_mul(NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mul(r, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mul(NULL, a, NULL, NULL), 0);
    ExpectIntEQ(BN_mul(NULL, NULL, b, NULL), 0);
    ExpectIntEQ(BN_mul(r, a, NULL, NULL), 0);
    ExpectIntEQ(BN_mul(r, NULL, b, NULL), 0);
    ExpectIntEQ(BN_mul(NULL, a, b, NULL), 0);

    ExpectIntEQ(BN_mul(&emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mul(r, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mul(&emptyBN, a, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mul(&emptyBN, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_mul(r, a, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mul(r, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_mul(&emptyBN, a, b, NULL), 0);

    ExpectIntEQ(BN_div(NULL, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_div(r, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_div(NULL, rem, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_div(NULL, NULL, a, NULL, NULL), 0);
    ExpectIntEQ(BN_div(NULL, NULL, NULL, b, NULL), 0);
    ExpectIntEQ(BN_div(NULL, rem, a, b, NULL), 0);
    ExpectIntEQ(BN_div(r, NULL, a, b, NULL), 0);
    ExpectIntEQ(BN_div(r, rem, NULL, b, NULL), 0);
    ExpectIntEQ(BN_div(r, rem, a, NULL, NULL), 0);

    ExpectIntEQ(BN_div(&emptyBN, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_div(r, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_div(&emptyBN, rem, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_div(&emptyBN, &emptyBN, a, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_div(&emptyBN, &emptyBN, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_div(&emptyBN, rem, a, b, NULL), 0);
    ExpectIntEQ(BN_div(r, &emptyBN, a, b, NULL), 0);
    ExpectIntEQ(BN_div(r, rem, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_div(r, rem, a, &emptyBN, NULL), 0);

    ExpectIntEQ(BN_mod(NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod(r, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod(NULL, a, NULL, NULL), 0);
    ExpectIntEQ(BN_mod(NULL, NULL, b, NULL), 0);
    ExpectIntEQ(BN_mod(r, a, NULL, NULL), 0);
    ExpectIntEQ(BN_mod(r, NULL, b, NULL), 0);
    ExpectIntEQ(BN_mod(NULL, a, b, NULL), 0);

    ExpectIntEQ(BN_mod(&emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod(r, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod(&emptyBN, a, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod(&emptyBN, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_mod(r, a, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod(r, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_mod(&emptyBN, a, b, NULL), 0);
    /* END Invalid parameters. */

    val1 = 8;
    val2 = 3;
    ExpectIntEQ(BN_set_word(a, val1), 1);
    ExpectIntEQ(BN_set_word(b, val2), 1);
    ExpectIntEQ(BN_add(r, a, b), 1);
    ExpectIntEQ(BN_is_word(r, val1 + val2), 1);
    ExpectIntEQ(BN_sub(r, a, b), 1);
    ExpectIntEQ(BN_is_word(r, val1 - val2), 1);
    ExpectIntEQ(BN_mul(r, a, b, NULL), 1);
    ExpectIntEQ(BN_is_word(r, val1 * val2), 1);
    ExpectIntEQ(BN_div(r, rem, a, b, NULL), 1);
    ExpectIntEQ(BN_is_word(r, val1 / val2), 1);
    ExpectIntEQ(BN_is_word(rem, val1 % val2), 1);
    ExpectIntEQ(BN_mod(r, a, b, NULL), 1);
    ExpectIntEQ(BN_is_word(r, val1 % val2), 1);

    BN_free(rem);
    BN_free(r);
    BN_free(b);
    BN_free(a);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_math_mod(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM* m = NULL;
    BIGNUM* r = NULL;
    BIGNUM* t = NULL;
    BIGNUM emptyBN;
    BN_ULONG val1;
    BN_ULONG val2;
    BN_ULONG val3;

    /* Setup */
    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(a = BN_new());
    ExpectNotNull(b = BN_new());
    ExpectNotNull(m = BN_new());
    ExpectNotNull(r = BN_new());

    /* Invalid parameters. */
    ExpectIntEQ(BN_mod_add(NULL, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_add(NULL, a, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_add(NULL, NULL, b, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_add(NULL, NULL, NULL, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(NULL, a, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, NULL, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, a, NULL, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, a, m, NULL, NULL), 0);

    ExpectIntEQ(BN_mod_add(&emptyBN, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_add(&emptyBN, a, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_add(&emptyBN, &emptyBN, b, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_add(&emptyBN, &emptyBN, &emptyBN, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(&emptyBN, a, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, &emptyBN, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, a, &emptyBN, m, NULL), 0);
    ExpectIntEQ(BN_mod_add(r, a, m, &emptyBN, NULL), 0);

    ExpectIntEQ(BN_mod_mul(NULL, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_mul(NULL, a, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_mul(NULL, NULL, b, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_mul(NULL, NULL, NULL, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(NULL, a, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, NULL, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, a, NULL, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, a, m, NULL, NULL), 0);

    ExpectIntEQ(BN_mod_mul(&emptyBN, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_mul(&emptyBN, a, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_mul(&emptyBN, &emptyBN, b, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_mul(&emptyBN, &emptyBN, &emptyBN, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(&emptyBN, a, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, &emptyBN, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, a, &emptyBN, m, NULL), 0);
    ExpectIntEQ(BN_mod_mul(r, a, m, &emptyBN, NULL), 0);

    ExpectIntEQ(BN_mod_exp(NULL, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_exp(NULL, a, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_exp(NULL, NULL, b, NULL, NULL), 0);
    ExpectIntEQ(BN_mod_exp(NULL, NULL, NULL, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(NULL, a, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, NULL, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, a, NULL, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, a, m, NULL, NULL), 0);

    ExpectIntEQ(BN_mod_exp(&emptyBN, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, &emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_exp(&emptyBN, a, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_exp(&emptyBN, &emptyBN, b, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_mod_exp(&emptyBN, &emptyBN, &emptyBN, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(&emptyBN, a, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, &emptyBN, b, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, a, &emptyBN, m, NULL), 0);
    ExpectIntEQ(BN_mod_exp(r, a, m, &emptyBN, NULL), 0);

    ExpectNull(BN_mod_inverse(r, NULL, NULL, NULL));
    ExpectNull(BN_mod_inverse(r, a, NULL, NULL));
    ExpectNull(BN_mod_inverse(r, NULL, m, NULL));
    ExpectNull(BN_mod_inverse(r, NULL, m, NULL));
    ExpectNull(BN_mod_inverse(r, a, NULL, NULL));

    ExpectNull(BN_mod_inverse(&emptyBN, &emptyBN, &emptyBN, NULL));
    ExpectNull(BN_mod_inverse(r, &emptyBN, &emptyBN, NULL));
    ExpectNull(BN_mod_inverse(&emptyBN, a, &emptyBN, NULL));
    ExpectNull(BN_mod_inverse(&emptyBN, &emptyBN, m, NULL));
    ExpectNull(BN_mod_inverse(&emptyBN, a, m, NULL));
    ExpectNull(BN_mod_inverse(r, &emptyBN, m, NULL));
    ExpectNull(BN_mod_inverse(r, a, &emptyBN, NULL));
    /* END Invalid parameters. */

    val1 = 9;
    val2 = 13;
    val3 = 5;
    ExpectIntEQ(BN_set_word(a, val1), 1);
    ExpectIntEQ(BN_set_word(b, val2), 1);
    ExpectIntEQ(BN_set_word(m, val3), 1);
    ExpectIntEQ(BN_mod_add(r, a, b, m, NULL), 1);
    ExpectIntEQ(BN_is_word(r, (val1 + val2) % val3), 1);
    ExpectIntEQ(BN_mod_mul(r, a, b, m, NULL), 1);
    ExpectIntEQ(BN_is_word(r, (val1 * val2) % val3), 1);

    ExpectIntEQ(BN_set_word(a, 2), 1);
    ExpectIntEQ(BN_set_word(b, 3), 1);
    ExpectIntEQ(BN_set_word(m, 5), 1);
    /* (2 ^ 3) % 5 = 8 % 5 = 3 */
    ExpectIntEQ(BN_mod_exp(r, a, b, m, NULL), 1);
    ExpectIntEQ(BN_is_word(r, 3), 1);

    /* (2 * 3) % 5 = 6 % 5 = 1 => inv = 3 */
    ExpectNotNull(BN_mod_inverse(r, a, m, NULL));
    ExpectIntEQ(BN_is_word(r, 3), 1);
    ExpectNotNull(t = BN_mod_inverse(NULL, a, m, NULL));
    ExpectIntEQ(BN_is_word(t, 3), 1);
    BN_free(t);
    /* No inverse case. No inverse when a divides b. */
    ExpectIntEQ(BN_set_word(a, 3), 1);
    ExpectIntEQ(BN_set_word(m, 9), 1);
    ExpectNull(BN_mod_inverse(r, a, m, NULL));

    BN_free(r);
    BN_free(m);
    BN_free(b);
    BN_free(a);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_math_other(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM* r = NULL;
    BIGNUM emptyBN;

    /* Setup */
    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(a = BN_new());
    ExpectNotNull(b = BN_new());
    ExpectNotNull(r = BN_new());

    /* Invalid parameters. */
    ExpectIntEQ(BN_gcd(NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_gcd(r, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_gcd(NULL, a, NULL, NULL), 0);
    ExpectIntEQ(BN_gcd(NULL, NULL, b, NULL), 0);
    ExpectIntEQ(BN_gcd(NULL, a, b, NULL), 0);
    ExpectIntEQ(BN_gcd(r, NULL, b, NULL), 0);
    ExpectIntEQ(BN_gcd(r, a, NULL, NULL), 0);

    ExpectIntEQ(BN_gcd(&emptyBN, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_gcd(r, &emptyBN, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_gcd(&emptyBN, a, &emptyBN, NULL), 0);
    ExpectIntEQ(BN_gcd(&emptyBN, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_gcd(&emptyBN, a, b, NULL), 0);
    ExpectIntEQ(BN_gcd(r, &emptyBN, b, NULL), 0);
    ExpectIntEQ(BN_gcd(r, a, &emptyBN, NULL), 0);
    /* END Invalid parameters. */

    /* No common factors between 2 and 3. */
    ExpectIntEQ(BN_set_word(a, 2), 1);
    ExpectIntEQ(BN_set_word(b, 3), 1);
    ExpectIntEQ(BN_gcd(r, a, b, NULL), 1);
    ExpectIntEQ(BN_is_word(r, 1), 1);
    /* 3 is largest value that divides both 6 and 9. */
    ExpectIntEQ(BN_set_word(a, 6), 1);
    ExpectIntEQ(BN_set_word(b, 9), 1);
    ExpectIntEQ(BN_gcd(r, a, b, NULL), 1);
    ExpectIntEQ(BN_is_word(r, 3), 1);
    /* GCD of 0 and 0 is undefined. */
    ExpectIntEQ(BN_set_word(a, 0), 1);
    ExpectIntEQ(BN_set_word(b, 0), 1);
    ExpectIntEQ(BN_gcd(r, a, b, NULL), 0);

    /* Teardown */
    BN_free(r);
    BN_free(b);
    BN_free(a);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_rand(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(OPENSSL_EXTRA_NO_BN)
    BIGNUM* bn = NULL;
    BIGNUM* range = NULL;
    BIGNUM emptyBN;

    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(bn = BN_new());
    ExpectNotNull(range = BN_new());

    /* Invalid parameters. */
    ExpectIntEQ(BN_rand(NULL, -1, 0, 0), 0);
    ExpectIntEQ(BN_rand(bn, -1, 0, 0), 0);
    ExpectIntEQ(BN_rand(NULL, 1, 0, 0), 0);
    ExpectIntEQ(BN_rand(&emptyBN, -1, 0, 0), 0);
    ExpectIntEQ(BN_rand(bn, -1, 0, 0), 0);
    ExpectIntEQ(BN_rand(&emptyBN, 1, 0, 0), 0);

    ExpectIntEQ(BN_pseudo_rand(NULL, -1, 0, 0), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, -1, 0, 0), 0);
    ExpectIntEQ(BN_pseudo_rand(NULL, 1, 0, 0), 0);
    ExpectIntEQ(BN_pseudo_rand(&emptyBN, -1, 0, 0), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, -1, 0, 0), 0);
    ExpectIntEQ(BN_pseudo_rand(&emptyBN, 1, 0, 0), 0);

    ExpectIntEQ(BN_rand_range(NULL, NULL), 0);
    ExpectIntEQ(BN_rand_range(bn, NULL), 0);
    ExpectIntEQ(BN_rand_range(NULL, range), 0);
    ExpectIntEQ(BN_rand_range(&emptyBN, &emptyBN), 0);
    ExpectIntEQ(BN_rand_range(bn, &emptyBN), 0);
    ExpectIntEQ(BN_rand_range(&emptyBN, range), 0);

    /* 0 bit random value must be 0 and so cannot set bit in any position. */
    ExpectIntEQ(BN_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    ExpectIntEQ(BN_rand(bn, 0, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    ExpectIntEQ(BN_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ANY,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    ExpectIntEQ(BN_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 0);
    ExpectIntEQ(BN_rand(bn, 0, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, 0, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ANY,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, 0, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 0);

    /* 1 bit random value must have no more than one top bit set. */
    ExpectIntEQ(BN_rand(bn, 1, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 0);
    ExpectIntEQ(BN_rand(bn, 1, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, 1, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 0);
    ExpectIntEQ(BN_pseudo_rand(bn, 1, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 0);
    /* END Invalid parameters. */

    /* 0 bit random: 0. */
    ExpectIntEQ(BN_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ANY,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_is_zero(bn), 1);

    ExpectIntEQ(BN_set_word(bn, 2), 1); /* Make sure not zero. */
    ExpectIntEQ(BN_pseudo_rand(bn, 0, WOLFSSL_BN_RAND_TOP_ANY,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_is_zero(bn), 1);

    /* 1 bit random: 0 or 1. */
    ExpectIntEQ(BN_rand(bn, 1, WOLFSSL_BN_RAND_TOP_ANY,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntLT(BN_get_word(bn), 2); /* Make sure valid range. */
    ExpectIntEQ(BN_rand(bn, 1, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_get_word(bn), 1);
    ExpectIntEQ(BN_rand(bn, 1, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 1);
    ExpectIntEQ(BN_get_word(bn), 1);

    ExpectIntEQ(BN_pseudo_rand(bn, 1, WOLFSSL_BN_RAND_TOP_ANY,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntLT(BN_get_word(bn), 2); /* Make sure valid range. */
    ExpectIntEQ(BN_pseudo_rand(bn, 1, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_get_word(bn), 1);
    ExpectIntEQ(BN_pseudo_rand(bn, 1, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 1);
    ExpectIntEQ(BN_get_word(bn), 1);

    ExpectIntEQ(BN_rand(bn, 8, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_num_bits(bn), 8);
    ExpectIntEQ(BN_is_bit_set(bn, 7), 1);
    ExpectIntEQ(BN_pseudo_rand(bn, 8, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_num_bits(bn), 8);
    ExpectIntEQ(BN_is_bit_set(bn, 7), 1);

    ExpectIntEQ(BN_rand(bn, 8, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_is_bit_set(bn, 7), 1);
    ExpectIntEQ(BN_is_bit_set(bn, 6), 1);
    ExpectIntEQ(BN_pseudo_rand(bn, 8, WOLFSSL_BN_RAND_TOP_TWO,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_is_bit_set(bn, 7), 1);
    ExpectIntEQ(BN_is_bit_set(bn, 6), 1);

    ExpectIntEQ(BN_rand(bn, 8, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 1);
    ExpectIntEQ(BN_is_bit_set(bn, 0), 1);
    ExpectIntEQ(BN_pseudo_rand(bn, 8, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ODD), 1);
    ExpectIntEQ(BN_is_bit_set(bn, 0), 1);

    /* Regression test: Older versions of wolfSSL_BN_rand would round the
     * requested number of bits up to the nearest multiple of 8. E.g. in this
     * case, requesting a 13-bit random number would actually return a 16-bit
     * random number. */
    ExpectIntEQ(BN_rand(bn, 13, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_num_bits(bn), 13);

    ExpectIntEQ(BN_rand(range, 64, WOLFSSL_BN_RAND_TOP_ONE,
        WOLFSSL_BN_RAND_BOTTOM_ANY), 1);
    ExpectIntEQ(BN_rand_range(bn, range), 1);

    ExpectIntEQ(BN_set_word(range, 0), 1);
    ExpectIntEQ(BN_rand_range(bn, range), 1);
    ExpectIntEQ(BN_set_word(range, 1), 1);
    ExpectIntEQ(BN_rand_range(bn, range), 1);

    BN_free(bn);
    BN_free(range);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BN_prime(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_ASN) && \
    !defined(OPENSSL_EXTRA_NO_BN) && !defined(WOLFSSL_SP_MATH)
#if defined(WOLFSSL_KEY_GEN) && (!defined(NO_RSA) || !defined(NO_DH) || !defined(NO_DSA))
    BIGNUM* a = NULL;
    BIGNUM* add = NULL;
    BIGNUM* rem = NULL;
    BIGNUM emptyBN;

    XMEMSET(&emptyBN, 0, sizeof(emptyBN));
    ExpectNotNull(a = BN_new());
    ExpectNotNull(add = BN_new());
    ExpectNotNull(rem = BN_new());

    /* Invalid parameters. */
    /* BN_generate_prime_ex()
     * prime - must have valid BIGNUM
     * bits  - Greater then 0
     * safe  - not supported, must be 0
     * add   - not supported, must be NULL
     * rem   - not supported, must be NULL
     * cb    - anything
     */
    ExpectIntEQ(BN_generate_prime_ex(NULL, -1, 1, add, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(&emptyBN, -1, 1, add, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(a, -1, 1, add, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(NULL, 2, 1, add, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(&emptyBN, 2, 1, add, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(NULL, -1, 0, add, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(&emptyBN, -1, 0, add, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(NULL, -1, 1, NULL, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(&emptyBN, -1, 1, NULL, rem, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(NULL, -1, 1, add, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(&emptyBN, -1, 1, add, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(NULL, 2, 0, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(&emptyBN, 2, 0, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(a, -1, 0, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(a, 0, 0, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(a, 2, 1, NULL, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(a, 2, 0, add, NULL, NULL), 0);
    ExpectIntEQ(BN_generate_prime_ex(a, 2, 0, NULL, rem, NULL), 0);

    ExpectIntEQ(BN_is_prime_ex(NULL, -1, NULL, NULL), -1);
    ExpectIntEQ(BN_is_prime_ex(&emptyBN, -1, NULL, NULL), -1);
    ExpectIntEQ(BN_is_prime_ex(a, -1, NULL, NULL), -1);
    ExpectIntEQ(BN_is_prime_ex(a, 2048, NULL, NULL), -1);
    ExpectIntEQ(BN_is_prime_ex(NULL, 1, NULL, NULL), -1);
    ExpectIntEQ(BN_is_prime_ex(&emptyBN, 1, NULL, NULL), -1);
    /* END Invalid parameters. */

    ExpectIntEQ(BN_generate_prime_ex(a, 512, 0, NULL, NULL, NULL), 1);
    ExpectIntEQ(BN_is_prime_ex(a, 8, NULL, NULL), 1);

    ExpectIntEQ(BN_clear_bit(a, 0), 1);
    ExpectIntEQ(BN_is_prime_ex(a, 8, NULL, NULL), 0);

    BN_free(rem);
    BN_free(add);
    BN_free(a);
#endif
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_ASN) */
    return EXPECT_RESULT();
}

