/* test_ossl_cipher.c
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

#include <wolfssl/openssl/des.h>
#include <wolfssl/openssl/aes.h>
#include <wolfssl/openssl/rc4.h>
#include <wolfssl/openssl/modes.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_cipher.h>

/*******************************************************************************
 * Cipher OpenSSL compatibility API Testing
 ******************************************************************************/

int test_wolfSSL_DES(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DES3)
    const_DES_cblock myDes;
    DES_cblock iv;
    DES_key_schedule key;
    word32 i = 0;
    DES_LONG dl = 0;
    unsigned char msg[] = "hello wolfssl";
    unsigned char weakKey[][8] = {
        { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
        { 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE },
        { 0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1 },
        { 0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E }
    };
    unsigned char semiWeakKey[][8] = {
        { 0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E },
        { 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01 },
        { 0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1 },
        { 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01 },
        { 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE },
        { 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01 },
        { 0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1 },
        { 0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E },
        { 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE },
        { 0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E },
        { 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE },
        { 0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1 }
    };

    /* check, check of odd parity */
    XMEMSET(myDes, 4, sizeof(const_DES_cblock));
    XMEMSET(key, 5, sizeof(DES_key_schedule));

    DES_set_key(&myDes, &key);

    myDes[0] = 6; /* set even parity */
    ExpectIntEQ(DES_set_key_checked(&myDes, &key), -1);
    ExpectIntNE(key[0], myDes[0]); /* should not have copied over key */
    ExpectIntEQ(DES_set_key_checked(NULL, NULL), -2);
    ExpectIntEQ(DES_set_key_checked(&myDes, NULL), -2);
    ExpectIntEQ(DES_set_key_checked(NULL, &key), -2);

    /* set odd parity for success case */
    DES_set_odd_parity(&myDes);
    ExpectIntEQ(DES_check_key_parity(&myDes), 1);
    fprintf(stderr, "%02x %02x %02x %02x", myDes[0], myDes[1], myDes[2],
        myDes[3]);
    ExpectIntEQ(DES_set_key_checked(&myDes, &key), 0);
    for (i = 0; i < sizeof(DES_key_schedule); i++) {
        ExpectIntEQ(key[i], myDes[i]);
    }
    ExpectIntEQ(DES_is_weak_key(&myDes), 0);

    /* check weak key */
    XMEMSET(myDes, 1, sizeof(const_DES_cblock));
    XMEMSET(key, 5, sizeof(DES_key_schedule));
    ExpectIntEQ(DES_set_key_checked(&myDes, &key), -2);
    ExpectIntNE(key[0], myDes[0]); /* should not have copied over key */

    DES_set_key_unchecked(NULL, NULL);
    DES_set_key_unchecked(&myDes, NULL);
    DES_set_key_unchecked(NULL, &key);
    /* compare arrays, should be the same */
    /* now do unchecked copy of a weak key over */
    DES_set_key_unchecked(&myDes, &key);
    /* compare arrays, should be the same */
    for (i = 0; i < sizeof(DES_key_schedule); i++) {
        ExpectIntEQ(key[i], myDes[i]);
    }
    ExpectIntEQ(DES_is_weak_key(&myDes), 1);

    myDes[7] = 2;
    ExpectIntEQ(DES_set_key_checked(&myDes, &key), 0);
    ExpectIntEQ(DES_is_weak_key(&myDes), 0);
    ExpectIntEQ(DES_is_weak_key(NULL), 1);

    /* Test all weak keys. */
    for (i = 0; i < sizeof(weakKey) / sizeof(*weakKey); i++) {
        ExpectIntEQ(DES_set_key_checked(&weakKey[i], &key), -2);
    }
    /* Test all semi-weak keys. */
    for (i = 0; i < sizeof(semiWeakKey) / sizeof(*semiWeakKey); i++) {
        ExpectIntEQ(DES_set_key_checked(&semiWeakKey[i], &key), -2);
    }

    /* check DES_key_sched API */
    XMEMSET(key, 1, sizeof(DES_key_schedule));
    ExpectIntEQ(DES_key_sched(&myDes, NULL), 0);
    ExpectIntEQ(DES_key_sched(NULL, &key),   0);
    ExpectIntEQ(DES_key_sched(&myDes, &key), 0);
    /* compare arrays, should be the same */
    for (i = 0; i < sizeof(DES_key_schedule); i++) {
        ExpectIntEQ(key[i], myDes[i]);
    }


    ExpectIntEQ((DES_cbc_cksum(NULL, NULL, 0, NULL, NULL)), 0);
    ExpectIntEQ((DES_cbc_cksum(msg, NULL, 0, NULL, NULL)), 0);
    ExpectIntEQ((DES_cbc_cksum(NULL, &key, 0, NULL, NULL)), 0);
    ExpectIntEQ((DES_cbc_cksum(NULL, NULL, 0, &myDes, NULL)), 0);
    ExpectIntEQ((DES_cbc_cksum(NULL, NULL, 0, NULL, &iv)), 0);
    ExpectIntEQ((DES_cbc_cksum(NULL, &key, sizeof(msg), &myDes, &iv)), 0);
    ExpectIntEQ((DES_cbc_cksum(msg, NULL, sizeof(msg), &myDes, &iv)), 0);
    ExpectIntEQ((DES_cbc_cksum(msg, &key, sizeof(msg), NULL, &iv)), 0);
    ExpectIntEQ((DES_cbc_cksum(msg, &key, sizeof(msg), &myDes, NULL)), 0);
    /* DES_cbc_cksum should return the last 4 of the last 8 bytes after
     * DES_cbc_encrypt on the input */
    XMEMSET(iv, 0, sizeof(DES_cblock));
    XMEMSET(myDes, 5, sizeof(DES_key_schedule));
    ExpectIntGT((dl = DES_cbc_cksum(msg, &key, sizeof(msg), &myDes, &iv)), 0);
    ExpectIntEQ(dl, 480052723);
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_DES3) */
    return EXPECT_RESULT();
}

int test_wolfSSL_DES_ncbc(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DES3)
    const_DES_cblock myDes;
    DES_cblock iv = {1};
    DES_key_schedule key = {0};
    unsigned char msg[] = "hello wolfssl";
    unsigned char out[DES_BLOCK_SIZE * 2] = {0};
    unsigned char pln[DES_BLOCK_SIZE * 2] = {0};

    unsigned char exp[]  = {0x31, 0x98, 0x2F, 0x3A, 0x55, 0xBF, 0xD8, 0xC4};
    unsigned char exp2[] = {0xC7, 0x45, 0x8B, 0x28, 0x10, 0x53, 0xE0, 0x58};

    /* partial block test */
    DES_set_key(&key, &myDes);
    DES_ncbc_encrypt(msg, out, 3, &myDes, &iv, DES_ENCRYPT);
    ExpectIntEQ(XMEMCMP(exp, out, DES_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(exp, iv, DES_BLOCK_SIZE), 0);

    DES_set_key(&key, &myDes);
    XMEMSET((byte*)&iv, 0, DES_BLOCK_SIZE);
    *((byte*)&iv) = 1;
    DES_ncbc_encrypt(out, pln, 3, &myDes, &iv, DES_DECRYPT);
    ExpectIntEQ(XMEMCMP(msg, pln, 3), 0);
    ExpectIntEQ(XMEMCMP(exp, iv, DES_BLOCK_SIZE), 0);

    /* full block test */
    DES_set_key(&key, &myDes);
    XMEMSET(pln, 0, DES_BLOCK_SIZE);
    XMEMSET((byte*)&iv, 0, DES_BLOCK_SIZE);
    *((byte*)&iv) = 1;
    DES_ncbc_encrypt(msg, out, 8, &myDes, &iv, DES_ENCRYPT);
    ExpectIntEQ(XMEMCMP(exp2, out, DES_BLOCK_SIZE), 0);
    ExpectIntEQ(XMEMCMP(exp2, iv, DES_BLOCK_SIZE), 0);

    DES_set_key(&key, &myDes);
    XMEMSET((byte*)&iv, 0, DES_BLOCK_SIZE);
    *((byte*)&iv) = 1;
    DES_ncbc_encrypt(out, pln, 8, &myDes, &iv, DES_DECRYPT);
    ExpectIntEQ(XMEMCMP(msg, pln, 8), 0);
    ExpectIntEQ(XMEMCMP(exp2, iv, DES_BLOCK_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DES_ecb_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DES3) && defined(WOLFSSL_DES_ECB)
    WOLFSSL_DES_cblock input1, input2, output1, output2, back1, back2;
    WOLFSSL_DES_key_schedule key;

    XMEMCPY(key, "12345678", sizeof(WOLFSSL_DES_key_schedule));
    XMEMCPY(input1, "Iamhuman", sizeof(WOLFSSL_DES_cblock));
    XMEMCPY(input2, "Whoisit?", sizeof(WOLFSSL_DES_cblock));
    XMEMSET(output1, 0, sizeof(WOLFSSL_DES_cblock));
    XMEMSET(output2, 0, sizeof(WOLFSSL_DES_cblock));
    XMEMSET(back1, 0, sizeof(WOLFSSL_DES_cblock));
    XMEMSET(back2, 0, sizeof(WOLFSSL_DES_cblock));

    wolfSSL_DES_ecb_encrypt(NULL, NULL, NULL, DES_ENCRYPT);
    wolfSSL_DES_ecb_encrypt(&input1, NULL, NULL, DES_ENCRYPT);
    wolfSSL_DES_ecb_encrypt(NULL, &output1, NULL, DES_ENCRYPT);
    wolfSSL_DES_ecb_encrypt(NULL, NULL, &key, DES_ENCRYPT);
    wolfSSL_DES_ecb_encrypt(&input1, &output1, NULL, DES_ENCRYPT);
    wolfSSL_DES_ecb_encrypt(&input1, NULL, &key, DES_ENCRYPT);
    wolfSSL_DES_ecb_encrypt(NULL, &output1, &key, DES_ENCRYPT);

    /* Encrypt messages */
    wolfSSL_DES_ecb_encrypt(&input1, &output1, &key, DES_ENCRYPT);
    wolfSSL_DES_ecb_encrypt(&input2, &output2, &key, DES_ENCRYPT);

    {
        /* Decrypt messages */
        int ret1 = 0;
        int ret2 = 0;
        wolfSSL_DES_ecb_encrypt(&output1, &back1, &key, DES_DECRYPT);
        ExpectIntEQ(ret1 = XMEMCMP((unsigned char *)back1,
            (unsigned char *)input1, sizeof(WOLFSSL_DES_cblock)), 0);
        wolfSSL_DES_ecb_encrypt(&output2, &back2, &key, DES_DECRYPT);
        ExpectIntEQ(ret2 = XMEMCMP((unsigned char *)back2,
            (unsigned char *)input2, sizeof(WOLFSSL_DES_cblock)), 0);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DES_ede3_cbc_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DES3)
    unsigned char input1[8], input2[8];
    unsigned char output1[8], output2[8];
    unsigned char back1[8], back2[8];
    WOLFSSL_DES_cblock iv1, iv2;
    WOLFSSL_DES_key_schedule key1, key2, key3;
    int i;

    XMEMCPY(key1, "12345678", sizeof(WOLFSSL_DES_key_schedule));
    XMEMCPY(key2, "23456781", sizeof(WOLFSSL_DES_key_schedule));
    XMEMCPY(key3, "34567823", sizeof(WOLFSSL_DES_key_schedule));
    XMEMCPY(input1, "Iamhuman", sizeof(input1));
    XMEMCPY(input2, "Whoisit?", sizeof(input2));

    XMEMSET(output1, 0, sizeof(output1));
    XMEMSET(output2, 0, sizeof(output2));
    XMEMSET(back1, 0, sizeof(back1));
    XMEMSET(back2, 0, sizeof(back2));

    XMEMCPY(iv1, "87654321", sizeof(WOLFSSL_DES_cblock));
    XMEMCPY(iv2, "98765432", sizeof(WOLFSSL_DES_cblock));
    /* Encrypt messages */
    wolfSSL_DES_ede3_cbc_encrypt(input1, output1, 8, &key1, &key2, &key3, &iv1,
        DES_ENCRYPT);
    wolfSSL_DES_ede3_cbc_encrypt(input2, output2, 8, &key1, &key2, &key3, &iv2,
        DES_ENCRYPT);

    {
        XMEMCPY(iv1, "87654321", sizeof(WOLFSSL_DES_cblock));
        XMEMCPY(iv2, "98765432", sizeof(WOLFSSL_DES_cblock));
        /* Decrypt messages */
        wolfSSL_DES_ede3_cbc_encrypt(output1, back1, 8, &key1, &key2, &key3,
            &iv1, DES_DECRYPT);
        ExpectIntEQ(XMEMCMP(back1, input1, sizeof(input1)), 0);
        wolfSSL_DES_ede3_cbc_encrypt(output2, back2, 8, &key1, &key2, &key3,
            &iv2, DES_DECRYPT);
        ExpectIntEQ(XMEMCMP(back2, input2, sizeof(input2)), 0);
    }

    for (i = 0; i < 8; i++) {
        XMEMSET(output1, 0, sizeof(output1));
        XMEMSET(output2, 0, sizeof(output2));
        XMEMSET(back1, 0, sizeof(back1));
        XMEMSET(back2, 0, sizeof(back2));

        XMEMCPY(iv1, "87654321", sizeof(WOLFSSL_DES_cblock));
        XMEMCPY(iv2, "98765432", sizeof(WOLFSSL_DES_cblock));
        /* Encrypt partial messages */
        wolfSSL_DES_ede3_cbc_encrypt(input1, output1, i, &key1, &key2, &key3,
            &iv1, DES_ENCRYPT);
        wolfSSL_DES_ede3_cbc_encrypt(input2, output2, i, &key1, &key2, &key3,
            &iv2, DES_ENCRYPT);

        {
            XMEMCPY(iv1, "87654321", sizeof(WOLFSSL_DES_cblock));
            XMEMCPY(iv2, "98765432", sizeof(WOLFSSL_DES_cblock));
            /* Decrypt messages */
            wolfSSL_DES_ede3_cbc_encrypt(output1, back1, i, &key1, &key2,
                &key3, &iv1, DES_DECRYPT);
            ExpectIntEQ(XMEMCMP(back1, input1, i), 0);
            wolfSSL_DES_ede3_cbc_encrypt(output2, back2, i, &key1, &key2,
                &key3, &iv2, DES_DECRYPT);
            ExpectIntEQ(XMEMCMP(back2, input2, i), 0);
        }
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_AES_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_ECB) && \
    defined(WOLFSSL_AES_256) && !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    AES_KEY enc;
    AES_KEY dec;
    const byte msg[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    const byte exp[] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    };
    const byte key[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    byte eout[sizeof(msg)];
    byte dout[sizeof(msg)];

    ExpectIntEQ(AES_set_encrypt_key(key, sizeof(key)*8, &enc), 0);
    ExpectIntEQ(AES_set_decrypt_key(key, sizeof(key)*8, &dec), 0);

    wolfSSL_AES_encrypt(NULL, NULL, NULL);
    wolfSSL_AES_encrypt(msg, NULL, NULL);
    wolfSSL_AES_encrypt(NULL, eout, NULL);
    wolfSSL_AES_encrypt(NULL, NULL, &enc);
    wolfSSL_AES_encrypt(msg, eout, NULL);
    wolfSSL_AES_encrypt(msg, NULL, &enc);
    wolfSSL_AES_encrypt(NULL, eout, &enc);

    wolfSSL_AES_decrypt(NULL, NULL, NULL);
    wolfSSL_AES_decrypt(eout, NULL, NULL);
    wolfSSL_AES_decrypt(NULL, dout, NULL);
    wolfSSL_AES_decrypt(NULL, NULL, &dec);
    wolfSSL_AES_decrypt(eout, dout, NULL);
    wolfSSL_AES_decrypt(eout, NULL, &dec);
    wolfSSL_AES_decrypt(NULL, dout, &dec);

    wolfSSL_AES_encrypt(msg, eout, &enc);
    ExpectIntEQ(XMEMCMP(eout, exp, AES_BLOCK_SIZE), 0);
    wolfSSL_AES_decrypt(eout, dout, &dec);
    ExpectIntEQ(XMEMCMP(dout, msg, AES_BLOCK_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_AES_ecb_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(HAVE_AES_ECB) && \
    defined(WOLFSSL_AES_256) && !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    AES_KEY aes;
    const byte msg[] =
    {
      0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
      0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    const byte verify[] =
    {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
        0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };

    const byte key[] =
    {
      0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
      0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
      0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
      0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };


    byte out[AES_BLOCK_SIZE];

    ExpectIntEQ(AES_set_encrypt_key(key, sizeof(key)*8, &aes), 0);
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    AES_ecb_encrypt(msg, out, &aes, AES_ENCRYPT);
    ExpectIntEQ(XMEMCMP(out, verify, AES_BLOCK_SIZE), 0);

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(AES_set_decrypt_key(key, sizeof(key)*8, &aes), 0);
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    AES_ecb_encrypt(verify, out, &aes, AES_DECRYPT);
    ExpectIntEQ(XMEMCMP(out, msg, AES_BLOCK_SIZE), 0);
#endif

    /* test bad arguments */
    AES_ecb_encrypt(NULL, out, &aes, AES_DECRYPT);
    AES_ecb_encrypt(verify, NULL, &aes, AES_DECRYPT);
    AES_ecb_encrypt(verify, out, NULL, AES_DECRYPT);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_AES_cbc_encrypt(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(OPENSSL_EXTRA) && \
        !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    AES_KEY aes;
    AES_KEY* aesN = NULL;
    size_t len = 0;
    size_t lenB = 0;
    int keySz0 = 0;
    int keySzN = -1;
    byte out[AES_BLOCK_SIZE] = {0};
    byte* outN = NULL;

    /* Test vectors retrieved from:
     *   <begin URL>
     *       https://csrc.nist.gov/
     *       CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/
     *       documents/aes/KAT_AES.zip
     *   </end URL>
     */
    const byte* pt128N  = NULL;
    byte* key128N       = NULL;
    byte* iv128N        = NULL;
    byte iv128tmp[AES_BLOCK_SIZE] = {0};

    const byte pt128[]  = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    const byte ct128[]  = { 0x87,0x85,0xb1,0xa7,0x5b,0x0f,0x3b,0xd9,
                            0x58,0xdc,0xd0,0xe2,0x93,0x18,0xc5,0x21 };

    const byte iv128[]  = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    byte key128[]       = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                            0xff,0xff,0xf0,0x00,0x00,0x00,0x00,0x00 };


    len = sizeof(pt128);

    #define STRESS_T(a, b, c, d, e, f, g, h, i) \
            wolfSSL_AES_cbc_encrypt(a, b, c, d, e, f); \
            ExpectIntNE(XMEMCMP(b, g, h), i)

    #define RESET_IV(x, y) XMEMCPY(x, y, AES_BLOCK_SIZE)

    /* Stressing wolfSSL_AES_cbc_encrypt() */
    STRESS_T(pt128N, out, len, &aes, iv128tmp, 1, ct128, AES_BLOCK_SIZE, 0);
    STRESS_T(pt128, out, len, &aes, iv128N, 1, ct128, AES_BLOCK_SIZE, 0);

    wolfSSL_AES_cbc_encrypt(pt128, outN, len, &aes, iv128tmp, AES_ENCRYPT);
    ExpectIntNE(XMEMCMP(out, ct128, AES_BLOCK_SIZE), 0);
    wolfSSL_AES_cbc_encrypt(pt128, out, len, aesN, iv128tmp, AES_ENCRYPT);
    ExpectIntNE(XMEMCMP(out, ct128, AES_BLOCK_SIZE), 0);

    STRESS_T(pt128, out, lenB, &aes, iv128tmp, 1, ct128, AES_BLOCK_SIZE, 0);

    /* Stressing wolfSSL_AES_set_encrypt_key */
    ExpectIntNE(wolfSSL_AES_set_encrypt_key(key128N, sizeof(key128)*8, &aes),0);
    ExpectIntNE(wolfSSL_AES_set_encrypt_key(key128, sizeof(key128)*8, aesN),0);
    ExpectIntNE(wolfSSL_AES_set_encrypt_key(key128, keySz0, &aes), 0);
    ExpectIntNE(wolfSSL_AES_set_encrypt_key(key128, keySzN, &aes), 0);

    /* Stressing wolfSSL_AES_set_decrypt_key */
    ExpectIntNE(wolfSSL_AES_set_decrypt_key(key128N, sizeof(key128)*8, &aes),0);
    ExpectIntNE(wolfSSL_AES_set_decrypt_key(key128N, sizeof(key128)*8, aesN),0);
    ExpectIntNE(wolfSSL_AES_set_decrypt_key(key128, keySz0, &aes), 0);
    ExpectIntNE(wolfSSL_AES_set_decrypt_key(key128, keySzN, &aes), 0);

  #ifdef WOLFSSL_AES_128

    /* wolfSSL_AES_cbc_encrypt() 128-bit */
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    RESET_IV(iv128tmp, iv128);

    ExpectIntEQ(wolfSSL_AES_set_encrypt_key(key128, sizeof(key128)*8, &aes), 0);
    wolfSSL_AES_cbc_encrypt(pt128, out, len, &aes, iv128tmp, AES_ENCRYPT);
    ExpectIntEQ(XMEMCMP(out, ct128, AES_BLOCK_SIZE), 0);
    wc_AesFree((Aes*)&aes);

    #ifdef HAVE_AES_DECRYPT

    /* wolfSSL_AES_cbc_encrypt() 128-bit in decrypt mode */
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    RESET_IV(iv128tmp, iv128);
    len = sizeof(ct128);

    ExpectIntEQ(wolfSSL_AES_set_decrypt_key(key128, sizeof(key128)*8, &aes), 0);
    wolfSSL_AES_cbc_encrypt(ct128, out, len, &aes, iv128tmp, AES_DECRYPT);
    ExpectIntEQ(XMEMCMP(out, pt128, AES_BLOCK_SIZE), 0);
    wc_AesFree((Aes*)&aes);

    #endif

  #endif /* WOLFSSL_AES_128 */
  #ifdef WOLFSSL_AES_192
  {
    /* Test vectors from NIST Special Publication 800-38A, 2001 Edition
     * Appendix F.2.3  */

    byte iv192tmp[AES_BLOCK_SIZE] = {0};

    const byte pt192[]  = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a };

    const byte ct192[]  = { 0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,
                            0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8 };

    const byte iv192[]  = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };

    byte key192[]       = { 0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
                            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
                            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };

    len = sizeof(pt192);

    /* wolfSSL_AES_cbc_encrypt() 192-bit */
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    RESET_IV(iv192tmp, iv192);

    ExpectIntEQ(wolfSSL_AES_set_encrypt_key(key192, sizeof(key192)*8, &aes), 0);
    wolfSSL_AES_cbc_encrypt(pt192, out, len, &aes, iv192tmp, AES_ENCRYPT);
    ExpectIntEQ(XMEMCMP(out, ct192, AES_BLOCK_SIZE), 0);
    wc_AesFree((Aes*)&aes);

    #ifdef HAVE_AES_DECRYPT

    /* wolfSSL_AES_cbc_encrypt() 192-bit in decrypt mode */
    len = sizeof(ct192);
    RESET_IV(iv192tmp, iv192);
    XMEMSET(out, 0, AES_BLOCK_SIZE);

    ExpectIntEQ(wolfSSL_AES_set_decrypt_key(key192, sizeof(key192)*8, &aes), 0);
    wolfSSL_AES_cbc_encrypt(ct192, out, len, &aes, iv192tmp, AES_DECRYPT);
    ExpectIntEQ(XMEMCMP(out, pt192, AES_BLOCK_SIZE), 0);
    wc_AesFree((Aes*)&aes);

    #endif
  }
  #endif /* WOLFSSL_AES_192 */
  #ifdef WOLFSSL_AES_256
  {
    /* Test vectors from NIST Special Publication 800-38A, 2001 Edition,
     * Appendix F.2.5  */
    byte iv256tmp[AES_BLOCK_SIZE] = {0};

    const byte pt256[]  = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a };

    const byte ct256[]  = { 0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
                            0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6 };

    const byte iv256[]  = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };

    byte key256[]       = { 0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };


    len = sizeof(pt256);

    /* wolfSSL_AES_cbc_encrypt() 256-bit */
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    RESET_IV(iv256tmp, iv256);

    ExpectIntEQ(wolfSSL_AES_set_encrypt_key(key256, sizeof(key256)*8, &aes), 0);
    wolfSSL_AES_cbc_encrypt(pt256, out, len, &aes, iv256tmp, AES_ENCRYPT);
    ExpectIntEQ(XMEMCMP(out, ct256, AES_BLOCK_SIZE), 0);
    wc_AesFree((Aes*)&aes);

    #ifdef HAVE_AES_DECRYPT

    /* wolfSSL_AES_cbc_encrypt() 256-bit in decrypt mode */
    len = sizeof(ct256);
    RESET_IV(iv256tmp, iv256);
    XMEMSET(out, 0, AES_BLOCK_SIZE);

    ExpectIntEQ(wolfSSL_AES_set_decrypt_key(key256, sizeof(key256)*8, &aes), 0);
    wolfSSL_AES_cbc_encrypt(ct256, out, len, &aes, iv256tmp, AES_DECRYPT);
    ExpectIntEQ(XMEMCMP(out, pt256, AES_BLOCK_SIZE), 0);
    wc_AesFree((Aes*)&aes);

    #endif

    #if defined(HAVE_AES_KEYWRAP) && !defined(HAVE_FIPS) && \
        !defined(HAVE_SELFTEST)
    {
    byte wrapCipher[sizeof(key256) + KEYWRAP_BLOCK_SIZE] = { 0 };
    byte wrapPlain[sizeof(key256)] = { 0 };
    byte wrapIV[KEYWRAP_BLOCK_SIZE] = { 0 };

    /* wolfSSL_AES_wrap_key() 256-bit NULL iv */
    ExpectIntEQ(wolfSSL_AES_set_encrypt_key(key256, sizeof(key256)*8, &aes), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, NULL, wrapCipher, key256,
            15), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, NULL, wrapCipher, key256,
            sizeof(key256)), sizeof(wrapCipher));
    wc_AesFree((Aes*)&aes);

    /* wolfSSL_AES_unwrap_key() 256-bit NULL iv */
    ExpectIntEQ(wolfSSL_AES_set_decrypt_key(key256, sizeof(key256)*8, &aes), 0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(&aes, NULL, wrapPlain, wrapCipher,
            23), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_AES_unwrap_key(&aes, NULL, wrapPlain, wrapCipher,
            sizeof(wrapCipher)), sizeof(wrapPlain));
    ExpectIntEQ(XMEMCMP(wrapPlain, key256, sizeof(key256)), 0);
    XMEMSET(wrapCipher, 0, sizeof(wrapCipher));
    XMEMSET(wrapPlain, 0, sizeof(wrapPlain));
    wc_AesFree((Aes*)&aes);

    /* wolfSSL_AES_wrap_key() 256-bit custom iv */
    ExpectIntEQ(wolfSSL_AES_set_encrypt_key(key256, sizeof(key256)*8, &aes), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, wrapIV, wrapCipher, key256,
            sizeof(key256)), sizeof(wrapCipher));
    wc_AesFree((Aes*)&aes);

    /* wolfSSL_AES_unwrap_key() 256-bit custom iv */
    ExpectIntEQ(wolfSSL_AES_set_decrypt_key(key256, sizeof(key256)*8, &aes), 0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(&aes, wrapIV, wrapPlain, wrapCipher,
            sizeof(wrapCipher)), sizeof(wrapPlain));
    ExpectIntEQ(XMEMCMP(wrapPlain, key256, sizeof(key256)), 0);
    wc_AesFree((Aes*)&aes);

    ExpectIntEQ(wolfSSL_AES_wrap_key(NULL, NULL, NULL, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, NULL, NULL, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(NULL, wrapIV, NULL, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(NULL, NULL, wrapCipher, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(NULL, NULL, NULL, key256, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(NULL, wrapIV, wrapCipher, key256, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, NULL, wrapCipher, key256, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, wrapIV, NULL, key256, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, wrapIV, wrapCipher, NULL, 0), 0);

    ExpectIntEQ(wolfSSL_AES_unwrap_key(NULL, NULL, NULL, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(&aes, NULL, NULL, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(NULL, wrapIV, NULL, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(NULL, NULL, wrapPlain, NULL, 0), 0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(NULL, NULL, NULL, wrapCipher, 0), 0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(NULL, wrapIV, wrapPlain, wrapCipher, 0),
        0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(&aes, NULL, wrapPlain, wrapCipher, 0),
        0);
    ExpectIntEQ(wolfSSL_AES_unwrap_key(&aes, wrapIV, NULL, wrapCipher, 0), 0);
    ExpectIntEQ(wolfSSL_AES_wrap_key(&aes, wrapIV, wrapPlain, NULL, 0), 0);
    }
    #endif /* HAVE_AES_KEYWRAP */
  }
  #endif /* WOLFSSL_AES_256 */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_AES_cfb128_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_AES) && defined(WOLFSSL_AES_CFB) && \
        !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    AES_KEY aesEnc;
    AES_KEY aesDec;
    const byte msg[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    const byte exp[] = {
        0x2c, 0x4e, 0xc4, 0x58, 0x4b, 0xf3, 0xb3, 0xad,
        0xd0, 0xe6, 0xf1, 0x80, 0x43, 0x59, 0x54, 0x6b
    };
    const byte key[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81
    };
    const byte ivData[] = {
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    };
    byte out[AES_BLOCK_SIZE];
    byte iv[AES_BLOCK_SIZE];
    word32 i;
    int num;

    ExpectIntEQ(AES_set_encrypt_key(key, sizeof(key)*8, &aesEnc), 0);
    XMEMCPY(iv, ivData, sizeof(iv));
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    AES_cfb128_encrypt(msg, out, sizeof(msg), &aesEnc, iv, NULL, AES_ENCRYPT);
    ExpectIntEQ(XMEMCMP(out, exp, sizeof(msg)), 0);
    ExpectIntNE(XMEMCMP(iv, ivData, sizeof(iv)), 0);

#ifdef HAVE_AES_DECRYPT
    ExpectIntEQ(AES_set_encrypt_key(key, sizeof(key)*8, &aesDec), 0);
    XMEMCPY(iv, ivData, sizeof(iv));
    XMEMSET(out, 0, AES_BLOCK_SIZE);
    AES_cfb128_encrypt(exp, out, sizeof(msg), &aesDec, iv, NULL, AES_DECRYPT);
    ExpectIntEQ(XMEMCMP(out, msg, sizeof(msg)), 0);
    ExpectIntNE(XMEMCMP(iv, ivData, sizeof(iv)), 0);
#endif

    for (i = 0; EXPECT_SUCCESS() && (i <= sizeof(msg)); i++) {
        ExpectIntEQ(AES_set_encrypt_key(key, sizeof(key)*8, &aesEnc), 0);
        XMEMCPY(iv, ivData, sizeof(iv));
        XMEMSET(out, 0, AES_BLOCK_SIZE);
        AES_cfb128_encrypt(msg, out, i, &aesEnc, iv, &num, AES_ENCRYPT);
        ExpectIntEQ(num, i % AES_BLOCK_SIZE);
        ExpectIntEQ(XMEMCMP(out, exp, i), 0);
        if (i == 0) {
            ExpectIntEQ(XMEMCMP(iv, ivData, sizeof(iv)), 0);
        }
        else {
            ExpectIntNE(XMEMCMP(iv, ivData, sizeof(iv)), 0);
        }

    #ifdef HAVE_AES_DECRYPT
        ExpectIntEQ(AES_set_encrypt_key(key, sizeof(key)*8, &aesDec), 0);
        XMEMCPY(iv, ivData, sizeof(iv));
        XMEMSET(out, 0, AES_BLOCK_SIZE);
        AES_cfb128_encrypt(exp, out, i, &aesDec, iv, &num, AES_DECRYPT);
        ExpectIntEQ(num, i % AES_BLOCK_SIZE);
        ExpectIntEQ(XMEMCMP(out, msg, i), 0);
        if (i == 0) {
            ExpectIntEQ(XMEMCMP(iv, ivData, sizeof(iv)), 0);
        }
        else {
            ExpectIntNE(XMEMCMP(iv, ivData, sizeof(iv)), 0);
        }
    #endif
    }

    if (EXPECT_SUCCESS()) {
        /* test bad arguments */
        AES_cfb128_encrypt(NULL, NULL, 0, NULL, NULL, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(msg, NULL, 0, NULL, NULL, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(NULL, out, 0, NULL, NULL, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(NULL, NULL, 0, &aesDec, NULL, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(NULL, NULL, 0, NULL, iv, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(NULL, out, 0, &aesDec, iv, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(msg, NULL, 0, &aesDec, iv, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(msg, out, 0, NULL, iv, NULL, AES_DECRYPT);
        AES_cfb128_encrypt(msg, out, 0, &aesDec, NULL, NULL, AES_DECRYPT);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CRYPTO_cts128(void)
{
    EXPECT_DECLS;
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(OPENSSL_EXTRA) && \
    defined(HAVE_CTS) && !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)
    byte tmp[64]; /* Largest vector size */
    /* Test vectors taken form RFC3962 Appendix B */
    const testVector vects[] = {
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20",
            "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f"
            "\x97",
            17, 17
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20",
            "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5",
            31, 31
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43",
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
            32, 32
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5",
            47, 47
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8",
            48, 48
        },
        {
            "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65"
            "\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"
            "\x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20"
            "\x61\x6e\x64\x20\x77\x6f\x6e\x74\x6f\x6e\x20\x73\x6f\x75\x70\x2e",
            "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
            "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
            "\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"
            "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8",
            64, 64
        }
    };
    byte keyBytes[AES_128_KEY_SIZE] = {
        0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
        0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
    };
    size_t i;
    AES_KEY encKey;
    byte iv[AES_IV_SIZE]; /* All-zero IV for all cases */

    XMEMSET(tmp, 0, sizeof(tmp));

    for (i = 0; i < sizeof(vects)/sizeof(vects[0]); i++) {
        AES_KEY decKey;

        ExpectIntEQ(AES_set_encrypt_key(keyBytes, AES_128_KEY_SIZE * 8,
            &encKey), 0);
        ExpectIntEQ(AES_set_decrypt_key(keyBytes, AES_128_KEY_SIZE * 8,
            &decKey), 0);
        XMEMSET(iv, 0, sizeof(iv));
        ExpectIntEQ(CRYPTO_cts128_encrypt((const unsigned char*)vects[i].input,
            tmp, vects[i].inLen, &encKey, iv, (cbc128_f)AES_cbc_encrypt),
            vects[i].outLen);
        ExpectIntEQ(XMEMCMP(tmp, vects[i].output, vects[i].outLen), 0);
        XMEMSET(iv, 0, sizeof(iv));
        ExpectIntEQ(CRYPTO_cts128_decrypt((const unsigned char*)vects[i].output,
            tmp, vects[i].outLen, &decKey, iv, (cbc128_f)AES_cbc_encrypt),
            vects[i].inLen);
        ExpectIntEQ(XMEMCMP(tmp, vects[i].input, vects[i].inLen), 0);
    }

    ExpectIntEQ(CRYPTO_cts128_encrypt(NULL, NULL, 17, NULL, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(tmp, NULL, 17, NULL, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(NULL, tmp, 17, NULL, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(NULL, NULL, 17, &encKey, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(NULL, NULL, 17, NULL, iv, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(NULL, NULL, 17, NULL, NULL,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(NULL, tmp, 17, &encKey, iv,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(tmp, NULL, 17, &encKey, iv,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(tmp, tmp, 17, NULL, iv,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(tmp, tmp, 17, &encKey, NULL,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_encrypt(tmp, tmp, 17, &encKey, iv, NULL), 0);
    /* Length too small. */
    ExpectIntEQ(CRYPTO_cts128_encrypt(tmp, tmp, 0, &encKey, iv,
        (cbc128_f)AES_cbc_encrypt), 0);

    ExpectIntEQ(CRYPTO_cts128_decrypt(NULL, NULL, 17, NULL, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(tmp, NULL, 17, NULL, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(NULL, tmp, 17, NULL, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(NULL, NULL, 17, &encKey, NULL, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(NULL, NULL, 17, NULL, iv, NULL), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(NULL, NULL, 17, NULL, NULL,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(NULL, tmp, 17, &encKey, iv,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(tmp, NULL, 17, &encKey, iv,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(tmp, tmp, 17, NULL, iv,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(tmp, tmp, 17, &encKey, NULL,
        (cbc128_f)AES_cbc_encrypt), 0);
    ExpectIntEQ(CRYPTO_cts128_decrypt(tmp, tmp, 17, &encKey, iv, NULL), 0);
    /* Length too small. */
    ExpectIntEQ(CRYPTO_cts128_decrypt(tmp, tmp, 0, &encKey, iv,
        (cbc128_f)AES_cbc_encrypt), 0);
#endif /* !NO_AES && HAVE_AES_CBC && OPENSSL_EXTRA && HAVE_CTS */
    return EXPECT_RESULT();
}

int test_wolfSSL_RC4(void)
{
    EXPECT_DECLS;
#if !defined(NO_RC4) && defined(OPENSSL_EXTRA)
    WOLFSSL_RC4_KEY rc4Key;
    unsigned char key[] =  {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    unsigned char data[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    unsigned char enc[sizeof(data)];
    unsigned char dec[sizeof(data)];
    word32 i;
    word32 j;

    wolfSSL_RC4_set_key(NULL, -1, NULL);
    wolfSSL_RC4_set_key(&rc4Key, -1, NULL);
    wolfSSL_RC4_set_key(NULL, 0, NULL);
    wolfSSL_RC4_set_key(NULL, -1, key);
    wolfSSL_RC4_set_key(&rc4Key, 0, NULL);
    wolfSSL_RC4_set_key(&rc4Key, -1, key);
    wolfSSL_RC4_set_key(NULL, 0, key);

    wolfSSL_RC4(NULL, 0, NULL, NULL);
    wolfSSL_RC4(&rc4Key, 0, NULL, NULL);
    wolfSSL_RC4(NULL, 0, data, NULL);
    wolfSSL_RC4(NULL, 0, NULL, enc);
    wolfSSL_RC4(&rc4Key, 0, data, NULL);
    wolfSSL_RC4(&rc4Key, 0, NULL, enc);
    wolfSSL_RC4(NULL, 0, data, enc);

    ExpectIntEQ(1, 1);
    for (i = 0; EXPECT_SUCCESS() && (i <= sizeof(key)); i++) {
        for (j = 0; EXPECT_SUCCESS() && (j <= sizeof(data)); j++) {
            XMEMSET(enc, 0, sizeof(enc));
            XMEMSET(dec, 0, sizeof(dec));

            /* Encrypt */
            wolfSSL_RC4_set_key(&rc4Key, (int)i, key);
            wolfSSL_RC4(&rc4Key, j, data, enc);
            /* Decrypt */
            wolfSSL_RC4_set_key(&rc4Key, (int)i, key);
            wolfSSL_RC4(&rc4Key, j, enc, dec);

            ExpectIntEQ(XMEMCMP(dec, data, j), 0);
        }
    }
#endif
    return EXPECT_RESULT();
}

