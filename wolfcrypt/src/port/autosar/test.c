/* test.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_AUTOSAR

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/autosar/Csm.h>
#define BLOCK_SIZE 16

static int singleshot_test(void)
{
    Std_ReturnType ret;

    uint8 cipher[BLOCK_SIZE * 2];
    uint8 plain[BLOCK_SIZE * 2];

    uint32 cipherSz = 0;
    uint32 plainSz  = 0;
    const uint8 msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const uint8 verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    const uint8 key[] = "0123456789abcdef   ";
    const uint8 iv[]  = "1234567890abcdef   ";

    XMEMSET(cipher, 0, BLOCK_SIZE);
    XMEMSET(plain, 0, BLOCK_SIZE);

    /* set key that will be used for encryption */
    ret = Csm_KeyElementSet(0U, CRYPTO_KE_CIPHER_KEY, key, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(1U, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
        cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    if (XMEMCMP(cipher, verify, BLOCK_SIZE) != 0) {
        printf("Error with cipher data\n");
        return -1;
    }

    /* set key that will be used for decryption */
    ret = Csm_KeyElementSet(0U, CRYPTO_KE_CIPHER_KEY, key, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(1U, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* decrypt data using AES CBC */
    ret = Csm_Decrypt(2U, CRYPTO_OPERATIONMODE_SINGLECALL, cipher, BLOCK_SIZE,
        plain, &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    if (XMEMCMP(msg, plain, BLOCK_SIZE) != 0) {
        printf("Error with plain data\n");
        return -1;
    }

    return 0;
}


static int update_test(void)
{
    Std_ReturnType ret;

    uint8 cipher[BLOCK_SIZE * 3];
    uint8 plain[BLOCK_SIZE * 3];

    uint32 cipherSz = 0;
    uint32 plainSz  = 0;
    const uint8 msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const uint8 key[] = "0123456789abcdef   ";
    const uint8 iv[]  = "1234567890abcdef   ";

    XMEMSET(cipher, 0, BLOCK_SIZE);
    XMEMSET(plain, 0, BLOCK_SIZE);

    /* set key that will be used for encryption */
    ret = Csm_KeyElementSet(0U, CRYPTO_KE_CIPHER_KEY, key, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(1U, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(1U,
            CRYPTO_OPERATIONMODE_START | CRYPTO_OPERATIONMODE_UPDATE,
            msg, BLOCK_SIZE, cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    ret = Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE,
            cipher + BLOCK_SIZE, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    ret = Csm_Encrypt(1U,
            CRYPTO_OPERATIONMODE_UPDATE | CRYPTO_OPERATIONMODE_FINISH,
            msg, BLOCK_SIZE, cipher + (BLOCK_SIZE * 2), &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    /* set key that will be used for decryption */
    ret = Csm_KeyElementSet(0U, CRYPTO_KE_CIPHER_KEY, key, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(1U, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* decrypt data using AES CBC */
    ret = Csm_Decrypt(2U,
            CRYPTO_OPERATIONMODE_START | CRYPTO_OPERATIONMODE_UPDATE,
            cipher, BLOCK_SIZE, plain, &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    ret = Csm_Decrypt(2U, CRYPTO_OPERATIONMODE_UPDATE, cipher + BLOCK_SIZE,
            BLOCK_SIZE, plain + BLOCK_SIZE, &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    ret = Csm_Decrypt(2U,
            CRYPTO_OPERATIONMODE_UPDATE | CRYPTO_OPERATIONMODE_FINISH,
            cipher + (BLOCK_SIZE * 2), BLOCK_SIZE,
            plain + (BLOCK_SIZE * 2), &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    if (XMEMCMP(msg, plain, BLOCK_SIZE) != 0 ||
        XMEMCMP(msg, plain + BLOCK_SIZE, BLOCK_SIZE) != 0 ||
        XMEMCMP(msg, plain + (BLOCK_SIZE * 2), BLOCK_SIZE) != 0) {
        printf("Error with plain data\n");
        return -1;
    }

    return 0;
}


static int random_test(void)
{
    Std_ReturnType ret;

    int i;
    uint8 j;
    uint8 data[BLOCK_SIZE * 3];
    uint32 dataSz;
    XMEMSET(data, 0, BLOCK_SIZE * 3);

    /* make three calls, filling up data buffer */
    for (i = 0; i < 3; i++) {
        dataSz = BLOCK_SIZE;
        ret = Csm_RandomGenerate(0U, data + (i * BLOCK_SIZE), &dataSz);
        if (ret != E_OK) {
            printf("Issue with getting random data block");
            return -1;
        }

        if (dataSz != BLOCK_SIZE) {
            printf("Did not get full block of random data");
            return -1;
        }
    }

    /* simple test that is not all 0's still after random generate */
    j = 0;
    dataSz = sizeof(data);
    for (i = 0; i < (int)dataSz; i++) {
        j |= data[i];
    }
    if (j == 0) {
        printf("call to random generate produced all 0's");
        return -1;
    }

    /* fill full data buffer all at once */
    dataSz = sizeof(data);
    ret = Csm_RandomGenerate(0U, data, &dataSz);
    if (ret != E_OK) {
        printf("Issue with getting random data block");
        return -1;
    }

    if (dataSz != sizeof(data)) {
        printf("Did not get full block of random data");
        return -1;
    }
    return 0;
}


#ifndef MAX_KEYSTORE
    /* default max key slots from crypto.c */
    #define MAX_KEYSTORE 15
#endif
static int key_test(void)
{
    Std_ReturnType ret;

    uint8 i;
    uint8 max = MAX_KEYSTORE;
    uint8 data[BLOCK_SIZE];
    uint32 dataSz;
    XMEMSET(data, 0, BLOCK_SIZE);

    for (i = 0; i < max; i++) {
        dataSz = BLOCK_SIZE;
        ret = Csm_RandomGenerate(0U, data, &dataSz);
        if (ret != E_OK) {
            printf("Issue with getting random data block for key");
            return -1;
        }

        if (dataSz != BLOCK_SIZE) {
            printf("Did not get full block of random data");
            return -1;
        }

        ret = Csm_KeyElementSet(i, CRYPTO_KE_CIPHER_KEY, data, BLOCK_SIZE);
        if (ret != E_OK) {
            printf("Issue with setting key id %d", i);
            return -1;
        }
    }

    /* try creating one more key for fail case */
    ret = Csm_KeyElementSet(i, CRYPTO_KE_CIPHER_KEY, data, BLOCK_SIZE);
    if (ret == E_OK) {
        printf("Created more keys than should be possible");
        return -1;
    }

    return 0;
}

#ifdef REDIRECTION_CONFIG
static int redirect_test()
{
    Std_ReturnType ret;

    uint8 cipher[BLOCK_SIZE * 2];
    uint32 cipherSz = 0;
    const uint8 msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const uint8 verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    const uint8 key[] = "0123456789abcdef   ";  /* align */
    const uint8 iv[]  = "1234567890abcdef   ";  /* align */
    unsigned int i;

    XMEMSET(cipher, 0, BLOCK_SIZE);

    /* fill keystore with bad keys */
    for (i = 0; i < MAX_KEYSTORE; i++) {
        ret = Csm_KeyElementSet(i, CRYPTO_KE_CIPHER_KEY, verify, BLOCK_SIZE);
        if (ret != E_OK) {
            printf("Issue with setting key");
            return -1;
        }
    }

    /* set specific key that will be used for encryption */
    ret = Csm_KeyElementSet(REDIRECTION_IN1_KEYID, REDIRECTION_IN1_KEYELMID,
            key, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(REDIRECTION_IN2_KEYID, REDIRECTION_IN2_KEYELMID,
            iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(0U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
        cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    if (XMEMCMP(cipher, verify, BLOCK_SIZE) != 0) {
        printf("Error with cipher data ");
        return -1;
    }

    /* now set bad key to be used for encryption */
    ret = Csm_KeyElementSet(REDIRECTION_IN1_KEYID, REDIRECTION_IN1_KEYELMID,
            verify, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key ");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(0U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
        cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg ");
        return -1;
    }

    if (XMEMCMP(cipher, verify, BLOCK_SIZE) == 0) {
        printf("Error with cipher data ");
        return -1;
    }

    return 0;
}
#endif /* REDIRECTION_CONFIG */

/* takes in test function test() and name of test
 * returns 1 if test failed and 0 if passed */
static int run_test(int(test)(void), const char* name)
{
    printf("%s", name);
    if (test() != 0) {
        printf("fail\n");
        return 1;
    }
    else {
        printf("pass\n");
    }
    return 0;
}


/* AES block size */
int main(int argc, char* argv[])
{
    int ret = 0;
    (void)argv;
    (void)argc;

    wolfSSL_Debugging_ON();
    Csm_Init(NULL);

    ret |= run_test(singleshot_test, "singleshot_test ... ");
    ret |= run_test(update_test, "update_test ... ");
    ret |= run_test(random_test, "random_test ... ");
    ret |= run_test(key_test, "key_test ... ");
#ifdef REDIRECTION_CONFIG
    ret |= run_test(redirect_test, "redirect_test ... ");
#endif /* REDIRECTION_CONFIG */
    return ret;
}

#endif /* WOLFSSL_AUTOSAR */
