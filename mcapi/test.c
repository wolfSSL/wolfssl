/* test.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/* Tests Microchip CRYPTO API layer */



/* mc api header */
#include "crypto.h"

/* sanity test against our default implementation, cyassl headers  */
#include <cyassl/ctaocrypt/md5.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/sha256.h>
#include <cyassl/ctaocrypt/sha512.h>
#include <cyassl/ctaocrypt/hmac.h>

/* c stdlib headers */
#include <stdio.h>


#define OUR_DATA_SIZE 1024
static byte ourData[OUR_DATA_SIZE];
static byte* key = NULL;

static int check_md5(void);
static int check_sha(void);
static int check_sha256(void);
static int check_sha384(void);
static int check_sha512(void);
static int check_hmac(void);


int main(int argc, char** argv)
{
    int ret;
    int i;

    (void)argc;
    (void)argv;

    /* align key pointer */
    key = (byte*)malloc(128);
    if (key == NULL) {
        printf("mcapi key alloc failed\n");
        return -1;
    }

    for (i = 0; i < OUR_DATA_SIZE; i++)
        ourData[i] = (byte)i;

    ret = check_md5();
    if (ret != 0) {
        printf("mcapi check_md5 failed\n");
        return -1;
    }

    ret = check_sha();
    if (ret != 0) {
        printf("mcapi check_sha failed\n");
        return -1;
    }

    ret = check_sha256();
    if (ret != 0) {
        printf("mcapi check_sha256 failed\n");
        return -1;
    }

    ret = check_sha384();
    if (ret != 0) {
        printf("mcapi check_sha384 failed\n");
        return -1;
    }

    ret = check_sha512();
    if (ret != 0) {
        printf("mcapi check_sha512 failed\n");
        return -1;
    }

    ret = check_hmac();
    if (ret != 0) {
        printf("mcapi check_hmac failed\n");
        return -1;
    }



    return 0;
}


/* check mcapi md5 against internal */
static int check_md5(void)
{
    CRYPT_MD5_CTX mcMd5;
    Md5           defMd5;
    byte          mcDigest[CRYPT_MD5_DIGEST_SIZE];
    byte          defDigest[MD5_DIGEST_SIZE];

    CRYPT_MD5_Initialize(&mcMd5);
    InitMd5(&defMd5);

    CRYPT_MD5_DataAdd(&mcMd5, ourData, OUR_DATA_SIZE);
    Md5Update(&defMd5, ourData, OUR_DATA_SIZE);

    CRYPT_MD5_Finalize(&mcMd5, mcDigest);
    Md5Final(&defMd5, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_MD5_DIGEST_SIZE) != 0) {
        printf("md5 final memcmp fialed\n");
        return -1;
    } 
    printf("md5         mcapi test passed\n");

    return 0;
}


/* check mcapi sha against internal */
static int check_sha(void)
{
    CRYPT_SHA_CTX mcSha;
    Sha           defSha;
    byte          mcDigest[CRYPT_SHA_DIGEST_SIZE];
    byte          defDigest[SHA_DIGEST_SIZE];

    CRYPT_SHA_Initialize(&mcSha);
    InitSha(&defSha);

    CRYPT_SHA_DataAdd(&mcSha, ourData, OUR_DATA_SIZE);
    ShaUpdate(&defSha, ourData, OUR_DATA_SIZE);

    CRYPT_SHA_Finalize(&mcSha, mcDigest);
    ShaFinal(&defSha, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA_DIGEST_SIZE) != 0) {
        printf("sha final memcmp fialed\n");
        return -1;
    } 
    printf("sha         mcapi test passed\n");

    return 0;
}


/* check mcapi sha256 against internal */
static int check_sha256(void)
{
    CRYPT_SHA256_CTX mcSha256;
    Sha256           defSha256;
    byte             mcDigest[CRYPT_SHA256_DIGEST_SIZE];
    byte             defDigest[SHA256_DIGEST_SIZE];

    CRYPT_SHA256_Initialize(&mcSha256);
    InitSha256(&defSha256);

    CRYPT_SHA256_DataAdd(&mcSha256, ourData, OUR_DATA_SIZE);
    Sha256Update(&defSha256, ourData, OUR_DATA_SIZE);

    CRYPT_SHA256_Finalize(&mcSha256, mcDigest);
    Sha256Final(&defSha256, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA256_DIGEST_SIZE) != 0) {
        printf("sha256 final memcmp fialed\n");
        return -1;
    } 
    printf("sha256      mcapi test passed\n");

    return 0;
}


/* check mcapi sha384 against internal */
static int check_sha384(void)
{
    CRYPT_SHA384_CTX mcSha384;
    Sha384           defSha384;
    byte             mcDigest[CRYPT_SHA384_DIGEST_SIZE];
    byte             defDigest[SHA384_DIGEST_SIZE];

    CRYPT_SHA384_Initialize(&mcSha384);
    InitSha384(&defSha384);

    CRYPT_SHA384_DataAdd(&mcSha384, ourData, OUR_DATA_SIZE);
    Sha384Update(&defSha384, ourData, OUR_DATA_SIZE);

    CRYPT_SHA384_Finalize(&mcSha384, mcDigest);
    Sha384Final(&defSha384, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA384_DIGEST_SIZE) != 0) {
        printf("sha384 final memcmp fialed\n");
        return -1;
    } 
    printf("sha384      mcapi test passed\n");

    return 0;
}


/* check mcapi sha512 against internal */
static int check_sha512(void)
{
    CRYPT_SHA512_CTX mcSha512;
    Sha512           defSha512;
    byte             mcDigest[CRYPT_SHA512_DIGEST_SIZE];
    byte             defDigest[SHA512_DIGEST_SIZE];

    CRYPT_SHA512_Initialize(&mcSha512);
    InitSha512(&defSha512);

    CRYPT_SHA512_DataAdd(&mcSha512, ourData, OUR_DATA_SIZE);
    Sha512Update(&defSha512, ourData, OUR_DATA_SIZE);

    CRYPT_SHA512_Finalize(&mcSha512, mcDigest);
    Sha512Final(&defSha512, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA512_DIGEST_SIZE) != 0) {
        printf("sha512 final memcmp fialed\n");
        return -1;
    } 
    printf("sha512      mcapi test passed\n");

    return 0;
}


/* check mcapi hmac against internal */
static int check_hmac(void)
{
    CRYPT_HMAC_CTX mcHmac;
    Hmac           defHmac;
    byte           mcDigest[CRYPT_SHA512_DIGEST_SIZE];
    byte           defDigest[SHA512_DIGEST_SIZE];

    strncpy((char*)key, "Jefe", 4);

    /* SHA1 */
    CRYPT_HMAC_SetKey(&mcHmac, CRYPT_HMAC_SHA, key, 4);
    HmacSetKey(&defHmac, SHA, key, 4);

    CRYPT_HMAC_DataAdd(&mcHmac, ourData, OUR_DATA_SIZE);
    HmacUpdate(&defHmac, ourData, OUR_DATA_SIZE);

    CRYPT_HMAC_Finalize(&mcHmac, mcDigest);
    HmacFinal(&defHmac, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA_DIGEST_SIZE) != 0) {
        printf("hmac sha final memcmp fialed\n");
        return -1;
    } 
    printf("hmac sha    mcapi test passed\n");

    /* SHA-256 */
    CRYPT_HMAC_SetKey(&mcHmac, CRYPT_HMAC_SHA256, key, 4);
    HmacSetKey(&defHmac, SHA256, key, 4);

    CRYPT_HMAC_DataAdd(&mcHmac, ourData, OUR_DATA_SIZE);
    HmacUpdate(&defHmac, ourData, OUR_DATA_SIZE);

    CRYPT_HMAC_Finalize(&mcHmac, mcDigest);
    HmacFinal(&defHmac, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA256_DIGEST_SIZE) != 0) {
        printf("hmac sha256 final memcmp fialed\n");
        return -1;
    } 
    printf("hmac sha256 mcapi test passed\n");

    /* SHA-384 */
    CRYPT_HMAC_SetKey(&mcHmac, CRYPT_HMAC_SHA384, key, 4);
    HmacSetKey(&defHmac, SHA384, key, 4);

    CRYPT_HMAC_DataAdd(&mcHmac, ourData, OUR_DATA_SIZE);
    HmacUpdate(&defHmac, ourData, OUR_DATA_SIZE);

    CRYPT_HMAC_Finalize(&mcHmac, mcDigest);
    HmacFinal(&defHmac, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA384_DIGEST_SIZE) != 0) {
        printf("hmac sha384 final memcmp fialed\n");
        return -1;
    } 
    printf("hmac sha384 mcapi test passed\n");

    /* SHA-512 */
    CRYPT_HMAC_SetKey(&mcHmac, CRYPT_HMAC_SHA512, key, 4);
    HmacSetKey(&defHmac, SHA512, key, 4);

    CRYPT_HMAC_DataAdd(&mcHmac, ourData, OUR_DATA_SIZE);
    HmacUpdate(&defHmac, ourData, OUR_DATA_SIZE);

    CRYPT_HMAC_Finalize(&mcHmac, mcDigest);
    HmacFinal(&defHmac, defDigest);

    if (memcmp(mcDigest, defDigest, CRYPT_SHA512_DIGEST_SIZE) != 0) {
        printf("hmac sha512 final memcmp fialed\n");
        return -1;
    } 
    printf("hmac sha512 mcapi test passed\n");

    return 0;
}


