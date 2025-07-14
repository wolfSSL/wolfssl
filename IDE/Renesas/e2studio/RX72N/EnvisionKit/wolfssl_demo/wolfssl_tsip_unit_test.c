/* wolfssl_tsip_unit_test.c
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

#include <wolfssl_simple_demo.h>

#ifdef TSIP_CRYPT_UNIT_TEST

#include "r_bsp_config.h"
#if BSP_CFG_USTACK_BYTES < 0x4000
#    error "more than 0x4000 stack needed to run the unit tests."
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#include <wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h>
WOLFSSL_API int wc_CryptoCb_CryptInitRenesasCmn(struct WOLFSSL* ssl, void* ctx);

#ifdef FREERTOS
#include "FreeRTOS.h"
# if defined(FREERTOS_TCP)
    #include "FreeRTOS_IP.h"
    #include "FreeRTOS_Sockets.h"
    #include "platform/iot_network.h"
    #include "platform.h"
# endif
#endif

#ifndef NO_SHA
 int sha_test(void);
#endif

#ifndef NO_SHA256
 int sha256_test(void);
#endif

#define SMALL_STACK_SIZE (1 * 1024)
#define STACK_SIZE       (4 * 1024)

#define RESULT_STR(ret)  if (ret == 0)\
                          printf(" passed \n");\
                         else \
                          printf(" failed \n");
#ifdef FREERTOS
    static xSemaphoreHandle exit_semaph;
    static byte exit_loop = 0;
    static byte sha_multTst_rslt = 0;
    static byte sha256_multTst_rslt = 0;
    static byte Aes128_Cbc_multTst_rslt = 0;
    static byte Aes256_Cbc_multTst_rslt = 0;
    static byte Aes128_Gcm_multTst_rslt = 0;
    static byte Aes256_Gcm_multTst_rslt = 0;
#endif /* FREERTOS */

#if defined(HAVE_AES_CBC)

 #if defined(WOLFSSL_AES_128)
  static tsip_aes_key_index_t g_user_aes128_key_index1;
  static tsip_aes_key_index_t g_user_aes128_key_index2;
 #endif

 #if defined(WOLFSSL_AES_256)
  static tsip_aes_key_index_t g_user_aes256_key_index1;
  static tsip_aes_key_index_t g_user_aes256_key_index2;
 #endif

#endif



typedef struct tagInfo
{
    tsip_aes_key_index_t aes_key;
} Info;

#ifdef WOLFSSL_RENESAS_TSIP_CRYPTONLY
 static TsipUserCtx userContext;

 void Clr_CallbackCtx(TsipUserCtx *g)
 {
    #ifndef NO_RSA
     #if defined(TSIP_RSAES_1024) && TSIP_RSAES_1024 == 1
        XFREE(g->rsa1024pri_keyIdx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(g->rsa1024pub_keyIdx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
     #endif
     #if defined(TSIP_RSAES_2048) && TSIP_RSAES_2048 == 1
        XFREE(g->rsa2048pri_keyIdx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(g->rsa2048pub_keyIdx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
     #endif
    #endif
    XMEMSET(g, 0, sizeof(TsipUserCtx));
 }

 int TSIP_AesKeyGeneration(TsipUserCtx *g, byte sz)
 {
	e_tsip_err_t tsip_error_code;
    /* Generate AES tsip Key */
    if (sz == 16) {
        tsip_error_code = R_TSIP_GenerateAes128RandomKeyIndex(
                &g_user_aes128_key_index1);
        if (tsip_error_code == TSIP_SUCCESS) {
            XMEMCPY(&g->user_aes128_key_index, &g_user_aes128_key_index1,
                    sizeof(g_user_aes128_key_index1));
            g->user_aes128_key_set = 1;
        } else {
            printf("Failed to generate Aes 256 Key Index %d\n",
                                                        tsip_error_code);
            return -1;
        }

        tsip_error_code = R_TSIP_GenerateAes128RandomKeyIndex(
                        &g_user_aes128_key_index2);
        if (tsip_error_code != TSIP_SUCCESS) {
            printf("Failed to generate Aes 128 Key Index %d\n",
                                                        tsip_error_code);
            return -1;
        }
    } else if (sz == 32) {
        tsip_error_code = R_TSIP_GenerateAes256RandomKeyIndex(
                    &g_user_aes256_key_index1);
        if (tsip_error_code == TSIP_SUCCESS) {
            XMEMCPY(&g->user_aes256_key_index, &g_user_aes256_key_index1,
                    sizeof(g_user_aes256_key_index1));
            g->user_aes256_key_set = 1;
        } else {
            printf("Failed to generate Aes 256 Key Index %d\n",
                                                        tsip_error_code);
            return -1;
        }

        tsip_error_code = R_TSIP_GenerateAes256RandomKeyIndex(
                    &g_user_aes256_key_index2);
        if (tsip_error_code != TSIP_SUCCESS) {
            printf("Failed to generate Aes 256 Key Index %d\n",
                                                        tsip_error_code);
            return -1;
        }
    } else
        return -1;

    return 0;
 }
#endif

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
static int tsip_aes128_cbc_test(int prnt, int devId)
{
    Aes  aes[1];

    byte cipher[WC_AES_BLOCK_SIZE];
    byte plain[WC_AES_BLOCK_SIZE];
    int  ret = 0;

    WOLFSSL_SMALL_STACK_STATIC const byte msg[] = {
        /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    byte key[] = "0123456789abcdef   ";  /* align */
    byte iv[]  = "1234567890abcdef   ";  /* align */

    ForceZero(cipher, WC_AES_BLOCK_SIZE);
    ForceZero(plain, WC_AES_BLOCK_SIZE);

    if (prnt) {
        printf(" tsip_aes128_cbc_test() ");
    }

    ret = wc_AesInit(aes, NULL, devId);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, WC_AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        aes->ctx.keySize = aes->keylen;
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes, cipher, msg, WC_AES_BLOCK_SIZE);
        }

        wc_AesFree(aes);
    }

    if (ret != 0)
        ret = -1;

#ifdef HAVE_AES_DECRYPT
    if (ret == 0)
        ret = wc_AesInit(aes, NULL, devId);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, WC_AES_BLOCK_SIZE, iv, AES_DECRYPTION);
        if (ret == 0)
            ret = wc_AesCbcDecrypt(aes, plain, cipher, WC_AES_BLOCK_SIZE);

        wc_AesFree(aes);
    }
    if (ret != 0)
        ret = -2;
    if (XMEMCMP(plain, msg, WC_AES_BLOCK_SIZE) != 0)
        ret = -3;
#endif /* HAVE_AES_DECRYPT */

    (void)plain;

    if (prnt) {
        RESULT_STR(ret)
    }

    return ret;
}

#if defined(WOLFSSL_AES_COUNTER)
#if (defined(TSIP_AES_128_CTR) && TSIP_AES_128_CTR == 1) &&\
    (defined(WOLFSSL_AES_128))
static int tsip_aes128_ctr_test(int prnt, int devId)
{
    int ret;
    Aes *enc = NULL;
    Aes *dec = NULL;
    byte cipher[WC_AES_BLOCK_SIZE * 4];
    byte plain [WC_AES_BLOCK_SIZE * 4];
    /* test vectors from "Recommendation for Block Cipher Modes of
     * Operation" NIST Special Publication 800-38A */

    WOLFSSL_SMALL_STACK_STATIC const byte ctrIv[] =
    {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };

    WOLFSSL_SMALL_STACK_STATIC const byte ctrPlain[] =
    {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
        0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
        0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctrIvWrap128[] =
    {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctr128Key[] =
    {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    WOLFSSL_SMALL_STACK_STATIC const byte ctr128Cipher[] =
    {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
        0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
        0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
        0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
        0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctr128Wrap128CipherLong[] =
    {
        0xe1,0x33,0x38,0xe3,0x6c,0xb7,0x19,0x62,
        0xe0,0x0d,0x02,0x0b,0x4c,0xed,0xbd,0x86,
        0xd3,0xda,0xe1,0x5b,0x04,0xbb,0x35,0x2f,
        0xa0,0xf5,0x9f,0xeb,0xfc,0xb4,0xda,0x3e
    };
    WOLFSSL_SMALL_STACK_STATIC const byte oddCipher[] =
    {
        0xb9,0xd7,0xcb,0x08,0xb0,0xe1,0x7b,0xa0,
        0xc2
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctr128Wrap128Cipher[] =
    {
        0xe1,0x33,0x38,0xe3,0x6c,0xb7,0x19,0x62,
        0xe0,0x0d,0x02,0x0b,0x4c,0xed,0xbd,0x86,
        0xd3,0xda,0xe1,0x5b,0x04
    };

    int i;
    struct {
        const byte* key;
        int         keySz;
        const byte* iv;
        const byte* plain;
        int         len;
        const byte* cipher;
    } testVec[] = {
        { ctr128Key, (int)sizeof(ctr128Key), ctrIv,
          ctrPlain, (int)sizeof(ctrPlain), ctr128Cipher },
        /* let's try with just 9 bytes, non block size test */
        { ctr128Key, (int)sizeof(ctr128Key), ctrIv,
          ctrPlain, (int)sizeof(oddCipher), ctr128Cipher },
        /* and an additional 9 bytes to reuse tmp left buffer */
        { NULL, 0, NULL, ctrPlain, (int)sizeof(oddCipher), oddCipher },
        /* Counter wrapping */
        { ctr128Key, (int)sizeof(ctr128Key), ctrIvWrap128,
          ctrPlain, (int)sizeof(ctr128Wrap128Cipher), ctr128Wrap128Cipher },
        { ctr128Key, (int)sizeof(ctr128Key), ctrIvWrap128,
          ctrPlain, (int)sizeof(ctr128Wrap128CipherLong),
          ctr128Wrap128CipherLong },
    };
    int AES_CTR_TEST_LEN = (int)(sizeof(testVec) / sizeof(*testVec));

    if (prnt)
        printf(" tsip_aes128_ctr_test() ");

    enc = wc_AesNew(NULL, devId, &ret);
    if (enc == NULL){
        ret = -1;
        goto out;
    }
    dec = wc_AesNew(NULL, devId, &ret);
    if (dec == NULL){
        ret = -2;
        goto out;
    }

    for (i = 0; i < AES_CTR_TEST_LEN; i++) {
        if (testVec[i].key != NULL) {
            ret = wc_AesSetKeyDirect(enc, testVec[i].key, (word32)testVec[i].keySz,
                testVec[i].iv, AES_ENCRYPTION);

            if (ret != 0) {
                ret = -3;
                goto out;
            }
            /* Ctr only uses encrypt, even on key setup */
            ret = wc_AesSetKeyDirect(dec, testVec[i].key, (word32)testVec[i].keySz,
                testVec[i].iv, AES_ENCRYPTION);
            if (ret != 0) {
                ret = -4;
                goto out;
            }
        }

        ret = wc_AesCtrEncrypt(enc, cipher, testVec[i].plain, (word32)testVec[i].len);
        if (ret != 0) {
            ret = -5;
            goto out;
        }
        ret = wc_AesCtrEncrypt(dec, plain, cipher, (word32)testVec[i].len);
        if (ret != 0) {
            ret = -6;
            goto out;
        }

        if (XMEMCMP(plain, ctrPlain, (size_t)testVec[i].len)) {
            ret = -7;
            goto out;
        }
    }
out:
    wc_AesDelete(enc, &enc);
    wc_AesDelete(dec, &dec);

    return ret;
}
#endif /* WOLFSSL_AES_128 */
#if (defined(TSIP_AES_256_CTR) && TSIP_AES_256_CTR == 1) &&\
    (defined(WOLFSSL_AES_256))
static int tsip_aes256_ctr_test(int prnt, int devId)
{
    int ret;
    Aes *enc = NULL;
    Aes *dec = NULL;
    byte cipher[WC_AES_BLOCK_SIZE * 4];
    byte plain [WC_AES_BLOCK_SIZE * 4];
    /* test vectors from "Recommendation for Block Cipher Modes of
     * Operation" NIST Special Publication 800-38A */

    WOLFSSL_SMALL_STACK_STATIC const byte ctrIv[] =
    {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };

    WOLFSSL_SMALL_STACK_STATIC const byte ctrPlain[] =
    {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
        0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
        0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctrIvWrap128[] =
    {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctr256Key[] =
    {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    WOLFSSL_SMALL_STACK_STATIC const byte ctr256Cipher[] =
    {
        0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
        0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
        0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,
        0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
        0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,
        0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
        0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,
        0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctr256Wrap128CipherLong[] =
    {
        0x50,0xfd,0x97,0xc3,0xe6,0x1a,0xbb,0x48,
        0x73,0xfb,0x78,0xdf,0x1e,0x8e,0x77,0xe6,
        0x4b,0x45,0x7c,0xd6,0x8a,0xcc,0xda,0x4a,
        0x89,0xfa,0x23,0x6c,0x06,0xbf,0x26,0x05
    };
    WOLFSSL_SMALL_STACK_STATIC const byte oddCipher[] =
    {
        0xb9,0xd7,0xcb,0x08,0xb0,0xe1,0x7b,0xa0,
        0xc2
    };
    WOLFSSL_SMALL_STACK_STATIC const byte ctr256Wrap128Cipher[] =
    {
        0x50,0xfd,0x97,0xc3,0xe6,0x1a,0xbb,0x48,
        0x73,0xfb,0x78,0xdf,0x1e,0x8e,0x77,0xe6,
        0x4b,0x45,0x7c,0xd6,0x8a
    };
    int i;
    struct {
        const byte* key;
        int         keySz;
        const byte* iv;
        const byte* plain;
        int         len;
        const byte* cipher;
    } testVec[] = {
        { ctr256Key, (int)sizeof(ctr256Key), ctrIv,
          ctrPlain, (int)sizeof(ctrPlain), ctr256Cipher },
        /* let's try with just 9 bytes, non block size test */
        { ctr256Key, (int)sizeof(ctr256Key), ctrIv,
          ctrPlain, (int)sizeof(oddCipher), ctr256Cipher },
        /* Counter wrapping */
        { ctr256Key, (int)sizeof(ctr256Key), ctrIvWrap128,
          ctrPlain, (int)sizeof(ctr256Wrap128Cipher), ctr256Wrap128Cipher },
        { ctr256Key, (int)sizeof(ctr256Key), ctrIvWrap128,
          ctrPlain, (int)sizeof(ctr256Wrap128CipherLong),
          ctr256Wrap128CipherLong },
    };
    int AES_CTR_TEST_LEN = (int)(sizeof(testVec) / sizeof(*testVec));

    if (prnt)
        printf(" tsip_aes256_ctr_test() ");

    enc = wc_AesNew(NULL, devId, &ret);
    if (enc == NULL){
        ret = -1;
        goto out;
    }
    dec = wc_AesNew(NULL, devId, &ret);
    if (dec == NULL){
        ret = -2;
        goto out;
    }

    for (i = 0; i < AES_CTR_TEST_LEN; i++) {
        if (testVec[i].key != NULL) {
            ret = wc_AesSetKeyDirect(enc, testVec[i].key, (word32)testVec[i].keySz,
                testVec[i].iv, AES_ENCRYPTION);
            if (ret != 0) {
                ret = -3;
                goto out;
            }
            /* Ctr only uses encrypt, even on key setup */
            ret = wc_AesSetKeyDirect(dec, testVec[i].key, (word32)testVec[i].keySz,
                testVec[i].iv, AES_ENCRYPTION);
            if (ret != 0) {
                ret = -4;
                goto out;
            }
        }

        ret = wc_AesCtrEncrypt(enc, cipher, testVec[i].plain, (word32)testVec[i].len);
        if (ret != 0) {
            ret = -5;
            goto out;
        }
        ret = wc_AesCtrEncrypt(dec, plain, cipher, (word32)testVec[i].len);
        if (ret != 0) {
            ret = -6;
            goto out;
        }

        if (XMEMCMP(plain, ctrPlain, (size_t)testVec[i].len)) {
            ret = -7;
            goto out;
        }
    }
out:
    wc_AesDelete(enc, &enc);
    wc_AesDelete(dec, &dec);

    return ret;
}
#endif /* WOLFSSL_AES_256 */
#endif /* TSIP_AES_256_CTR && WOLFSSL_AES_COUNTER */

#ifdef FREERTOS
static void tskAes128_Cbc_Test(void *pvParam)
{
    int ret = 0;
    Info *p = (Info*)pvParam;

    while (exit_loop == false) {
        ret = tsip_aes_cbc_test(0, &p->aes_key);
        vTaskDelay(10/portTICK_PERIOD_MS);
        if (ret != 0) {
            printf(" result was not good(%d). tsip_aes_cbc_test\n", ret);
            Aes128_Cbc_multTst_rslt = 1;
        }
    }

    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif /* FREERTOS */
#endif

#ifdef WOLFSSL_AES_256
static int tsip_aes256_cbc_test(int prnt, int devId)
{
    Aes enc[1];
    byte cipher[WC_AES_BLOCK_SIZE];
    byte plain[WC_AES_BLOCK_SIZE];
    Aes dec[1];
    int  ret = 0;

    /* Test vectors from NIST Special Publication 800-38A, 2001 Edition,
     * Appendix F.2.5  */
    WOLFSSL_SMALL_STACK_STATIC const byte msg[] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    WOLFSSL_SMALL_STACK_STATIC const byte verify[] =
    {
        0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
        0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
    };

    WOLFSSL_SMALL_STACK_STATIC byte key[] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    WOLFSSL_SMALL_STACK_STATIC byte iv[]  = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    (void)verify;

    if (prnt)
        printf(" tsip_aes256_cbc_test() ");

    if (wc_AesInit(enc, NULL, devId) != 0) {
        ret = -1;
        goto out;
    }

    if (wc_AesInit(dec, NULL, devId) != 0){
        ret = -2;
        goto out;
    }

    ret = wc_AesSetKey(enc, key, (int) sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0){
        ret = -3;
        goto out;
    }

    ret = wc_AesSetKey(dec, key, (int) sizeof(key), iv, AES_DECRYPTION);
    if (ret != 0) {
        ret = -4;
        goto out;
    }

    ForceZero(cipher, WC_AES_BLOCK_SIZE);
    ret = wc_AesCbcEncrypt(enc, cipher, msg, (int) sizeof(msg));

    if (ret != 0) {
        ret = -5;
        goto out;
    }

    ForceZero(plain, WC_AES_BLOCK_SIZE);
    ret = wc_AesCbcDecrypt(dec, plain, cipher, (int) sizeof(cipher));

    if (ret != 0){
        ret = -6;
        goto out;
    }
    if (XMEMCMP(plain, msg, (int) sizeof(plain))) {
        ret = -7;
        goto out;
    }

out:
    wc_AesFree(enc);
    wc_AesFree(dec);

    if (prnt) {
        RESULT_STR(ret)
    }

    return ret;
}
#ifdef FREERTOS
static void tskAes256_Cbc_Test(void *pvParam)
{
    int ret = 0;
    Info *p = (Info*)pvParam;

    while (exit_loop == false) {
        ret = tsip_aes256_test(0, &p->aes_key);
        vTaskDelay(10/portTICK_PERIOD_MS);
        if (ret != 0) {
            printf(" result was not good(%d). tsip_aes256_test\n", ret);
            Aes256_Cbc_multTst_rslt = 1;
        }
    }

    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif /* FREERTOS */
#endif /* WOLFSSL_AES_256 */

#if defined(WOLFSSL_AES_256)
static int tsip_aesgcm256_test(int prnt, int devId)
{
    Aes enc[1];
    Aes dec[1];

    /*
     * This is Test Case 16 from the document Galois/
     * Counter Mode of Operation (GCM) by McGrew and
     * Viega.
     */
    WOLFSSL_SMALL_STACK_STATIC const byte p[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };

    WOLFSSL_SMALL_STACK_STATIC const byte a[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    WOLFSSL_SMALL_STACK_STATIC const byte k1[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    WOLFSSL_SMALL_STACK_STATIC const byte iv1[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };

    WOLFSSL_SMALL_STACK_STATIC const byte c1[] =
    {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
    };

    WOLFSSL_SMALL_STACK_STATIC const byte t1[] =
    {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
    };

    byte resultT[sizeof(t1)];
    byte resultP[sizeof(p) + WC_AES_BLOCK_SIZE];
    byte resultC[sizeof(p) + WC_AES_BLOCK_SIZE];
    int  result = 0;
    int  ret;

    (void) result;
    (void) c1;
    (void) t1;

    if (prnt) {
        printf(" tsip_aes256_gcm_test() ");
    }

    XMEMSET(resultT, 0, sizeof(resultT));
    XMEMSET(resultC, 0, sizeof(resultC));
    XMEMSET(resultP, 0, sizeof(resultP));

    if (wc_AesInit(enc, NULL, devId) != 0) {
        ret = -1;
        goto out;
    }
    if (wc_AesInit(dec, NULL, devId) != 0) {
        ret = -2;
        goto out;
    }

    result = wc_AesGcmSetKey(enc, k1, sizeof(k1));
    if (result != 0) {
        ret = -3;
        goto out;
    }

    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(enc,
        resultC, p, sizeof(p),
        (byte*)iv1, sizeof(iv1), resultT, sizeof(resultT),
        a, sizeof(a));
    if (result != 0) {
        ret = -4;
        goto out;
    }

    result = wc_AesGcmSetKey(dec, k1, sizeof(k1));
    if (result != 0) {
        ret = -7;
        goto out;
    } else {
        dec->ctx.keySize = enc->keylen;
    }

    result = wc_AesGcmDecrypt(dec,
        resultP, resultC, sizeof(c1),
        iv1, sizeof(iv1), resultT, sizeof(resultT),
        a, sizeof(a));
    if (result != 0){
        ret = -8;
        goto out;
    }
    if (XMEMCMP(p, resultP, sizeof(p))) {
        ret = -9;
        goto out;
    }

    ForceZero(resultT, sizeof(resultT));
    ForceZero(resultC, sizeof(resultC));
    ForceZero(resultP, sizeof(resultP));

    wc_AesGcmSetKey(enc, k1, sizeof(k1));
    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(enc,
        resultC, p, sizeof(p), iv1, sizeof(iv1),
        resultT + 1, sizeof(resultT) - 1,
        a, sizeof(a));
    if (result != 0) {
        ret = -10;
        goto out;
    }

    result = wc_AesGcmDecrypt(enc,
        resultP, resultC, sizeof(p),
        iv1, sizeof(iv1), resultT + 1, sizeof(resultT) - 1,
        a, sizeof(a));
    if (result != 0) {
        ret = -11;
        goto out;
    }
    if (XMEMCMP(p, resultP, sizeof(p))) {
        ret = -12;
        goto out;
    }

    ret = 0;

  out:
    wc_AesFree(enc);
    wc_AesFree(dec);

    if (prnt) {
        RESULT_STR(ret)
    }

    return ret;
}
#ifdef FREERTOS
static void tskAes256_Gcm_Test(void *pvParam)
{
    int ret = 0;
    Info *p = (Info*)pvParam;

    while (exit_loop == false) {
        ret = tsip_aesgcm256_test(0, &p->aes_key);
        vTaskDelay(10/portTICK_PERIOD_MS);
        if (ret != 0) {
            printf(" result was not good(%d). tsip_aesgcm256_test\n", ret);
            Aes256_Gcm_multTst_rslt = 1;
        }
    }

    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif /* FREERTOS */
#endif

#if defined(WOLFSSL_AES_128) && defined(HAVE_AESGCM)

static int tsip_aesgcm128_test(int prnt, int devId)
{
    Aes enc[1];
    Aes dec[1];

    /* The following is an interesting test case from the example
     * FIPS test vectors for AES-GCM. IVlen = 1 byte */
    WOLFSSL_SMALL_STACK_STATIC const byte p3[] =
    {
        0x57, 0xce, 0x45, 0x1f, 0xa5, 0xe2, 0x35, 0xa5,
        0x8e, 0x1a, 0xa2, 0x3b, 0x77, 0xcb, 0xaf, 0xe2
    };

    WOLFSSL_SMALL_STACK_STATIC const byte k3[] =
    {
        0xbb, 0x01, 0xd7, 0x03, 0x81, 0x1c, 0x10, 0x1a,
        0x35, 0xe0, 0xff, 0xd2, 0x91, 0xba, 0xf2, 0x4b
    };

    WOLFSSL_SMALL_STACK_STATIC const byte iv3[] =
    {
        0xca
    };

    WOLFSSL_SMALL_STACK_STATIC const byte c3[] =
    {
        0x6b, 0x5f, 0xb3, 0x9d, 0xc1, 0xc5, 0x7a, 0x4f,
        0xf3, 0x51, 0x4d, 0xc2, 0xd5, 0xf0, 0xd0, 0x07
    };

    WOLFSSL_SMALL_STACK_STATIC const byte a3[] =
    {
        0x40, 0xfc, 0xdc, 0xd7, 0x4a, 0xd7, 0x8b, 0xf1,
        0x3e, 0x7c, 0x60, 0x55, 0x50, 0x51, 0xdd, 0x54
    };

    WOLFSSL_SMALL_STACK_STATIC const byte t3[] =
    {
        0x06, 0x90, 0xed, 0x01, 0x34, 0xdd, 0xc6, 0x95,
        0x31, 0x2e, 0x2a, 0xf9, 0x57, 0x7a, 0x1e, 0xa6
    };

    byte resultT[sizeof(t3)];
    byte resultP[sizeof(p3) + WC_AES_BLOCK_SIZE];
    byte resultC[sizeof(p3) + WC_AES_BLOCK_SIZE];
    int  result = 0;
    int ret;

    (void) result;
    (void) c3;
    (void) t3;
    if (prnt) {
        printf(" tsip_aes128_gcm_test() ");
    }

    XMEMSET(resultT, 0, sizeof(resultT));
    XMEMSET(resultC, 0, sizeof(resultC));
    XMEMSET(resultP, 0, sizeof(resultP));

    if (wc_AesInit(enc, NULL, devId) != 0) {
        ret = -1;
        goto out;
    }

    if (wc_AesInit(dec, NULL, devId) != 0) {
        ret = -2;
        goto out;
    }

    wc_AesGcmSetKey(enc, k3, sizeof(k3));
    if (result != 0) {
        ret = -3;
        goto out;
    }
    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(enc,resultC, p3, sizeof(p3), iv3, sizeof(iv3),
            resultT, sizeof(t3),a3, sizeof(a3));
    if (result != 0) {
        ret = -4;
        goto out;
    }

    result = wc_AesGcmDecrypt(enc, resultP, resultC, sizeof(c3),
        iv3, sizeof(iv3), resultT, sizeof(resultT), a3, sizeof(a3));
    if (result != 0) {
        ret = -5;
        goto out;
    }

    if (XMEMCMP(p3, resultP, sizeof(p3))) {
        ret = -6;
        goto out;
    }

    ret = 0;

  out:
    wc_AesFree(enc);
    wc_AesFree(dec);

    if (prnt) {
        RESULT_STR(ret)
    }

    return ret;
}
#ifdef FREERTOS
static void tskAes128_Gcm_Test(void *pvParam)
{
    int ret = 0;
    Info *p = (Info*)pvParam;

    while (exit_loop == false) {
        ret = tsip_aesgcm128_test(0, &p->aes_key);
        vTaskDelay(10/portTICK_PERIOD_MS);
        if (ret != 0) {
            printf(" result was not good(%d). tsip_aesgcm128_test\n", ret);
            Aes128_Gcm_multTst_rslt = 1;
        }
    }

    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif /* FREERTOS */
#endif


#ifdef FREERTOS

#ifndef NO_SHA

static void tskSha_Test(void *pvParam)
{
    int ret = 0;

    while (exit_loop == false) {
        ret = sha_test();
        vTaskDelay(10/portTICK_PERIOD_MS);
        if (ret != 0) {
            printf(" result was not good(%d). sha_test\n", ret);
            sha_multTst_rslt = 1;
        }
    }

    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif

#ifndef NO_SHA256
static void tskSha256_Test(void *pvParam)
{
    int ret = 0;

    while (exit_loop == false) {
        ret = sha256_test();
        vTaskDelay(10/portTICK_PERIOD_MS);
        if (ret != 0) {
            printf(" result was not good(%d). sha256_test\n", ret);
            sha256_multTst_rslt = 1;
        }
    }

    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif
#endif /* FREERTOS */

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)

/* testing rsa sign/verify w/ rsa 2048 bit key */
#define TEST_STRING     "Everyone gets Friday off."
#define TEST_STRING2    "Everyone gets Friday ofv."
#define TEST_STRING_SZ   25
#define RSA_TEST_BYTES   256 /* up to 2048-bit key */

static int tsip_rsa_test(int prnt, int keySize)
{
    int ret = 0;

    RsaKey *key = NULL;
    WC_RNG rng;
    const char inStr [] = TEST_STRING;
    const word32 inLen = (word32)TEST_STRING_SZ;
    const word32 outSz = RSA_TEST_BYTES;
    word32 out_actual_len = 0;
    byte *in = NULL;
    byte *out= NULL;
    byte *outplain = NULL;
    int initRsa = 0;
    int devId = 7890; /* fixed devid for TSIP/SCE */

    XMEMSET(&rng, 0, sizeof(rng));

    key = (RsaKey *)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    in = (byte*)XMALLOC(inLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte*)XMALLOC(outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    outplain = (byte*)XMALLOC(outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (key == NULL || in == NULL || out == NULL || outplain == NULL) {
        ret = -1;
        goto out;
    }

    XMEMSET(key, 0, sizeof(*key));
    XMEMCPY(in, inStr, inLen);
    XMEMSET(out,  0, outSz);
    XMEMSET(outplain, 0, outSz);

    ret = wc_InitRsaKey_ex(key, NULL, devId);
    if (ret != 0) {
        goto out;
    }
    initRsa = 1;

    if ((ret = wc_InitRng(&rng)) != 0)
        goto out;

    if ((ret = wc_RsaSetRNG(key, &rng)) != 0)
        goto out;

    /* Generate a new RSA key to use with TSIP/SCE */
    if ((ret = wc_MakeRsaKey(key, keySize, 65537, &rng)) != 0) {
        goto out;
    }

    ret = wc_RsaPublicEncrypt(in, inLen, out, outSz, key, &rng);
    if (ret < 0) {
        goto out;
    }

    ret = wc_RsaPrivateDecrypt(out, (word32)(keySize/8), outplain, outSz, key);
    if (ret < 0) {
        ret = -1;
        goto out;
    }

    if (XMEMCMP(in, outplain, inLen) != 0) {
        ret = -2;
        goto out;
    }

    ret = 0;
out:

    wc_FreeRng(&rng);
    if (key != NULL) {
        if (initRsa)
            wc_FreeRsaKey(key);
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(in, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outplain, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    (void)prnt;
    return ret;
}


static int tsip_rsa_SignVerify_test(int prnt, int keySize)
{
    int ret = 0;

    RsaKey *key = NULL;
    WC_RNG rng;
    const char inStr [] = TEST_STRING;
    const char inStr2[] = TEST_STRING2;
    const word32 inLen = (word32)TEST_STRING_SZ;
    const word32 outSz = RSA_TEST_BYTES;
    word32 signSz = 0;
    byte *in = NULL;
    byte *in2 = NULL;
    byte *out= NULL;
    int initRsa = 0;
    int devId = 7890; /* fixed devid for TSIP/SCE */

    XMEMSET(&rng, 0, sizeof(rng));

    key = (RsaKey *)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    in = (byte*)XMALLOC(inLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    in2 = (byte*)XMALLOC(inLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte*)XMALLOC(outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (key == NULL || in == NULL || out == NULL) {
        ret = -1;
        goto out;
    }

    XMEMSET(key, 0, sizeof(*key));
    XMEMCPY(in, inStr, inLen);
    XMEMCPY(in2, inStr2, inLen);

    ret = wc_InitRsaKey_ex(key, NULL, devId);
    if (ret != 0) {
        goto out;
    }
    initRsa = 1;

    if ((ret = wc_InitRng(&rng)) != 0)
        goto out;

    if ((ret = wc_RsaSetRNG(key, &rng)) != 0)
        goto out;

    /* Generate a new RSA key to use with TSIP/SCE */
    if ((ret = wc_MakeRsaKey(key, keySize, 65537, &rng)) != 0) {
        goto out;
    }

    ret = wc_RsaSSL_Sign(in, inLen, out, outSz, key, &rng);
    if (ret < 0) {
        goto out;
    }
    signSz = ret;

    /* this should fail */
    ret = wc_RsaSSL_Verify(out, signSz, in2, inLen, key);
    if (ret != SIG_VERIFY_E) {
        ret = -1;
        goto out;
    }
    /* this should succeed */
    ret = wc_RsaSSL_Verify(out, signSz, in, inLen, key);
    if (ret < 0) {
        ret = -1;
        goto out;
    }
    ret = 0;

  out:

    wc_FreeRng(&rng);
    if (key != NULL) {
        if (initRsa)
            wc_FreeRsaKey(key);
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(in, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(in2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    (void)prnt;
    return ret;
}
#endif /* NO_RSA */


#ifdef TSIP_MULTIUNIT_TEST
int tsip_crypt_sha_multitest(void)
{
    int ret = 0;
    int num = 0;
    int i;
    BaseType_t xRet;

#ifndef NO_SHA
    num++;
#endif
#ifndef NO_SHA256
    num++;
#endif
    exit_loop = 0;
    sha_multTst_rslt = 0;
    sha256_multTst_rslt = 0;

    exit_semaph = xSemaphoreCreateCounting(num, 0);
    xRet = pdPASS;

#ifndef NO_SHA
    xRet = xTaskCreate(tskSha_Test, "sha_test",
                            SMALL_STACK_SIZE, NULL, 3, NULL);
#endif
#ifndef NO_SHA256
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskSha256_Test, "sha256_test",
                            SMALL_STACK_SIZE, NULL, 3, NULL);
#endif

    if (xRet == pdPASS) {
        printf(" Waiting for completing tasks ...");
        vTaskDelay(10000/portTICK_PERIOD_MS);
        exit_loop = true;

        for (i = 0; i < num; i++) {
            if (!xSemaphoreTake(exit_semaph, 2000/portTICK_PERIOD_MS)) {
                printf("a semaphore was not given by a test task.");
                ret = -1;
                xRet = pdFAIL;
            }
        }
    }

    vSemaphoreDelete(exit_semaph);

    if ((xRet == pdPASS) &&
       (sha_multTst_rslt == 0 && sha256_multTst_rslt == 0))
        ret = 0;
    else
        ret = -1;

    RESULT_STR(ret)

    return ret;
}


int tsip_crypt_AesCbc_multitest(void)
{
    int ret = 0;
    int num = 0;
    int i;
    Info info_aes1;
    Info info_aes2;
    Info info_aes256_1;
    Info info_aes256_2;
    BaseType_t xRet;

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    num+=2;
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    num+=2;
#endif
    exit_loop = 0;
    Aes128_Cbc_multTst_rslt = 0;
    Aes256_Cbc_multTst_rslt = 0;

    exit_semaph = xSemaphoreCreateCounting(num, 0);
    xRet = pdPASS;

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    XMEMCPY(&info_aes1.aes_key, &g_user_aes128_key_index1,
                                            sizeof(tsip_aes_key_index_t));
    xRet = xTaskCreate(tskAes128_Cbc_Test, "aes_cbc_tes1t",
            SMALL_STACK_SIZE, &info_aes1, 3, NULL);
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    XMEMCPY(&info_aes2.aes_key, &g_user_aes128_key_index2,
                                            sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes128_Cbc_Test, "aes_cbc_test2",
                SMALL_STACK_SIZE, &info_aes2, 3, NULL);
#endif

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    XMEMCPY(&info_aes256_1.aes_key, &g_user_aes256_key_index1,
                                            sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes256_Cbc_Test, "aes256_cbc_test1",
                SMALL_STACK_SIZE, &info_aes256_1, 3, NULL);
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    XMEMCPY(&info_aes256_2.aes_key, &g_user_aes256_key_index2,
                                            sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes256_Cbc_Test, "aes256_cbc_test2",
                SMALL_STACK_SIZE, &info_aes256_2, 3, NULL);
#endif

    if (xRet == pdPASS) {
    printf(" Waiting for completing tasks ...");
        vTaskDelay(10000/portTICK_PERIOD_MS);
        exit_loop = true;

        for (i = 0; i < num; i++) {
            if (!xSemaphoreTake(exit_semaph, 2000/portTICK_PERIOD_MS)) {
                printf("a semaphore was not given by a test task.");
                ret = -1;
                xRet = pdFAIL;
            }
        }
    }

    vSemaphoreDelete(exit_semaph);

    if ((xRet == pdPASS) &&
       (Aes128_Cbc_multTst_rslt == 0 && Aes256_Cbc_multTst_rslt == 0))
        ret = 0;
    else
        ret = -1;

    RESULT_STR(ret)

    return ret;
}


int tsip_crypt_AesGcm_multitest(void)
{
    int ret = 0;
    int num = 0;
    int i;
    Info info_aes1;
    Info info_aes2;
    Info info_aes256_1;
    Info info_aes256_2;
    BaseType_t xRet;

#if defined(WOLFSSL_AES_128)
    num+=2;
#endif
#if defined(WOLFSSL_AES_256)
    num+=2;
#endif

    exit_loop = 0;
    Aes128_Gcm_multTst_rslt = 0;
    Aes256_Gcm_multTst_rslt = 0;

    exit_semaph = xSemaphoreCreateCounting(num, 0);
    xRet = pdPASS;

#if defined(WOLFSSL_AES_128)
    XMEMCPY(&info_aes1.aes_key, &g_user_aes128_key_index1,
                                    sizeof(tsip_aes_key_index_t));
    xTaskCreate(tskAes128_Gcm_Test, "aes128_gcm_test1",
                                    STACK_SIZE, &info_aes1, 3, NULL);

    XMEMCPY(&info_aes2.aes_key, &g_user_aes128_key_index2,
                                        sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes128_Gcm_Test, "aes128_gcm_test2",
                                    STACK_SIZE, &info_aes2, 3, NULL);
#endif


#if defined(WOLFSSL_AES_256)
    XMEMCPY(&info_aes256_1.aes_key, &g_user_aes256_key_index1,
                                        sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes256_Gcm_Test, "aes256_gcm_test1",
                                    STACK_SIZE, &info_aes256_1, 3, NULL);
    XMEMCPY(&info_aes256_2.aes_key, &g_user_aes256_key_index2,
                                        sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes256_Gcm_Test, "aes256_gcm_test2",
                                    STACK_SIZE, &info_aes256_2, 3, NULL);
#endif

    if (xRet == pdPASS) {
        printf(" Waiting for completing tasks ...");
        vTaskDelay(10000/portTICK_PERIOD_MS);
        exit_loop = true;

        for (i = 0; i < num; i++) {
            if (!xSemaphoreTake(exit_semaph, 5000/portTICK_PERIOD_MS)) {
                printf("a semaphore was not given by a test task.");
                ret = -1;
                xRet = pdFAIL;
            }
        }
    }

    vSemaphoreDelete(exit_semaph);

    if ((xRet == pdPASS) &&
        (Aes128_Gcm_multTst_rslt == 0 && Aes256_Gcm_multTst_rslt == 0))
        ret = 0;
    else
        ret = -1;

    RESULT_STR(ret)

    return ret;
}

int tsip_crypt_Sha_AesCbcGcm_multitest(void)
{
    int ret = 0;
    int num = 0;
    int i;
    Info info_aes256cbc;
    Info info_aes256gcm;
    BaseType_t xRet;

#ifndef NO_SHA
    num++;
#endif

#if defined(WOLFSSL_AES_128)
    num+=1;
#endif
#if defined(WOLFSSL_AES_256)
    num+=1;
#endif

    exit_loop = 0;
    sha_multTst_rslt = 0;
    Aes256_Cbc_multTst_rslt = 0;
    Aes256_Gcm_multTst_rslt = 0;

    exit_semaph = xSemaphoreCreateCounting(num, 0);
    xRet = pdPASS;

#ifndef NO_SHA
    xRet = xTaskCreate(tskSha_Test, "sha_test",
                                SMALL_STACK_SIZE, NULL, 3, NULL);
#endif

#if defined(WOLFSSL_AES_256)
    XMEMCPY(&info_aes256cbc.aes_key, &g_user_aes256_key_index1,
                                                sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes256_Cbc_Test, "aes256_cbc_test1",
                SMALL_STACK_SIZE, &info_aes256cbc, 3, NULL);
#endif

#if defined(WOLFSSL_AES_256)
    XMEMCPY(&info_aes256gcm.aes_key, &g_user_aes256_key_index2,
                                                sizeof(tsip_aes_key_index_t));
    if (xRet == pdPASS)
        xRet = xTaskCreate(tskAes256_Gcm_Test, "aes256_gcm_test2",
                                    STACK_SIZE, &info_aes256gcm, 3, NULL);
#endif

    if (xRet == pdPASS) {
        printf(" Waiting for completing tasks ...");
        vTaskDelay(10000/portTICK_PERIOD_MS);
        exit_loop = true;

        for (i = 0; i < num; i++) {
            if (!xSemaphoreTake(exit_semaph, 2000/portTICK_PERIOD_MS)) {
                printf("a semaphore was not given by a test task.");
                ret = -1;
                xRet = pdFAIL;
            }
        }
    }

    vSemaphoreDelete(exit_semaph);

    if (xRet == pdPASS && sha_multTst_rslt == 0 &&
       (Aes256_Cbc_multTst_rslt == 0 && Aes256_Gcm_multTst_rslt == 0)) {
        ret = 0;
    }
    else {
        ret = -1;
    }

    RESULT_STR(ret)

    return ret;
}
#endif


int tsip_crypt_test(void)
{
    int ret = 0;
    int devId;

    Clr_CallbackCtx(&userContext);
    if (ret != 0) {
        printf("TSIP Key Generation failed\n");
        return -1;
    }

    devId = wc_CryptoCb_CryptInitRenesasCmn(NULL, &userContext);
    if (devId > 0){
        ret = 0;
    }

    if (ret == 0) {
    #ifndef NO_SHA
        printf(" sha_test()");
        ret = sha_test();
        RESULT_STR(ret);
    #endif

    #ifndef NO_SHA256
        printf(" sha256_test()");
        if (ret == 0) {
            ret = sha256_test();
            RESULT_STR(ret);
        }
    #endif

    #ifdef HAVE_AES_CBC
        ret = TSIP_AesKeyGeneration(&userContext, 16);
        if (ret == 0)
            ret = tsip_aes128_cbc_test(1, devId);
        if (ret == 0) {
            Clr_CallbackCtx(&userContext);
            ret = TSIP_AesKeyGeneration(&userContext, 32);
            if (ret == 0)
                ret = tsip_aes256_cbc_test(1, devId);
        }
    #endif

    #ifdef HAVE_AESGCM
        if (ret == 0) {
            Clr_CallbackCtx(&userContext);
            ret = TSIP_AesKeyGeneration(&userContext, 16);
            if (ret == 0)
                ret = tsip_aesgcm128_test(1, devId);
        }
        if (ret == 0) {
            Clr_CallbackCtx(&userContext);
            ret = TSIP_AesKeyGeneration(&userContext, 32);
            if (ret == 0)
                ret = tsip_aesgcm256_test(1, devId);
        }
    #endif

    #if defined(WOLFSSL_AES_COUNTER) &&\
        (defined(TSIP_AES_128_CTR) && TSIP_AES_128_CTR == 1)
        #if defined(WOLFSSL_AES_128)
        Clr_CallbackCtx(&userContext);
        ret = TSIP_AesKeyGeneration(&userContext, 16);
        if (ret == 0) {
            ret = tsip_aes128_ctr_test(1, devId);
            RESULT_STR(ret);
        }
        #endif
        #if defined(WOLFSSL_AES_256)
        Clr_CallbackCtx(&userContext);
        ret = TSIP_AesKeyGeneration(&userContext, 32);
        if (ret == 0) {
            ret = tsip_aes256_ctr_test(1, devId);
            RESULT_STR(ret);
        }
        #endif
    #endif

    #if defined(WOLFSSL_KEY_GEN) && \
        defined(WOLFSSL_RENESAS_TSIP_CRYPTONLY)
    #if RSA_MIN_SIZE <= 1024
        if (ret == 0) {
            userContext.wrappedKeyType = TSIP_KEY_TYPE_RSA1024;
            printf(" tsip_rsa_test(1024)");
            ret = tsip_rsa_test(1, 1024);
            RESULT_STR(ret)
        }
    #endif
        if (ret == 0) {
            userContext.wrappedKeyType = TSIP_KEY_TYPE_RSA2048;
            printf(" tsip_rsa_test(2048)");
            ret = tsip_rsa_test(1, 2048);
            RESULT_STR(ret)
        }


    #if RSA_MIN_SIZE <= 1024
        if (ret == 0) {
            printf(" tsip_rsa_SignVerify_test(1024)");

            userContext.wrappedKeyType = TSIP_KEY_TYPE_RSA1024;
            userContext.sign_hash_type = sha256_mac;
            userContext.keyflgs_crypt.bits.message_type = 0;

            ret = tsip_rsa_SignVerify_test(1, 1024);
            RESULT_STR(ret)
        }

        Clr_CallbackCtx(&userContext);
    #endif

        if (ret == 0) {
            printf(" tsip_rsa_SignVerify_test(2048)");

            userContext.wrappedKeyType = TSIP_KEY_TYPE_RSA2048;
            userContext.sign_hash_type = sha256_mac;
            userContext.keyflgs_crypt.bits.message_type = 0;

            ret = tsip_rsa_SignVerify_test(1, 2048);
            RESULT_STR(ret)
        }

        Clr_CallbackCtx(&userContext);
#endif /* WOLFSSL_KEY_GEN && WOLFSSL_RENESAS_TSIP_CRYPTONLY */
    }
    else {
        ret = -1;
    }
    return ret;
}

#endif /* TSIP_CRYPT_UNIT_TEST */
