/* test_main.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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


#include "stdio.h"
#include "stdint.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
 #include <wolfssl/wolfcrypt/port/Renesas/renesas-sce-crypt.h>
 User_SCEPKCbInfo        guser_PKCbInfo;
#endif

#include <wolfssl_demo.h>
#include "key_data.h"
#include "hal_data.h"

#ifdef __cplusplus
extern "C" {
void abort(void);
}
#endif

/* the function is called just before main() to set up pins */
/* this needs to be called to setup IO Port */
void R_BSP_WarmStart (bsp_warm_start_event_t event)
{

    if (BSP_WARM_START_POST_C == event) {
        /* C runtime environment and system clocks are setup. */
        /* Configure pins. */
        R_IOPORT_Open(&g_ioport_ctrl, g_ioport.p_cfg);
    }
}

#if defined(TLS_CLIENT) || defined(TLS_SERVER) || defined(EXTRA_SCE_TSIP_TEST)

extern const st_user_key_block_data_t g_key_block_data;

/* Key type of the encrypted user_public_key 0: RSA-2048 2: ECDSA-P256*/
uint32_t              encrypted_user_key_type = 0;

static int SetScetlsKey()
{
#if defined(WOLFSSL_RENESAS_SCEPROTECT)

    #if defined(TLS_CLIENT) || defined(EXTRA_SCE_TSIP_TEST)

      #if defined(USE_CERT_BUFFERS_256)
        wc_sce_inform_cert_sign((const byte *)ca_ecc_cert_der_sign);
        encrypted_user_key_type = 2;
      #else
        wc_sce_inform_cert_sign((const byte *)ca_cert_der_sign);
      #endif
        wc_sce_inform_user_keys(
            (byte*)&g_key_block_data.encrypted_provisioning_key,
            (byte*)&g_key_block_data.iv,
            (byte*)&g_key_block_data.encrypted_user_rsa2048_ne_key,
            encrypted_user_key_type);
        #if defined(WOLFSSL_RENESAS_SCEPROTECT_ECC)
            guser_PKCbInfo.user_key_id = 0; /* not use user key id */
        #endif

    #elif defined(TLS_SERVER)

        wc_sce_inform_cert_sign((const byte *)client_cert_der_sign);
        wc_sce_inform_user_keys(
            (byte*)&g_key_block_data.encrypted_provisioning_key,
            (byte*)&g_key_block_data.iv,
            (byte*)&g_key_block_data.encrypted_user_rsa2048_ne_key,
            encrypted_user_key_type);

    #endif

#endif    
    return 0;
}    
#endif

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;


void wolfcrypt_test(func_args args);
int  benchmark_test(void *args);


void sce_test(void)
{

#if defined(CRYPT_TEST) || defined(BENCHMARK)
#if defined(CRYPT_TEST)
    int ret;
    func_args args = { 0 };

    if ((ret = wolfCrypt_Init()) != 0) {
         printf("wolfCrypt_Init failed %d\n", ret);
    }

    printf("Start wolfCrypt Test\n");
    wolfcrypt_test(args);
    printf("End wolfCrypt Test\n");

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", ret);
    }
#endif
#if defined(BENCHMARK)
    #include "hal_data.h"
    #include "r_sce.h"

    printf("Prepare Installed key\n");
#if defined(WOLFSSL_RENESAS_SCEPROTECT) && defined(SCEKEY_INSTALLED)
    /* aes 256 */
    memcpy(guser_PKCbInfo.sce_wrapped_key_aes256.value,
           (uint32_t *)DIRECT_KEY_ADDRESS_256, HW_SCE_AES256_KEY_INDEX_WORD_SIZE*4);
    guser_PKCbInfo.sce_wrapped_key_aes256.type = SCE_KEY_INDEX_TYPE_AES256;
    guser_PKCbInfo.aes256_installedkey_set = 1;
    /* aes 128 */
    memcpy(guser_PKCbInfo.sce_wrapped_key_aes128.value,
               (uint32_t *)DIRECT_KEY_ADDRESS_128, HW_SCE_AES128_KEY_INDEX_WORD_SIZE*4);
        guser_PKCbInfo.sce_wrapped_key_aes128.type = SCE_KEY_INDEX_TYPE_AES128;
    guser_PKCbInfo.aes128_installedkey_set = 1;
#endif
    printf("Start wolfCrypt Benchmark\n");
    benchmark_test(NULL);
    printf("End wolfCrypt Benchmark\n");
#endif
    
#elif defined(TLS_CLIENT)
    #include "hal_data.h"
    #include "r_sce.h"
    
  #if defined(USE_CERT_BUFFERS_256)
   #if defined(TEST_CIPHER_SPECIFIED)
    const char* cipherlist[] = {
       "ECDHE-ECDSA-AES128-SHA256",
       "ECDHE-ECDSA-AES128-GCM-SHA256"
    };
    const int cipherlist_sz = 2;
   #else
    const char* cipherlist[] = {
       NULL
    };
    const int cipherlist_sz = 1;
   #endif /* TEST_CIPHER_SPECIFIED */

  #else
   #if defined(TEST_CIPHER_SPECIFIED)
    const char* cipherlist[] = {
       "AES128-SHA256",
       "AES256-SHA256",
       "ECDHE-RSA-AES128-SHA256",
       "ECDHE-RSA-AES128-GCM-SHA256"
    };
    const int cipherlist_sz = 4;
   #else
    const char* cipherlist[] = {
       NULL
    };
    const int cipherlist_sz = 1;
   #endif /* TEST_CIPHER_SPECIFIED */
  #endif

    int i = 0;

    SetScetlsKey();
    
    TCPInit();

    do {
        if(cipherlist_sz > 0 && cipherlist[i] != NULL )
            printf("cipher : %s\n", cipherlist[i]);

        wolfSSL_TLS_client_init(cipherlist[i]);
        wolfSSL_TLS_client();
        
        i++;
    } while (i < cipherlist_sz);
#endif
}

#ifdef __cplusplus
void abort(void)
{

}
#endif
