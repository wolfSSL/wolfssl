/* test_main.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include "wolfssl_demo.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_RENESAS_SCEPROTECT) || \
defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY)
 #include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-crypt.h>
#if defined(TLS_MULTITHREAD_TEST)
 FSPSM_ST guser_PKCbInfo_taskA;
 FSPSM_ST guser_PKCbInfo_taskB;
#else
 FSPSM_ST guser_PKCbInfo;
#endif
#endif

#include <wolfssl_demo.h>
#include "key_data.h"
#include "hal_data.h"

#ifdef __cplusplus
extern "C" {
void abort(void);
}
#endif

#if defined(SCE_CRYPT_UNIT_TEST)
 int sce_crypt_test();
#endif

void R_BSP_WarmStart(bsp_warm_start_event_t event);

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

#if defined(TLS_CLIENT)

extern const st_user_key_block_data_t g_key_block_data;

/* Key type of the encrypted user_public_key 0: RSA-2048 2: ECDSA-P256*/
uint32_t              encrypted_user_key_type = 0;

static int SetScetlsKey()
{
#if defined(WOLFSSL_RENESAS_SCEPROTECT)

    #if defined(TLS_CLIENT)

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

#ifdef TLS_MULTITHREAD_TEST
static void my_Logging_cb(const int logLevel, const char *const logMessage)
{
    (void)logLevel;
    printf("custom-log: %s\n", logMessage);
}
#endif

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
void Clr_CallbackCtx(FSPSM_ST *g);
void SCE_KeyGeneration(FSPSM_ST *g);

void SCE_KeyGeneration(FSPSM_ST *g)
{
   fsp_err_t err = FSP_SUCCESS;

    if (g->wrapped_key_aes128 != NULL) {
        err = R_SCE_AES128_WrappedKeyGenerate(g->wrapped_key_aes128);
        if (err == FSP_SUCCESS)
            g->keyflgs_crypt.bits.aes128_installedkey_set = 1;
    }

    if (g->wrapped_key_aes256 != NULL) {
        err = R_SCE_AES256_WrappedKeyGenerate(g->wrapped_key_aes256);
        if (err == FSP_SUCCESS)
            g->keyflgs_crypt.bits.aes256_installedkey_set = 1;
    }


}

void Clr_CallbackCtx(FSPSM_ST *g)
{
    (void) g;

   #if defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY)
    XFREE(g->wrapped_key_rsapri2048, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    XFREE(g->wrapped_key_rsapub2048, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    XFREE(g->wrapped_key_rsapri1024, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (g->wrapped_key_rsapub2048 != NULL)
        XFREE(g->wrapped_key_rsapub1024,
                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
   #endif
   XMEMSET(g, 0, sizeof(FSPSM_ST));
}
#endif

void sce_test(void)
{

#if defined(SCE_CRYPT_UNIT_TEST) && \
        (defined(WOLFSSL_RENESAS_SCEPROTECT) || \
        defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY))
    int ret = 0;

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", ret);
    }
    printf("Start wolf sce crypt Test\n");

    printf(" \n");
    printf(" simple crypt test by using SCE\n");
    sce_crypt_test();

    printf(" \n");
    printf("End wolf sce crypt Test\n");

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", ret);
    }

#elif defined(CRYPT_TEST)  && \
        (defined(WOLFSSL_RENESAS_SCEPROTECT) || \
        defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY))
    int ret;
    func_args args = { 0 };

    if ((ret = wolfCrypt_Init()) != 0) {
         printf("wolfCrypt_Init failed %d\n", ret);
    }

#if defined(HAVE_RENESAS_SYNC) && \
    defined(HAVE_AES_CBC)

    Clr_CallbackCtx(&guser_PKCbInfo);

    #if defined(WOLFSSL_AES_128)
        sce_aes_wrapped_key_t user_aes128_key_index;
        guser_PKCbInfo.wrapped_key_aes128 = &user_aes128_key_index;
    #endif

    #if defined(WOLFSSL_AES_256)
       sce_aes_wrapped_key_t user_aes256_key_index;
        guser_PKCbInfo.wrapped_key_aes256 = &user_aes256_key_index;
    #endif
    /* Generate Wrapped aes key */
    SCE_KeyGeneration(&guser_PKCbInfo);
#endif



    printf("Start wolfCrypt Test\n");
    wolfcrypt_test(args);
    printf("End wolfCrypt Test\n");

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", ret);
    }

    Clr_CallbackCtx(&guser_PKCbInfo);

#elif defined(BENCHMARK)  && \
        (defined(WOLFSSL_RENESAS_SCEPROTECT) || \
        defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY))
    #include "hal_data.h"
    #include "r_sce.h"

    int ret;
    if ((ret = wolfCrypt_Init()) != 0) {
         printf("wolfCrypt_Init failed %d\n", ret);
    }

#if defined(HAVE_RENESAS_SYNC) && \
    defined(HAVE_AES_CBC)

    Clr_CallbackCtx(&guser_PKCbInfo);

    #if defined(WOLFSSL_AES_128)
        sce_aes_wrapped_key_t user_aes128_key_index;
        guser_PKCbInfo.wrapped_key_aes128 = &user_aes128_key_index;
    #endif

    #if defined(WOLFSSL_AES_256)
       sce_aes_wrapped_key_t user_aes256_key_index;
        guser_PKCbInfo.wrapped_key_aes256 = &user_aes256_key_index;
    #endif
    /* Generate Wrapped aes key */
    SCE_KeyGeneration(&guser_PKCbInfo);
#endif

    printf("Start wolfCrypt Benchmark\n");
    benchmark_test(NULL);
    printf("End wolfCrypt Benchmark\n");

    /* free */
    Clr_CallbackCtx(&guser_PKCbInfo);

#elif defined(TLS_CLIENT)
    #include "hal_data.h"
    #include "r_sce.h"

#if defined(WOLFSSL_TLS13)
    /* TLS1.3 needs RSA_PSS enabled.
     * SCE doesn't support RSA PSS Padding
     */
    const char* cipherlist[] = {
        NULL
    };
    const int cipherlist_sz = 1;
    TestInfo info[cipherlist_sz];
#else
    #if defined(USE_CERT_BUFFERS_256)
        #if !defined(TLS_MULTITHREAD_TEST)
        const char* cipherlist[] = {
           NULL,
           "ECDHE-ECDSA-AES128-GCM-SHA256",
           "ECDHE-ECDSA-AES256-SHA", /* sw only */
           "ECDHE-ECDSA-AES128-SHA256"
        };
        const int cipherlist_sz = 3;
        TestInfo info[cipherlist_sz];
        #else
        const char* cipherlist[] = {
           "ECDHE-ECDSA-AES128-GCM-SHA256",
           "ECDHE-ECDSA-AES128-SHA256"
        };
        const int cipherlist_sz = 2;
        TestInfo info[cipherlist_sz];
        #endif
    #else
       #if !defined(TLS_MULTITHREAD_TEST)
        const char* cipherlist[] = {
           NULL,
           "ECDHE-RSA-AES128-GCM-SHA256",
           "ECDHE-RSA-AES256-SHA", /* sw only */
           "ECDHE-RSA-AES128-SHA256",
           "AES128-SHA256",
           "AES256-SHA256",
        };
        const int cipherlist_sz = 6;
        TestInfo info[cipherlist_sz];
       #else
        const char* cipherlist[] = {
           "ECDHE-RSA-AES128-GCM-SHA256",
           "ECDHE-RSA-AES128-SHA256",
           "AES128-SHA256",
           "AES256-SHA256",
        };
        const int cipherlist_sz = 4;
        TestInfo info[cipherlist_sz];
       #endif
    #endif
#endif

    #ifdef TLS_MULTITHREAD_TEST
    BaseType_t xReturned;
    BaseType_t xHigherPriorityTaskWoken;
    xHigherPriorityTaskWoken = pdFALSE;
    int j = 0;
    #endif
    int i = 0;
    int ret = 0;

    printf("\n Start Client Example, ");
    printf("\n Connecting to %s\n\n", SERVER_IP);

    SetScetlsKey();

    TCPInit();

    #ifdef TLS_MULTITHREAD_TEST

    wolfSSL_TLS_client_init();

    exit_semaph = xSemaphoreCreateCounting(cipherlist_sz, 0);

    do {

        for(j = i; j < (i+2); j++) {
            info[j].port = DEFAULT_PORT + (j%2);
            info[j].cipher = cipherlist[j];
            info[j].ctx = client_ctx;
            info[j].xBinarySemaphore = xSemaphoreCreateBinary();
            info[j].log_f = my_Logging_cb;

            memset(info[j].name, 0, sizeof(info[j].name));
            sprintf(info[j].name, "clt_thd_%s", ((j%2) == 0) ?
                                                            "taskA" : "taskB");

            printf(" %s connecting to %d port\n", info[j].name, info[j].port);

            xReturned = xTaskCreate(wolfSSL_TLS_client_do, info[j].name,
                                    THREAD_STACK_SIZE, &info[j], 2, NULL);
            if (xReturned != pdPASS) {
                 printf("Failed to create task\n");
            }
        }

        for(j = i; j < (i+2); j++) {
            xSemaphoreGiveFromISR(info[j].xBinarySemaphore,
                                                &xHigherPriorityTaskWoken);
        }

        /* check if all tasks are completed */
        for(j = i; j < (i+2); j++) {
            if(!xSemaphoreTake(exit_semaph, portMAX_DELAY)) {
                printf("exit semaphore not released by test task");
            }
        }

        i+=2;

    } while (i < cipherlist_sz);

    vSemaphoreDelete(exit_semaph);

    #else

    int TCP_connect_retry = 0;
    wolfSSL_TLS_client_init();

    do {

        info[i].port = DEFAULT_PORT;
        info[i].cipher = cipherlist[i];
        info[i].ctx = client_ctx;
        info[i].id = i;

        XMEMSET(info[i].name, 0, sizeof(info[i].name));
        XSPRINTF(info[i].name, "wolfSSL_TLS_client_do(%02d)", i);

        ret = wolfSSL_TLS_client_do(&info[i]);
        if(ret == -116 || ret == -128) {
            TCP_connect_retry++;
            continue;
        }
        TCP_connect_retry = 0;
        i++;
    } while (i < cipherlist_sz && TCP_connect_retry < 100);

    #endif /* SCE_MULTITHREAD_TEST */

    printf("\n End of Client Example");

    wolfSSL_TLS_cleanup();

#endif
}

#ifdef __cplusplus
void abort(void)
{

}
#endif
