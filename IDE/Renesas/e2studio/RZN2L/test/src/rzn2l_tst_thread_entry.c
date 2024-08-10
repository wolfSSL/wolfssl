/* rzn2l_tst_thread_entry.c
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
#include "rzn2l_tst_thread.h"

#include "um_common_cfg.h"
#include "um_common_api.h"
#include "um_serial_io_api.h"
#include "um_serial_io.h"

#include "wolfssl_demo.h"
#include "user_settings.h"

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static serial_io_instance_ctrl_t g_serial_io0_ctrl;
static serial_io_cfg_t const g_serial_io0_cfg =
{
    .p_uart_instance = &g_uart0,
};
serial_io_instance_t const g_serial_io0 =
{
    .p_ctrl = &g_serial_io0_ctrl,
    .p_cfg  = &g_serial_io0_cfg,
    .p_api  = &g_serial_io_on_serial_io,
};

FSP_CPP_HEADER
void R_BSP_WarmStart(bsp_warm_start_event_t event)
BSP_PLACE_IN_SECTION(".warm_start");
FSP_CPP_FOOTER

void R_BSP_WarmStart(bsp_warm_start_event_t event)
{
    if (BSP_WARM_START_RESET == event) {
    }

    if (BSP_WARM_START_POST_C == event){
        R_IOPORT_Open (&g_ioport_ctrl, &g_bsp_pin_cfg);
    }
}

#if defined(TLS_CLIENT) || \
    defined(TLS_SERVER)
    extern uint8_t g_ether0_mac_address[6];
    const byte ucIPAddress[4]          = { 192, 168, 11, 241 };
    const byte ucNetMask[4]            = { 255, 255, 255, 0 };
    const byte ucGatewayAddress[4]     = { 192, 168, 11, 1 };
    const byte ucDNSServerAddress[4]   = { 192, 168, 11, 1 };
#endif

#if  defined(WOLFSSL_RENESAS_FSPSM) && \
     defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)

#if defined(UNIT_TEST)
 int rsip_crypt_test();
#endif

#if (defined(BENCHMARK) || defined(CRYPT_TEST)) \
    && defined(HAVE_RENESAS_SYNC) && defined(HAVE_AES_CBC)
    FSPSM_ST guser_PKCbInfo;
#endif

void Clr_CallbackCtx(FSPSM_ST *g);
void RSIP_KeyGeneration(FSPSM_ST *g);

void RSIP_KeyGeneration(FSPSM_ST *g)
{
    fsp_err_t rsip_error_code = FSP_SUCCESS;

    if (g->wrapped_key_aes128 != NULL) {
        rsip_error_code = R_RSIP_KeyGenerate(&gFSPSM_ctrl,
                                         RSIP_KEY_TYPE_AES_128,
                                         g->wrapped_key_aes128);
        if (rsip_error_code == FSP_SUCCESS)
            g->keyflgs_crypt.bits.aes128_installedkey_set = 1;
    }

    if (g->wrapped_key_aes256 != NULL) {
        rsip_error_code = R_RSIP_KeyGenerate(&gFSPSM_ctrl,
                                         RSIP_KEY_TYPE_AES_256,
                                         g->wrapped_key_aes256);
        if (rsip_error_code == FSP_SUCCESS)
            g->keyflgs_crypt.bits.aes256_installedkey_set = 1;
    }

    if (g->wrapped_key_rsapri1024 != NULL &&
        g->wrapped_key_rsapub1024 != NULL) {
        rsip_error_code = R_RSIP_KeyPairGenerate(&gFSPSM_ctrl,
                                 RSIP_KEY_PAIR_TYPE_RSA_1024,
                                 g->wrapped_key_rsapub1024,
                                 g->wrapped_key_rsapri1024);
        if (rsip_error_code == FSP_SUCCESS) {
            g->keyflgs_crypt.bits.rsapri1024_installedkey_set = 1;
            g->keyflgs_crypt.bits.rsapub1024_installedkey_set = 1;
        }
    }

    if (g->wrapped_key_rsapri2048 != NULL &&
        g->wrapped_key_rsapub2048 != NULL) {
        rsip_error_code = R_RSIP_KeyPairGenerate(&gFSPSM_ctrl,
                                 RSIP_KEY_PAIR_TYPE_RSA_2048,
                                 g->wrapped_key_rsapub2048,
                                 g->wrapped_key_rsapri2048);
        if (rsip_error_code == FSP_SUCCESS) {
            g->keyflgs_crypt.bits.rsapri2048_installedkey_set = 1;
            g->keyflgs_crypt.bits.rsapub2048_installedkey_set = 1;
        }
    }
}

/* only pointer sets to NULL     */
/* owner of keys should be freed */
void Clr_CallbackCtx(FSPSM_ST *g)
{
    (void) g;

    if (g->wrapped_key_aes256 != NULL)
        g->wrapped_key_aes256 = NULL;

    if (g->wrapped_key_aes128 != NULL)
        g->wrapped_key_aes128 = NULL;

   #if defined(WOLFSSL_RENESAS_RSIP_CRYPTONLY)
    if (g->wrapped_key_rsapri2048 != NULL)
        g->wrapped_key_rsapri2048 = NULL;

    if (g->wrapped_key_rsapub2048 != NULL)
        g->wrapped_key_rsapub2048 = NULL;

    if (g->wrapped_key_rsapri1024 != NULL)
        g->wrapped_key_rsapri1024 = NULL;

    if (g->wrapped_key_rsapub2048 != NULL)
        g->wrapped_key_rsapub2048 = NULL;
   #endif

    XMEMSET(g, 0, sizeof(FSPSM_ST));
}
#endif


#if defined(TLS_CLIENT) || \
    defined(TLS_SERVER)

extern WOLFSSL_CTX *client_ctx;
extern WOLFSSL_CTX *server_ctx;

void TCPInit( )
{
   BaseType_t fr_status;

   /* FreeRTOS+TCP Ethernet and IP Setup */
   fr_status = FreeRTOS_IPInit(ucIPAddress,
                               ucNetMask,
                               ucGatewayAddress,
                               ucDNSServerAddress,
                               g_ether0_mac_address);

   if (pdPASS != fr_status) {
       printf("Error [%ld]: FreeRTOS_IPInit.\n",fr_status);
   }
}


void wolfSSL_TLS_cleanup()
{
#if defined(TLS_CLIENT)
    if (client_ctx) {
        wolfSSL_CTX_free(client_ctx);
    }
#endif
#if defined(TLS_SERVER)
    if (server_ctx) {
        wolfSSL_CTX_free(server_ctx);
    }
#endif
    wolfSSL_Cleanup();
}

#endif

serial_io_instance_t   const * gp_serial_io0   = &g_serial_io0;
static void serial_init()
{
    usr_err_t usr_err;

    /** Open Serial I/O module. */
    usr_err = gp_serial_io0->p_api->open
            (gp_serial_io0->p_ctrl, gp_serial_io0->p_cfg );
    if( USR_SUCCESS != usr_err )
    {
      USR_DEBUG_BLOCK_CPU();
    }

    /** Start Serial I/O module. */
    usr_err = gp_serial_io0->p_api->start( gp_serial_io0->p_ctrl );
    if( USR_SUCCESS != usr_err )
    {
      USR_DEBUG_BLOCK_CPU();
    }
    printf( " Started Serial I/O interface." );
}

/* rzn2l_tst_thread entry function */
/* pvParameters contains TaskHandle_t */
void rzn2l_tst_thread_entry(void *pvParameters)
{
    FSP_PARAMETER_NOT_USED (pvParameters);


    serial_init();

#if defined(UNIT_TEST)

    int ret;

    printf("\n");
    printf("\n Start wolf RSIP Crypt Test\n");

    if ((ret = wolfCrypt_Init()) != 0) {
        printf(" wolfCrypt_Init failed %d\n", ret);
    }
#if defined(WOLFSSL_RENESAS_FSPSM) && \
    defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)
    printf(" \n");
    printf(" RSIP Unit Test\n");
    rsip_crypt_test();
#else
    printf(" \n");
    printf(" RSIP Unit Test Not Run\n");
#endif
    printf(" \n");
    printf(" End wolf RSIP crypt Test\n");

    if ((ret = wolfCrypt_Cleanup()) != 0) {
        printf("wolfCrypt_Cleanup failed %d\n", ret);
    }

#elif defined(CRYPT_TEST)
    #include "wolfcrypt/test/test.h"
#if defined(HAVE_RENESAS_SYNC) && \
    defined(HAVE_AES_CBC)

    Clr_CallbackCtx(&guser_PKCbInfo);

    #if defined(WOLFSSL_AES_128)
        uint8_t        wrapped_key1[RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128];
        FSPSM_AES_PWKEY user_aes128_key_index =
                            (FSPSM_AES_PWKEY)wrapped_key1;
        guser_PKCbInfo.wrapped_key_aes128 = user_aes128_key_index;
    #endif

    #if defined(WOLFSSL_AES_256)
        uint8_t        wrapped_key2[RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256];
        FSPSM_AES_PWKEY user_aes256_key_index =
                            (FSPSM_AES_PWKEY)wrapped_key2;
        guser_PKCbInfo.wrapped_key_aes256 = user_aes256_key_index;
    #endif
    /* Generate Wrapped aes key */
    RSIP_KeyGeneration(&guser_PKCbInfo);
#endif

    int ret;

    func_args args = { 0 };

    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", ret);
    }

    printf("\n");
    printf("\n Start wolfCrypt Test\n");
    wolfcrypt_test((void*)&args);
    printf(" End wolfCrypt Test\n");

    if ((ret = wolfCrypt_Cleanup()) != 0) {
       printf("wolfCrypt_Cleanup failed %d\n", ret);
    }
#if defined(HAVE_RENESAS_SYNC) && \
    defined(HAVE_AES_CBC)
    Clr_CallbackCtx(&guser_PKCbInfo);
#endif

#elif defined(BENCHMARK)
#if defined(HAVE_RENESAS_SYNC) && \
    defined(HAVE_AES_CBC)

    Clr_CallbackCtx(&guser_PKCbInfo);

    #if defined(WOLFSSL_AES_128)
        uint8_t        wrapped_key1[RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128];
        FSPSM_AES_PWKEY user_aes128_key_index =
                            (FSPSM_AES_PWKEY)wrapped_key1;
        guser_PKCbInfo.wrapped_key_aes128 = user_aes128_key_index;
    #endif

    #if defined(WOLFSSL_AES_256)
        uint8_t        wrapped_key2[RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256];
        FSPSM_AES_PWKEY user_aes256_key_index =
                            (FSPSM_AES_PWKEY)wrapped_key2;
        guser_PKCbInfo.wrapped_key_aes256 = user_aes256_key_index;
    #endif
    /* Generate Wrapped aes key */
    RSIP_KeyGeneration(&guser_PKCbInfo);
#endif
    printf(" Start wolfCrypt Benchmark\n");

    benchmark_test(NULL);

    printf(" End wolfCrypt Benchmark\n");
#if defined(HAVE_RENESAS_SYNC) && \
    defined(HAVE_AES_CBC)
    Clr_CallbackCtx(&guser_PKCbInfo);
#endif

#elif defined(TLS_CLIENT)

    int i = 0;
    const int Max_Retry = 10;

    #if defined(WOLFSSL_TLS13)
        const char* cipherlist[] = {
            "TLS13-AES128-GCM-SHA256",
            "TLS13-AES256-GCM-SHA384",
        };
        const int cipherlist_sz = 2;
        TestInfo info[cipherlist_sz];
    #elif defined(USE_CERT_BUFFERS_2048)
        const char* cipherlist[] = {
             "ECDHE-RSA-AES128-GCM-SHA256",
             "ECDHE-RSA-AES256-SHA",
             "ECDHE-RSA-AES128-SHA256"
        };
        const int cipherlist_sz = 3;
        TestInfo info[cipherlist_sz];
    #elif defined(USE_CERT_BUFFERS_256)
        const char* cipherlist[] = {
           "ECDHE-ECDSA-AES128-GCM-SHA256",
           "ECDHE-ECDSA-AES256-SHA",
           "ECDHE-ECDSA-AES128-SHA256"
        };
        const int cipherlist_sz = 3;
        TestInfo info[cipherlist_sz];
    #endif

    TCPInit();

    int TCP_connect_retry = 0;

    printf("\n Start TLS Connection to %s port(%d)\n", SERVER_IP, DEFAULT_PORT);
    wolfSSL_TLS_client_init();

    do {

        info[i].port = DEFAULT_PORT;
        info[i].cipher = cipherlist[i];
        info[i].ctx = client_ctx;
        info[i].id = i;

        XMEMSET(info[i].name, 0, sizeof(info[i].name));
        XSPRINTF(info[i].name, "wolfSSL_TLS_client_do(%02d)", i);

        if(wolfSSL_TLS_client_do(&info[i]) == -116) {
            TCP_connect_retry++;
            continue;
        }
        TCP_connect_retry = 0;
        i++;
    } while (i < cipherlist_sz && TCP_connect_retry < Max_Retry);

    printf("\n End of Client Example");

    wolfSSL_TLS_cleanup();
#elif defined(TLS_SERVER)

    int i = 0;
    const int Max_Retry = 10;
    TestInfo info;

    TCPInit();

    int TCP_connect_retry = 0;

    printf("\n Start TLS Accept at %03d.%03d.%03d.%03d port(%d)\n",
                                                   ucIPAddress[0],
                                                   ucIPAddress[1],
                                                   ucIPAddress[2],
                                                   ucIPAddress[3],DEFAULT_PORT);
    wolfSSL_TLS_server_init();

    do {

        info.port = DEFAULT_PORT;
        info.cipher = NULL;
        info.ctx = server_ctx;
        info.id = i;

        XMEMSET(info.name, 0, sizeof(info.name));
        XSPRINTF(info.name, "wolfSSL_TLS_server_do(%02d)",
                                                 TCP_connect_retry);
        if(wolfSSL_TLS_server_do(&info) == -116) {
            TCP_connect_retry++;
            continue;
        }
        TCP_connect_retry = 0;
    } while (TCP_connect_retry < Max_Retry);

    printf("\n End of Client Example");

#endif
    /* TODO: add your own code here */
    while (1)
    {
        vTaskDelay (1);
    }
}
