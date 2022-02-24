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
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl_demo.h"

void main(void);
#ifdef __cplusplus
extern "C" {

}
#endif


#if defined(TLS_CLIENT) || defined(TLS_SERVER)
    #include "r_tsip_rx_if.h"
    #include "r_t4_itcpip.h"
    #include "r_sys_time_rx_if.h"
    #include "Pin.h"

    #define T4_WORK_SIZE (14800)
    static UW tcpudp_work[(T4_WORK_SIZE / 4) + 1];
#endif

#if defined(WOLFSSL_RENESAS_TSIP_TLS)
    #include "key_data.h"
    #include <wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h>

    extern const st_key_block_data_t g_key_block_data;
    user_PKCbInfo            guser_PKCbInfo;
#endif

static long tick;
static void timeTick(void *pdata)
{
    tick++;
}

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;


void wolfcrypt_test(func_args args);
int  benchmark_test(void *args);

double current_time(int reset)
{
      if(reset) tick = 0 ;
      return ((double)tick/FREQ) ;
}

#if defined(TLS_CLIENT) || defined(TLS_SERVER)

int SetTsiptlsKey()
{
#if defined(WOLFSSL_RENESAS_TSIP) && (WOLFSSL_RENESAS_TSIP_VER >=109)   
    
#if defined(TLS_CLIENT)

    #if defined(USE_ECC_CERT)    
    /* Root CA cert has ECC-P256 public key */
    tsip_inform_cert_sign((const byte *)ca_ecc_cert_der_sig);
    #else    
    /* Root CA cert has RSA public key */
    tsip_inform_cert_sign((const byte *)ca_cert_der_sig);
    #endif

    tsip_inform_user_keys_ex(
            (byte*)&g_key_block_data.encrypted_provisioning_key,
            (byte*)&g_key_block_data.iv,
            (byte*)&g_key_block_data.encrypted_user_rsa2048_ne_key,
            encrypted_user_key_type);

    #if defined(WOLFSSL_RENESAS_TSIP_TLS) 
    guser_PKCbInfo.user_key_id = 0;
    #endif

#elif defined(TLS_SERVER)

    tsip_inform_cert_sign((const byte *)client_cert_der_sign);
    tsip_inform_user_keys_ex(
        (byte *)&g_key_block_data.encrypted_provisioning_key,
        (byte *)&g_key_block_data.iv,
        (byte *)&g_key_block_data.encrypted_user_rsa2048_ne_key,
        encrypted_user_key_type);

#endif

#elif defined(WOLFSSL_RENESAS_TSIP) && (WOLFSSL_RENESAS_TSIP_VER < 109)
    
    #if defined(TLS_CLIENT)
 
        tsip_inform_cert_sign((const byte *)ca_cert_sig);
        tsip_inform_user_keys((byte*)&g_key_block_data.encrypted_session_key,
                            (byte*)&g_key_block_data.iv,
                            (byte*)&g_key_block_data.encrypted_user_rsa2048_ne_key);
 
    #elif defined(TLS_SERVER)
 
        tsip_inform_cert_sign((const byte *)client_cert_der_sign);
        tsip_inform_user_keys((byte*)&g_key_block_data.encrypted_session_key,
                            (byte*)&g_key_block_data.iv,
                            (byte*)&g_key_block_data.encrypted_user_rsa2048_ne_key);
 
    #endif

#endif    
    return 0;
}

int Open_tcp( )
{
    ER  ercd;
    W   size;
    sys_time_err_t sys_ercd;
    char ver[128];

    /* initialize TSIP since t4 seems to call R_TSIP_RandomNumber */
    R_TSIP_Open(NULL,NULL);

    /* cast from uint8_t to char* */
    strcpy(ver, (char*)R_t4_version.library);

    sys_ercd = R_SYS_TIME_Open();
    if (sys_ercd != SYS_TIME_SUCCESS) {
        printf("ERROR : R_SYS_TIME_Open() failed\n");
        return -1;
    }
    R_Pins_Create();
    /* start LAN controller */
    ercd = lan_open();
    /* initialize TCP/IP */
    size = tcpudp_get_ramsize();
    if (size > (sizeof(tcpudp_work))) {
        printf("size > (sizeof(tcpudp_work))!\n");
        return -1;
    }
    ercd = tcpudp_open(tcpudp_work);
    if (ercd != E_OK) {
        printf("ERROR : tcpudp_open failed\n");
        return -1;
    }

    return 0;
}

void Close_tcp()
{
    /* end TCP/IP */
    tcpudp_close();
    lan_close();
    R_SYS_TIME_Close();
    R_TSIP_Close();
}
#endif

void main(void)
{
    (void)timeTick;

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
    #include "r_cmt_rx_if.h"

    uint32_t channel;
    R_CMT_CreatePeriodic(FREQ, &timeTick, &channel);

    printf("Start wolfCrypt Benchmark\n");
    benchmark_test(NULL);
    printf("End wolfCrypt Benchmark\n");
#endif
#elif defined(TLS_CLIENT)
    #include "r_cmt_rx_if.h"

#if defined(WOLFSSL_RENESAS_TSIP_TLS)

    #ifdef USE_ECC_CERT
    const char* cipherlist[] = {
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-SHA256"
    };
    const int cipherlist_sz = 2;

    #else
    const char* cipherlist[] = {
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-SHA256",
        "AES128-SHA",
        "AES128-SHA256",
        "AES256-SHA",
        "AES256-SHA256"
    };
    const int cipherlist_sz = 6;

    #endif

#else
    const char* cipherlist[] = { NULL };
    const int cipherlist_sz = 0;

#endif
    int i = 0;

    Open_tcp();

#if defined(WOLFSSL_RENESAS_TSIP_TLS)
    SetTsiptlsKey();
#endif
    
    do {
        if(cipherlist_sz > 0 ) printf("cipher : %s\n", cipherlist[i]);

        wolfSSL_TLS_client_init(cipherlist[i]);

        wolfSSL_TLS_client();

        i++;
    } while (i < cipherlist_sz);

    Close_tcp();
#elif defined(TLS_SERVER)

    Open_tcp();
#if   defined(WOLFSSL_RENESAS_TSIP)
    SetTsiptlsKey();
#endif

    wolfSSL_TLS_server_init();
    wolfSSL_TLS_server();

    Close_tcp();
#endif
}

#ifdef __cplusplus
void abort(void)
{

}
#endif
