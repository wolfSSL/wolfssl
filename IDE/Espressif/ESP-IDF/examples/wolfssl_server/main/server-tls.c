/* server-tls.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#include "server-tls.h"

/* Espressif FreeRTOS */
#ifndef SINGLE_THREADED
    #include <freertos/FreeRTOS.h>
    #include <freertos/task.h>
    #include <freertos/event_groups.h>
#endif

/* socket includes */
#include <lwip/netdb.h>
#include <lwip/sockets.h>

/* wolfSSL */
#include <wolfssl/wolfcrypt/settings.h>
#include "user_settings.h"
#include <wolfssl/ssl.h>

#ifdef WOLFSSL_TRACK_MEMORY
    #include <wolfssl/wolfcrypt/mem_track.h>
#endif

#ifndef NO_DH
    /* see also wolfssl/test.h */
    #undef  DEFAULT_MIN_DHKEY_BITS
    #define DEFAULT_MIN_DHKEY_BITS 1024

    #undef  DEFAULT_MAX_DHKEY_BITS
    #define DEFAULT_MAX_DHKEY_BITS 2048
#endif

#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    #include <wolfssl/certs_test_sm.h>
    #define CTX_CA_CERT          root_sm2
    #define CTX_CA_CERT_SIZE     sizeof_root_sm2
    #define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_PEM
    #define CTX_SERVER_CERT      server_sm2
    #define CTX_SERVER_CERT_SIZE sizeof_server_sm2
    #define CTX_SERVER_CERT_TYPE WOLFSSL_FILETYPE_PEM
    #define CTX_SERVER_KEY       server_sm2_priv
    #define CTX_SERVER_KEY_SIZE  sizeof_server_sm2_priv
    #define CTX_SERVER_KEY_TYPE  WOLFSSL_FILETYPE_PEM
#else
    #include <wolfssl/certs_test.h>
    #define CTX_CA_CERT          ca_cert_der_2048
    #define CTX_CA_CERT_SIZE     sizeof_ca_cert_der_2048
    #define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_ASN1
    #define CTX_SERVER_CERT      server_cert_der_2048
    #define CTX_SERVER_CERT_SIZE sizeof_server_cert_der_2048
    #define CTX_SERVER_CERT_TYPE WOLFSSL_FILETYPE_ASN1
    #define CTX_SERVER_KEY       server_key_der_2048
    #define CTX_SERVER_KEY_SIZE  sizeof_server_key_der_2048
    #define CTX_SERVER_KEY_TYPE  WOLFSSL_FILETYPE_ASN1
#endif

/* Project */
#include "wifi_connect.h"
#include "time_helper.h"


static const char* const TAG = "server-tls";
int stack_start = -1;

int ShowCiphers(WOLFSSL* ssl)
{
    #define CLIENT_TLS_MAX_CIPHER_LENGTH 4096
    char ciphers[CLIENT_TLS_MAX_CIPHER_LENGTH];
    const char* cipher_used;
    int ret = 0;

    if (ssl == NULL) {
        ESP_LOGI(TAG, "WOLFSSL* ssl is NULL, so no cipher in use");
        ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));
        if (ret == WOLFSSL_SUCCESS) {
            for (int i = 0; i < CLIENT_TLS_MAX_CIPHER_LENGTH; i++) {
                if (ciphers[i] == ':') {
                    ciphers[i] = '\n';
                }
            }
            ESP_LOGI(TAG, "Available Ciphers:\n%s\n", ciphers);
        }
        else {
            ESP_LOGE(TAG, "Failed to call wolfSSL_get_ciphers. Error: %d", ret);
        }
    }
    else {
        cipher_used = wolfSSL_get_cipher_name(ssl);
        ESP_LOGI(TAG, "WOLFSSL* ssl using %s", cipher_used);
    }

    return ret;
}


/* FreeRTOS */
/* server task */
WOLFSSL_ESP_TASK tls_smp_server_task(void *args)
{
#if defined(SINGLE_THREADED)
    #define TLS_SMP_SERVER_TASK_RET ret
#else
    #define TLS_SMP_SERVER_TASK_RET
#endif
    char               buff[256];
    const char msg[] = "I hear you fa shizzle!";

    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    int                sockfd;
    int                connd;
    int                shutdown = 0;
    int                ret;
    socklen_t          size = sizeof(clientAddr);
    size_t             len;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

    WOLFSSL_ENTER("tls_smp_server_task");

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
    ShowCiphers(NULL);
#endif

    /* Initialize wolfSSL */
    WOLFSSL_MSG("Start wolfSSL_Init()");
    wolfSSL_Init();

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    WOLFSSL_MSG( "start socket())");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        ESP_LOGE(TAG, "ERROR: failed to create the socket");
    }

    /* Create and initialize WOLFSSL_CTX */
    WOLFSSL_MSG("Create and initialize WOLFSSL_CTX");
#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    // ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());  /* only TLS 1.3 */
    if (ctx == NULL) {
        ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL_CTX");
    }
#else
    /* TODO remove duplicate */
    if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
        ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL_CTX");
    }
#endif

#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    ESP_LOGI(TAG, "Start SM3\n");

    /* Optional set explicit ciphers
    ret = wolfSSL_CTX_set_cipher_list(ctx, WOLFSSL_ESP32_CIPHER_SUITE);
    if (ret == SSL_SUCCESS) {
        ESP_LOGI(TAG, "Set cipher list: "WOLFSSL_ESP32_CIPHER_SUITE"\n");
    }
    else {
        ESP_LOGE(TAG, "ERROR: failed to set cipher list: "WOLFSSL_ESP32_CIPHER_SUITE"\n");
    }
    */
    ShowCiphers(NULL);
    ESP_LOGI(TAG, "Stack used: %d\n", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                      - uxTaskGetStackHighWaterMark(NULL));

    WOLFSSL_MSG("Loading certificate...");
    /* -c Load server certificates into WOLFSSL_CTX */
    ret = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,
                                                          CTX_SERVER_CERT,
                                                          CTX_SERVER_CERT_SIZE,
                                                          CTX_SERVER_CERT_TYPE
                                                         );

/* optional wolfSSL_CTX_use_certificate_buffer
    ret = wolfSSL_CTX_use_certificate_buffer(ctx,
                                             server_sm2,
                                             sizeof_server_sm2,
                                             WOLFSSL_FILETYPE_PEM);
*/
    if (ret == SSL_SUCCESS) {
        ESP_LOGI(TAG, "Loaded server_sm2\n");
    }
    else {
        ESP_LOGE(TAG, "ERROR: failed to load cert\n");
    }
    ESP_LOGI(TAG, "Stack used: %d\n", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                      - uxTaskGetStackHighWaterMark(NULL));

#ifndef NO_DH
    #define DEFAULT_MIN_DHKEY_BITS 1024
    #define DEFAULT_MAX_DHKEY_BITS 2048
    int    minDhKeyBits  = DEFAULT_MIN_DHKEY_BITS;
    ret = wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)minDhKeyBits);
#endif
#ifndef NO_RSA
    #define DEFAULT_MIN_RSAKEY_BITS 1024
    short  minRsaKeyBits = DEFAULT_MIN_RSAKEY_BITS;
    ret = wolfSSL_CTX_SetMinRsaKey_Sz(ctx, minRsaKeyBits);
#endif

    WOLFSSL_MSG("Loading key info...");
    /* -k Load server key into WOLFSSL_CTX */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                                            CTX_SERVER_KEY,
                                            CTX_SERVER_KEY_SIZE,
                                            CTX_SERVER_KEY_TYPE);

    if (ret == SSL_SUCCESS) {
        ESP_LOGI(TAG, "Loaded PrivateKey_buffer server_sm2_priv\n");
    }
    else {
        ESP_LOGE(TAG, "ERROR: failed to load "
                      "PrivateKey_buffer server_sm2_priv\n");
    }
    ESP_LOGI(TAG, "Stack used: %d\n", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                      - uxTaskGetStackHighWaterMark(NULL));
    /* -A load authority */
    ret = wolfSSL_CTX_load_verify_buffer(ctx,
                                         client_sm2,
                                         sizeof_client_sm2,
                                         WOLFSSL_FILETYPE_PEM);
    if (ret == SSL_SUCCESS) {
        ESP_LOGI(TAG, "Success: load verify buffer\n");
    }
    else {
        ESP_LOGE(TAG, "ERROR: failed to load verify buffer\n");
    }
    ESP_LOGI(TAG, "Finish SM2\n");
#else
    WOLFSSL_MSG("Loading certificate...");
    /* Load server certificates into WOLFSSL_CTX */

    if ((ret = wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
                        sizeof_server_cert_der_2048,
                        WOLFSSL_FILETYPE_ASN1)) != SSL_SUCCESS) {
        ESP_LOGE(TAG, "ERROR: failed to load cert");
    }
    WOLFSSL_MSG("Loading key info...");
    /* Load server key into WOLFSSL_CTX */

    if((ret=wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                            server_key_der_2048, sizeof_server_key_der_2048,
                            WOLFSSL_FILETYPE_ASN1)) != SSL_SUCCESS) {
        ESP_LOGE(TAG, "ERROR: failed to load privatekey");
    }

#endif


    /* TODO when using ECDSA,it loads the provisioned certificate and present it.
       TODO when using ECDSA,it uses the generated key instead of loading key  */

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));
    /* Fill in the server address */
    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(TLS_SMP_DEFAULT_PORT); /* on port */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

    /* Bind the server socket to our port */
    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
         ESP_LOGE(TAG, "ERROR: failed to bind");
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(sockfd, 5) == -1) {
         ESP_LOGE(TAG, "ERROR: failed to listen");
    }

#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)
    atcatls_set_callbacks(ctx);
    /* when using a custom slot allocation */
    #if defined(CUSTOM_SLOT_ALLOCATION)
    my_atmel_slotInit();
    atmel_set_slot_allocator(my_atmel_alloc, my_atmel_free);
    #endif
#endif
    ESP_LOGI(TAG, "accept clients...");
    /* Continue to accept clients until shutdown is issued */
    while (!shutdown) {
        ESP_LOGI(TAG, "Stack used: %d\n", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                          - uxTaskGetStackHighWaterMark(NULL));
        WOLFSSL_MSG("Waiting for a connection...");
        wifi_show_ip();

        /* Accept client socket connections */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size))
            == -1) {
             ESP_LOGE(TAG, "ERROR: failed to accept the connection");
        }
        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL object");
        }

        /* show what cipher connected for this WOLFSSL* object */
        ShowCiphers(ssl);

        /* Attach wolfSSL to the socket */
        wolfSSL_set_fd(ssl, connd);
        /* Establish TLS connection */
        ret = wolfSSL_accept(ssl);
        if (ret == SSL_SUCCESS) {
            ShowCiphers(ssl);
        }
        else {
            ESP_LOGE(TAG, "wolfSSL_accept error %d",
                           wolfSSL_get_error(ssl, ret));
        }
        WOLFSSL_MSG("Client connected successfully");
        ESP_LOGI(TAG, "Stack used: %d\n", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                          - uxTaskGetStackHighWaterMark(NULL));

        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));
        if (wolfSSL_read(ssl, buff, sizeof(buff)-1) == -1) {
            ESP_LOGE(TAG, "ERROR: failed to read");
        }
        /* Print to stdout any data the client sends */
        ESP_LOGI(TAG, "Stack used: %d\n", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                          - uxTaskGetStackHighWaterMark(NULL));
        WOLFSSL_MSG("Client sends:");
        WOLFSSL_MSG(buff);
        /* Check for server shutdown command */
        if (strncmp(buff, "shutdown", 8) == 0) {
            WOLFSSL_MSG("Shutdown command issued!");
            shutdown = 1;
        }
        /* Write our reply into buff */
        memset(buff, 0, sizeof(buff));
        memcpy(buff, msg, sizeof(msg));
        len = strnlen(buff, sizeof(buff));
        /* Reply back to the client */
        if (wolfSSL_write(ssl, buff, len) != len) {
            ESP_LOGE(TAG, "ERROR: failed to write");
        }
        /* Cleanup after this connection */
        wolfSSL_free(ssl);      /* Free the wolfSSL object              */
        close(connd);           /* Close the connection to the client   */
    }
    /* Cleanup and return */
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the socket listening for clients   */

    vTaskDelete(NULL);

    return TLS_SMP_SERVER_TASK_RET;
}

#if defined(SINGLE_THREADED)
    /* we don't initialize a thread */
#else
/* create task */
WOLFSSL_ESP_TASK tls_smp_server_init(void* args)
{
#if defined(SINGLE_THREADED)
    #define TLS_SMP_CLIENT_TASK_RET ret
#else
    #define TLS_SMP_CLIENT_TASK_RET
#endif
    int thisPort = 0;
    int ret_i = 0; /* interim return result */
    if (thisPort == 0) {
        thisPort = TLS_SMP_DEFAULT_PORT;
    }

#if ESP_IDF_VERSION_MAJOR >= 4
    TaskHandle_t _handle;
#else
    xTaskHandle _handle;
#endif
    /* http://esp32.info/docs/esp_idf/html/dd/d3c/group__xTaskCreate.html */
    ESP_LOGI(TAG, "Creating tls_smp_server_task with stack size = %d",
                   TLS_SMP_SERVER_TASK_WORDS);
    ret_i = xTaskCreate(tls_smp_server_task,
                      TLS_SMP_SERVER_TASK_NAME,
                      TLS_SMP_SERVER_TASK_WORDS, /* not bytes! */
                      (void*)&thisPort,
                      TLS_SMP_SERVER_TASK_PRIORITY,
                      &_handle);

    if (ret_i != pdPASS) {
        ESP_LOGI(TAG, "create thread %s failed", TLS_SMP_SERVER_TASK_NAME);
    }

    /* vTaskStartScheduler(); // called automatically in ESP-IDF */
    return TLS_SMP_CLIENT_TASK_RET;
}
#endif

