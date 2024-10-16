/* server-tls.c
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
#include <netinet/tcp.h> /* For TCP options */
#include <sys/socket.h>

#ifndef TCP_RTO_MIN
    #define TCP_RTO_MIN 1500
#endif

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/ssl.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif
#if defined(WOLFSSL_WC_KYBER)
    #include <wolfssl/wolfcrypt/kyber.h>
    #include <wolfssl/wolfcrypt/wc_kyber.h>
#endif
#if defined(USE_CERT_BUFFERS_2048) || defined(USE_CERT_BUFFERS_1024)
    #include <wolfssl/certs_test.h>
#endif
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
#if 0
    /* optionally set TCP RTO. See also below. */
    int rto_min = 200; /* Minimum TCP RTO in milliseconds */
#endif
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

    /* Optionally set TCP RTO
    setsockopt(sockfd, IPPROTO_TCP, TCP_RTO_MIN, &rto_min, sizeof(rto_min)); */

    /* Create and initialize WOLFSSL_CTX */
    WOLFSSL_MSG("Create and initialize WOLFSSL_CTX");
#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    /* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()); for only TLS 1.3 */
    if (ctx == NULL) {
        ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL_CTX");
    }
#else
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
#ifdef WOLFSSL_EXAMPLE_VERBOSITY
    ESP_LOGI(TAG, "Initial stack used: %d\n",
             TLS_SMP_SERVER_TASK_BYTES  - uxTaskGetStackHighWaterMark(NULL) );
#endif
    ESP_LOGI(TAG, "accept clients...");
    /* Continue to accept clients until shutdown is issued */
    while (!shutdown) {
        WOLFSSL_MSG("Waiting for a connection...");
#if ESP_IDF_VERSION_MAJOR >=4
        /* TODO: IP Address is problematic in RTOS SDK 3.4 */
        wifi_show_ip();
#endif
        /* Accept client socket connections */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size))
            == -1) {
             ESP_LOGE(TAG, "ERROR: failed to accept the connection");
        }
#if defined(WOLFSSL_EXPERIMENTAL_SETTINGS)
        ESP_LOGW(TAG, "WOLFSSL_EXPERIMENTAL_SETTINGS is enabled");
#endif
        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL object");
        }
#if defined(WOLFSSL_HAVE_KYBER)
        else {
            /* If success creating CTX and Kyber enabled, set key share: */
            ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_P521_KYBER_LEVEL5);
            if (ret == SSL_SUCCESS) {
                ESP_LOGI(TAG, "UseKeyShare WOLFSSL_P521_KYBER_LEVEL5 success");
            }
            else {
                ESP_LOGE(TAG, "UseKeyShare WOLFSSL_P521_KYBER_LEVEL5 failed");
            }
        }
#else
        ESP_LOGI(TAG, "WOLFSSL_HAVE_KYBER is not enabled, not using PQ.");
#endif
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
        ESP_LOGI(TAG, "Client connected successfully");

        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));
        if (wolfSSL_read(ssl, buff, sizeof(buff)-1) == -1) {
            ESP_LOGE(TAG, "ERROR: failed to read");
        }

        ESP_LOGI(TAG, "Client sends: %s", buff);
        /* Check for server shutdown command */
        if (strncmp(buff, "shutdown", 8) == 0) {
            ESP_LOGI(TAG, "Shutdown command issued!");
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

        ESP_LOGI(TAG, "Done! Cleanup...");
        /* Cleanup after this connection */
        wolfSSL_free(ssl);      /* Free the wolfSSL object              */
        close(connd);           /* Close the connection to the client   */
#ifdef WOLFSSL_EXAMPLE_VERBOSITY
        ESP_LOGI(TAG, "Stack used: %d\n",
                TLS_SMP_SERVER_TASK_BYTES - uxTaskGetStackHighWaterMark(NULL));
#endif
    } /* !shutdown */
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
    /* Note that despite vanilla FreeRTOS using WORDS for a parameter,
     * Espressif uses BYTES for the task stack size here. */
    ESP_LOGI(TAG, "Creating tls_smp_server_task with stack size = %d",
                   TLS_SMP_SERVER_TASK_BYTES);
    ret_i = xTaskCreate(tls_smp_server_task,
                      TLS_SMP_SERVER_TASK_NAME,
                      TLS_SMP_SERVER_TASK_BYTES,
                      (void*)&thisPort,
                      TLS_SMP_SERVER_TASK_PRIORITY,
                      &_handle);

    if (ret_i != pdPASS) {
        ESP_LOGI(TAG, "create thread %s failed", TLS_SMP_SERVER_TASK_NAME);
    }

    /* vTaskStartScheduler();  called automatically in ESP-IDF */
    return TLS_SMP_CLIENT_TASK_RET;
}
#endif

