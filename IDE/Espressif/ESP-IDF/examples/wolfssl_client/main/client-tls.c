/* client-tls.c
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

#include "client-tls.h"

/* Espressif FreeRTOS */
#ifndef SINGLE_THREADED
    #include <freertos/FreeRTOS.h>
    #include <freertos/task.h>
    #include <freertos/event_groups.h>
#endif

/* Espressif */
#include <esp_log.h>

/* socket includes */
#include <lwip/netdb.h>
#include <lwip/sockets.h>

/* wolfSSL */
#include <wolfssl/wolfcrypt/settings.h>
/* This project not yet using the library */
#undef USE_WOLFSSL_ESP_SDK_WIFI
#include <wolfssl/ssl.h>

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

/* working TLS 1.2 VS client app commandline param:
 *
 *  -h 192.168.1.128 -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3  -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C
 *
 * working Linux, non-working VS c app
 *
 *  -h 192.168.1.128 -v 4 -l TLS13-SM4-CCM-SM3        -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C
 *
 **/
#define TAG "client-tls"

#if defined(DEBUG_WOLFSSL)
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
            ESP_LOGE(TAG, "Failed to call wolfSSL_get_ciphers. Error %d", ret);
        }
    }
    else {
        cipher_used = wolfSSL_get_cipher_name(ssl);
        ESP_LOGI(TAG, "WOLFSSL* ssl using %s", cipher_used);
    }

    return ret;
}

#endif

#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)

#include "wolfssl/wolfcrypt/port/atmel/atmel.h"

/* when you want to use custom slot allocation */
/* enable the definition CUSTOM_SLOT_ALLOCATION.*/

#if defined(CUSTOM_SLOT_ALLOCATION)

static byte mSlotList[ATECC_MAX_SLOT];

int atmel_set_slot_allocator(atmel_slot_alloc_cb alloc,
                             atmel_slot_dealloc_cb dealloc);
/* initialize slot array */
void my_atmel_slotInit()
{
    int i;

    for (i = 0; i < ATECC_MAX_SLOT; i++) {
        mSlotList[i] = ATECC_INVALID_SLOT;
    }
}
/* allocate slot depending on slotType */
int my_atmel_alloc(int slotType)
{
    int i, slot = -1;

    switch (slotType) {
        case ATMEL_SLOT_ENCKEY:
            slot = 2;
            break;
        case ATMEL_SLOT_DEVICE:
            slot = 0;
            break;
        case ATMEL_SLOT_ECDHE:
            slot = 0;
            break;
        case ATMEL_SLOT_ECDHE_ENC:
            slot = 4;
            break;
        case ATMEL_SLOT_ANY:
            for (i = 0; i < ATECC_MAX_SLOT; i++) {
                if (mSlotList[i] == ATECC_INVALID_SLOT) {
                    slot = i;
                    break;
                }
            }
    }

    return slot;
}
/* free slot array       */
void my_atmel_free(int slotId)
{
    if (slotId >= 0 && slotId < ATECC_MAX_SLOT) {
        mSlotList[slotId] = ATECC_INVALID_SLOT;
    }
}
#endif /* CUSTOM_SLOT_ALLOCATION */
#endif /* WOLFSSL_ESPWROOM32SE && HAVE_PK_CALLBACK && WOLFSSL_ATECC508A */

/* client task */
WOLFSSL_ESP_TASK tls_smp_client_task(void* args)
{
#if defined(SINGLE_THREADED)
    int ret = ESP_OK;
    #define TLS_SMP_CLIENT_TASK_RET ret
#else
    #define TLS_SMP_CLIENT_TASK_RET
#endif
    char buff[256];
    const char sndMsg[] = "GET /index.html HTTP/1.0\r\n\r\n";
    const char* ch = TLS_SMP_TARGET_HOST; /* see wifi_connect.h */
    struct sockaddr_in servAddr;

    struct hostent *hp;
    struct ip4_addr *ip4_addr;
    int ret_i; /* interim return values */
    int err; /* interim return values */
    int sockfd;
    int doPeerCheck;
    int sendGet;
#ifdef DEBUG_WOLFSSL
    int this_heap = 0;
#endif
#ifndef NO_DH
    int minDhKeyBits = DEFAULT_MIN_DHKEY_BITS;
#endif

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

    size_t len;

    WOLFSSL_ENTER(TLS_SMP_CLIENT_TASK_NAME);

    doPeerCheck = 1;
    sendGet = 0;

#ifdef DEBUG_WOLFSSL
    WOLFSSL_MSG("Debug ON");
    ShowCiphers(NULL);
#endif
    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        ESP_LOGE(TAG, "ERROR: failed to create the socket\n");
    }

    ESP_LOGI(TAG, "get target IP address");

    hp = gethostbyname(TLS_SMP_TARGET_HOST);
    if (!hp) {
        ESP_LOGE(TAG, "Failed to get host name.");
        ip4_addr = NULL;
    }
    else {
        ip4_addr = (struct ip4_addr *)hp->h_addr;
    }

    /* Create and initialize WOLFSSL_CTX */
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()); /* SSL 3.0 - TLS 1.3. */
    /*   options:   */
    /* ctx = wolfSSL_CTX_new(wolfSSLv1_2_client_method());      only TLS 1.2 */
    /* ctx = wolfSSL_CTX_new(wolfSSLv1_3_client_method());      only TLS 1.3 */
    /* wolfSSL_CTX_NoTicketTLSv12(); */
    /* wolfSSL_NoTicketTLSv12();     */
    if (ctx == NULL) {
        ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL_CTX\n");
    }

#if defined(WOLFSSL_ESP32_CIPHER_SUITE)
    ESP_LOGI(TAG, "Start SM2\n");

/*
 *
 * reference code for SM Ciphers:
 *
    #if defined(HAVE_AESGCM) && !defined(NO_DH)
        #ifdef WOLFSSL_TLS13
            defaultCipherList = "TLS13-AES128-GCM-SHA256"
            #ifndef WOLFSSL_NO_TLS12
                                ":DHE-PSK-AES128-GCM-SHA256"
            #endif
            ;
        #else
            defaultCipherList = "DHE-PSK-AES128-GCM-SHA256";
        #endif
    #elif defined(HAVE_AESGCM) && defined(WOLFSSL_TLS13)
            defaultCipherList = "TLS13-AES128-GCM-SHA256:PSK-AES128-GCM-SHA256"
            #ifndef WOLFSSL_NO_TLS12
                                ":PSK-AES128-GCM-SHA256"
            #endif
            ;
    #elif defined(HAVE_NULL_CIPHER)
            defaultCipherList = "PSK-NULL-SHA256";
    #elif !defined(NO_AES_CBC)
            defaultCipherList = "PSK-AES128-CBC-SHA256";
    #else
            defaultCipherList = "PSK-AES128-GCM-SHA256";
    #endif
*/

    ret = wolfSSL_CTX_set_cipher_list(ctx, WOLFSSL_ESP32_CIPHER_SUITE);
    if (ret == WOLFSSL_SUCCESS) {
        ESP_LOGI(TAG, "Set cipher list: %s\n", WOLFSSL_ESP32_CIPHER_SUITE);
    }
    else {
        ESP_LOGE(TAG, "ERROR: failed to set cipher list: %s\n",
                       WOLFSSL_ESP32_CIPHER_SUITE);
    }
#endif

#ifdef DEBUG_WOLFSSL
    ShowCiphers(NULL);
    ESP_LOGI(TAG, "Stack used: %d\n",
                   CONFIG_ESP_MAIN_TASK_STACK_SIZE
                   - uxTaskGetStackHighWaterMark(NULL));
#endif

/* see user_settings PROJECT_DH for HAVE_DH and HAVE_FFDHE_2048 */
#ifndef NO_DH
    ret_i = wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)minDhKeyBits);
     if (ret_i != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "Error setting minimum DH key size");
    }
#endif

    /* no peer check */
    if (doPeerCheck == 0) {
        ESP_LOGW(TAG, "doPeerCheck == 0; WOLFSSL_VERIFY_NONE");
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);
    }
    else {
        ESP_LOGI(TAG, "doPeerCheck != 0");
        WOLFSSL_MSG("Loading... our cert");
        /* load our certificate */
        ret_i = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,
                                         CTX_CLIENT_CERT,
                                         CTX_CLIENT_CERT_SIZE,
                                         CTX_CLIENT_CERT_TYPE);
        if (ret_i != WOLFSSL_SUCCESS) {
            ESP_LOGE(TAG, "ERROR: failed to load our cert chain %d, "
                          "please check the file.", ret_i);
        }

        /* Load client certificates into WOLFSSL_CTX */
        WOLFSSL_MSG("Loading... CA cert");
        ret_i = wolfSSL_CTX_load_verify_buffer(ctx,
                                         CTX_CA_CERT,
                                         CTX_CA_CERT_SIZE,
                                         CTX_CA_CERT_TYPE);
        if (ret_i != WOLFSSL_SUCCESS) {
            ESP_LOGE(TAG, "ERROR: failed to load CA cert %d, "
                          "please check the file.\n", ret_i) ;
        }

        WOLFSSL_MSG("Loading... our key");
        ret_i = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                                         CTX_CLIENT_KEY,
                                         CTX_CLIENT_KEY_SIZE,
                                         CTX_CLIENT_KEY_TYPE);
        if (ret_i != WOLFSSL_SUCCESS) {
            ESP_LOGE(TAG, "ERROR: failed to load key %d, "
                          "please check the file.\n", ret_i) ;
        }

        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, 0);
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET; /* using IPv4      */
    servAddr.sin_port = htons(TLS_SMP_DEFAULT_PORT); /* on DEFAULT_PORT */

    if (*ch >= '1' && *ch <= '9') {
        /* Get the server IPv4 address from the command line call */
        WOLFSSL_MSG("inet_pton");
        if ((ret_i = inet_pton(AF_INET,
                             TLS_SMP_TARGET_HOST,
                             &servAddr.sin_addr)) != 1) {
            ESP_LOGE(TAG, "ERROR: invalid address ret=%d\n", ret_i);
        }
    }
    else {
        servAddr.sin_addr.s_addr = ip4_addr->addr;
    }

    /* Connect to the server */
    sprintf(buff,
            "Connecting to server....%s (port:%d)",
            TLS_SMP_TARGET_HOST,
            TLS_SMP_DEFAULT_PORT);
    ESP_LOGI(TAG, "%s\n", buff);

    if ((ret_i = connect(sockfd,
                       (struct sockaddr *)&servAddr,
                       sizeof(servAddr))) == -1) {
        ESP_LOGE(TAG, "ERROR: failed to connect ret=%d\n", ret_i);
    }

#if defined(WOLFSSL_EXPERIMENTAL_SETTINGS)
        ESP_LOGW(TAG, "WOLFSSL_EXPERIMENTAL_SETTINGS is enabled");
#endif

    WOLFSSL_MSG("Create a WOLFSSL object");
    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL object\n");
    }
    else {
#ifdef DEBUG_WOLFSSL
        ESP_LOGI(TAG, "\nCreated WOLFSSL object:");
        ShowCiphers(ssl);
        this_heap = esp_get_free_heap_size();
        ESP_LOGI(TAG, "tls_smp_client_task heap @ %p = %d",
                      &this_heap, this_heap);
#endif
#if defined(WOLFSSL_HAVE_KYBER)
    #if defined(WOLFSSL_KYBER1024)
        ESP_LOGI(TAG, "WOLFSSL_HAVE_KYBER is enabled, setting key share: "
                                        "WOLFSSL_P256_KYBER_LEVEL5");
        ret_i = wolfSSL_UseKeyShare(ssl, WOLFSSL_P521_KYBER_LEVEL5);
    #elif defined(WOLFSSL_KYBER768)
        ESP_LOGI(TAG, "WOLFSSL_HAVE_KYBER is enabled, setting key share: "
                                        "WOLFSSL_P256_KYBER_LEVEL3");
        ret_i = wolfSSL_UseKeyShare(ssl, WOLFSSL_P256_KYBER_LEVEL3);
    #elif defined(WOLFSSL_KYBER512)
        /* This will typically be a low memory situation, such as ESP8266 */
        ESP_LOGI(TAG, "WOLFSSL_HAVE_KYBER is enabled, setting key share: "
                                        "WOLFSSL_P256_KYBER_LEVEL1");
        ret_i = wolfSSL_UseKeyShare(ssl, WOLFSSL_P256_KYBER_LEVEL1);
    #else
        ESP_LOGW(TAG, "WOLFSSL_HAVE_KYBER enabled but no key size available.");
        ret_i = ESP_FAIL;
    #endif
        if (ret_i == WOLFSSL_SUCCESS) {
            ESP_LOGI(TAG, "UseKeyShare Kyber success");
        }
        else {
            ESP_LOGE(TAG, "UseKeyShare Kyber failed");
        }
#else
    ESP_LOGI(TAG, "WOLFSSL_HAVE_KYBER is not enabled");
#endif
    }

#if defined(WOLFSSL_SM2)
    /* SM TLS1.3 Cipher needs to have key share explicitly set. */
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_SM2P256V1);
    if (ret == WOLFSSL_SUCCESS) {
        ESP_LOGI(TAG, "Successfully set WOLFSSL_ECC_SM2P256V1");
    }
    else {
        ESP_LOGE(TAG, "FAILED to set WOLFSSL_ECC_SM2P256V1");
    }
#endif
        /* when using atecc608a on esp32-wroom-32se */

#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)
    atcatls_set_callbacks(ctx);
    /* when using custom slot-allocation */
    #if defined(CUSTOM_SLOT_ALLOCATION)
    my_atmel_slotInit();
    atmel_set_slot_allocator(my_atmel_alloc, my_atmel_free);
    #endif
#endif
#ifdef DEBUG_WOLFSSL
        this_heap = esp_get_free_heap_size();
        ESP_LOGI(TAG, "tls_smp_client_task heap(2) @ %p = %d",
                      &this_heap, this_heap);
#endif
    /* Attach wolfSSL to the socket */
    ret_i = wolfSSL_set_fd(ssl, sockfd);
    if (ret_i == WOLFSSL_SUCCESS) {
        ESP_LOGI(TAG, "wolfSSL_set_fd success");
    }
    else {
        ESP_LOGE(TAG, "ERROR: failed wolfSSL_set_fd. Error: %d\n", ret_i);
    }

    ESP_LOGI(TAG, "Connect to wolfSSL server...");
    #ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
    #endif
    ret_i = wolfSSL_connect(ssl);
#ifdef DEBUG_WOLFSSL
    this_heap = esp_get_free_heap_size();
    ESP_LOGI(TAG, "tls_smp_client_task heap(3) @ %p = %d",
                    &this_heap, this_heap);
#endif
    if (ret_i == WOLFSSL_SUCCESS) {
#ifdef DEBUG_WOLFSSL
        ShowCiphers(ssl);
#endif
        ESP_LOGI(TAG, "Connect success! Sending message...");
        /* Get a message for the server from stdin */
        WOLFSSL_MSG("Message for server: ");
        memset(buff, 0, sizeof(buff));

        if (sendGet) {
            len = XSTRLEN(sndMsg);
            strncpy(buff, sndMsg, len);
        }
        else {
            sprintf(buff, "Hello from Espressif wolfSSL TLS client!\n");
            len = strnlen(buff, sizeof(buff));
        }
        buff[len] = '\0';
        ESP_LOGI(TAG, "SSL connect ok, sending message:\n\n%s\n", buff);

        /* Send the message to the server */
        do {
            err = 0; /* reset error */
            ret_i = wolfSSL_write(ssl, buff, len);
            if (ret_i <= 0) {
                err = wolfSSL_get_error(ssl, 0);
            }
        } while (err == WOLFSSL_ERROR_WANT_WRITE ||
                 err == WOLFSSL_ERROR_WANT_READ);

        if (ret_i != len) {
            ESP_LOGE(TAG, "ERROR: failed to write\n");
        }
        else {
            ESP_LOGI(TAG, "Message sent! Awaiting response...");
        }

        /* Read the server data into our buff array */
        memset(buff, 0, sizeof(buff));

        do {
            err = 0; /* reset error */
            ret_i =wolfSSL_read(ssl, buff, sizeof(buff));
            if (ret_i <= 0) {
                err = wolfSSL_get_error(ssl, 0);
            }
        } while ((err == WOLFSSL_ERROR_WANT_READ) ||
                 (err == WOLFSSL_ERROR_WANT_WRITE) );

        if (ret_i < 0) {
            ESP_LOGE(TAG, "ERROR: failed to read\n");
        }

        /* Show any data the server sends */
        ESP_LOGI(TAG, "Server response: \n\n%s\n", buff);

        ret_i = wolfSSL_shutdown(ssl);
        while (ret_i == WOLFSSL_SHUTDOWN_NOT_DONE) {
            ret_i = wolfSSL_shutdown(ssl); /* bidirectional shutdown */
            if (ret_i == WOLFSSL_SUCCESS) {
                ESP_LOGI(TAG, "Bidirectional shutdown complete\n");
                break;
            }
            else if (ret_i != WOLFSSL_SHUTDOWN_NOT_DONE) {
                ESP_LOGE(TAG, "Bidirectional shutdown failed\n");
                break;
            }
        }
        if (ret_i != WOLFSSL_SUCCESS) {
            ESP_LOGE(TAG, "Bidirectional shutdown failed\n");
        }

    } /* wolfSSL_connect(ssl) == WOLFSSL_SUCCESS) */
    else {
        ESP_LOGE(TAG, "ERROR: failed to connect to wolfSSL. "
                      "Error: %d\n", ret_i);
    }
#ifdef DEBUG_WOLFSSL
    ShowCiphers(ssl);
#endif

    ESP_LOGI(TAG, "Cleanup and exit");
    wolfSSL_free(ssl);     /* Release the wolfSSL object memory        */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(sockfd);         /* Close the connection to the server       */

    vTaskDelete(NULL);

    return TLS_SMP_CLIENT_TASK_RET;
}

#if defined(SINGLE_THREADED)
    /* we don't initialize a single thread, so no init function here */
#else
/* create task */
WOLFSSL_ESP_TASK tls_smp_client_init(void* args)
{
    int ret;
#if ESP_IDF_VERSION_MAJOR >= 4
    TaskHandle_t _handle;
#else
    xTaskHandle _handle;
#endif
    /* See Espressif api-reference/system/freertos_idf.html#functions  */
    if (TLS_SMP_CLIENT_TASK_BYTES < (6 * 1024)) {
        /* Observed approximately 6KB limit for the RTOS task stack size.
         * Reminder parameter is bytes, not words as with generic FreeRTOS. */
        ESP_LOGW(TAG, "Warning: TLS_SMP_CLIENT_TASK_BYTES < 6KB");
    }
#ifndef WOLFSSL_SMALL_STACK
    ESP_LOGW(TAG, "WARNING: WOLFSSL_SMALL_STACK is not defined. Consider "
                  "defining that to reduce embedded memory usage.");
#endif

    /* Note that despite vanilla FreeRTOS using WORDS for a parameter,
     * Espressif uses BYTES for the task stack size here. */
    ret = xTaskCreate(tls_smp_client_task,
                      TLS_SMP_CLIENT_TASK_NAME,
                      TLS_SMP_CLIENT_TASK_BYTES,
                      NULL,
                      TLS_SMP_CLIENT_TASK_PRIORITY,
                      &_handle);

    if (ret != pdPASS) {
        ESP_LOGI(TAG, "Create thread %s failed.", TLS_SMP_CLIENT_TASK_NAME);
    }
    return TLS_SMP_CLIENT_TASK_RET;
}
#endif
