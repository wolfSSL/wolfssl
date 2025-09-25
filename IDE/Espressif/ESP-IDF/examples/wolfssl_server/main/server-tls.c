/* server-tls.c
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

#include "server-tls.h"

#define MY_PEER_VERIFY 1

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
#include <netinet/tcp.h> /* For TCP options */
#include <sys/socket.h>

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
    #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif
#if defined(WOLFSSL_WC_MLKEM)
    #include <wolfssl/wolfcrypt/mlkem.h>
    #include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif

/* The default user_settings.h includes macros that reference sample certs: */
#if defined(USE_CERT_BUFFERS_2048) || defined(USE_CERT_BUFFERS_1024) || \
    defined(USE_CERT_BUFFERS_256)
    #include <wolfssl/certs_test.h>
#endif
#if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
    #include <wolfssl/certs_test_sm.h>
#endif
/* Some older versions don't have cert name strings, so set to blanks: */
#ifndef CTX_CLIENT_CERT_NAME
    #define CTX_CLIENT_CERT_NAME ""
#endif
#ifndef CTX_SERVER_KEY_NAME
    #define CTX_SERVER_KEY_NAME ""
#endif
#ifndef CTX_SERVER_CERT_NAME
    #define CTX_SERVER_CERT_NAME ""
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

/* Optional experimental static memory to consider. See docs. */
#if defined(WOLFSSL_STATIC_MEMORY)
    #include <wolfssl/wolfcrypt/memory.h>
    #define MAX_CONNS 1
    #define MAX_CONCURRENT_HANDSHAKES 1
    /* multiple of 16 & 32 */
    /* #define WOLFMEM_IO_SZ 2048 */


    /* 2 fixed + 2 spare */
    #define IO_BLOCKS_PER_CONN 4
    #if defined(WOLFSSL_LOW_MEMORY)
        /* handshake, certs, math temps */
        #define GEN_POOL_SZ  (72 * 1024)
        /* if using MFL=512 -> ~2x ~660B; round up */
        #define IO_POOL_SZ (WOLFMEM_IO_SZ * IO_BLOCKS_PER_CONN * MAX_CONNS)
        /* #define IO_POOL_SZ   ((2 * WOLFMEM_IO_SZ * MAX_CONNS) * 4) */
    #else
        /* handshake, certs, math temps */
        #define GEN_POOL_SZ  (60 * 1024)
        /* if using MFL=512 -> ~2x ~660B; round up */
        #define IO_POOL_SZ   (2 * 720)
    #endif
    #if (GEN_POOL_SZ % 32) != 0
        #error "GEN_POOL_SZ must be 32-byte aligned with WOLFMEM_IO_POOL_FIXED"
    #endif
    #if (WOLFMEM_IO_SZ % 32) != 0
        #error "WOLFMEM_IO_SZ must be 32-byte aligned with WOLFMEM_IO_POOL_FIXED"
    #endif
    static __attribute__((aligned(32))) uint8_t genPool[GEN_POOL_SZ];
    static __attribute__((aligned(32))) uint8_t ioPool [IO_POOL_SZ];
#endif

/*
 * Optionally define explicit ciphers, for example these TLS 1.3 options.
 *
 * TLS13-AES128-GCM-SHA256
 * TLS13-AES256-GCM-SHA384
 * TLS13-AES128-CCM-SHA256
 * TLS13-AES128-CCM-8-SHA256
 * TLS13-AES128-CCM8-SHA256
 *
 * examples:
 * #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-AES128-GCM-SHA256:PSK-AES128-GCM-SHA256"
 * #define WOLFSSL_ESP32_CIPHER_SUITE "TLS13-AES128-CCM-8-SHA256"
 */


static const char* const TAG = "server-tls";
int stack_start = -1;

int ShowCiphers(WOLFSSL* ssl)
{
    #define CLIENT_TLS_MAX_CIPHER_LENGTH 4096
    char ciphers[CLIENT_TLS_MAX_CIPHER_LENGTH];
    const char* cipher_used;
    int ret = 0;

    if (ssl == NULL) {
        ESP_LOGI(TAG, "WOLFSSL* ssl is NULL, so no cipher in use yet.");
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
        ESP_LOGI(TAG, "checking  %p", ssl);
        cipher_used = wolfSSL_get_cipher_name(ssl);
        ESP_LOGI(TAG, "WOLFSSL* ssl using %s", cipher_used);
    }

    return ret;
}

static void halt_for_reboot(const char* s)
{
    ESP_LOGE(TAG, "Halt. %s", s);
    while (1) {
        vTaskDelay(60000);
    }
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
    int                ret_i; /* interim return values */
    int                reset_heap = 0;
    socklen_t          size = sizeof(clientAddr);
    size_t             len;
    size_t             success_ct = 0; /* number of client connect successes */
    size_t             failure_ct = 0; /* number of client connect failures  */

    /* declare wolfSSL objects */
    WOLFSSL_CTX*      ctx;
    WOLFSSL*          ssl;
#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_NO_MALLOC)
    size_t            this_heap = 0;
#endif

#if defined(CONFIG_ESP_WOLFSSL_TCP_REUSE) && (CONFIG_ESP_WOLFSSL_TCP_REUSE > 0)
    /* optionally set TCP reuse. See also below. */
    int tcp_reuse = 1;
#endif

    WOLFSSL_ENTER("tls_smp_server_task");

#ifdef DEBUG_WOLFSSL
    /* Turn debugging off as needed: */
    wolfSSL_Debugging_OFF();
    wolfSSL_Debugging_ON();
    ShowCiphers(NULL);
#endif

#if defined(SINGLE_THREADED)
    /* No startup delay */
#else
    /* Brief delay to allow the main task to be deleted and free memory. */
    vTaskDelay(100);
#endif

    /* Initialize wolfSSL */
    ESP_LOGI(TAG, "Start wolfSSL_Init()");
    ret_i = wolfSSL_Init();
    if (ret_i != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "Failed to initialize wolfSSL");
    }

    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    WOLFSSL_MSG( "start socket())");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1) {
        halt_for_reboot("ERROR: failed to create the socket");
    }

    /* Optionally set TCP Socket Reuse. */
#if defined(CONFIG_ESP_WOLFSSL_TCP_REUSE) && (CONFIG_ESP_WOLFSSL_TCP_REUSE > 0)
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tcp_reuse, sizeof(tcp_reuse));
#ifdef SO_REUSEPORT   /* not always available on lwIP */
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &tcp_reuse, sizeof(tcp_reuse));
#endif /* SO_REUSEPORT        */
#endif /* optional TCP reuse */

    /* Create and initialize WOLFSSL_CTX */
    WOLFSSL_MSG("Create and initialize WOLFSSL_CTX");
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_LOW_MEMORY)
    ESP_LOGW(TAG, "Warning: TLS 1.3 enabled on low-memory device.");
#endif
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_NO_TLS12)
    ESP_LOGW(TAG, "Creating TLS 1.3 (only) server context...");
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#elif defined(WOLFSSL_TLS13)
    ESP_LOGI(TAG, "Creating TLS (1.2 or 1.3) server context...");
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
#else
    ESP_LOGW(TAG, "Creating TLS 1.2 (only) server context...");
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#endif /* TLS 1.2 or TLS 1.3 */
    if (ctx == NULL) {
        halt_for_reboot("ERROR: failed to create wolfSSL ctx");
    }


    // TODO Begin fix or remove
    /* There's some temporary, non-working static memory */

#ifndef NO_WOLFSSL_CLIENT
    ret = wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_9);
    if (ret == WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_CTX_UseMaxFragment success");
    }
    else {
        halt_for_reboot("ERROR: failed wolfSSL_CTX_UseMaxFragment");
    }
#endif

#if 0
    WOLFSSL_MSG("memory success, create gen pool");
    ret = wolfSSL_CTX_load_static_memory(&ctx,
        wolfTLSv1_2_server_method_ex,
        genPool, GEN_POOL_SZ,
        WOLFMEM_GENERAL,                  /* general pool */
        MAX_CONNS);
    if (ret != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "ERROR: failed to create static memory WOLFSSL_CTX");
    }
    else {
        WOLFSSL_MSG("wolfSSL_CTX_load_static_memory success");
    }
#endif

#if defined(WOLFSSL_STATIC_MEMORY)
    WOLFSSL_HEAP_HINT* heap = NULL;
    ret = wc_LoadStaticMemory(&heap, genPool, sizeof(genPool),
                            WOLFMEM_GENERAL, MAX_CONNS);
    if (ret == 0) {
        WOLFSSL_MSG("wc_LoadStaticMemory success");
        /* default heap for any NULL-heap calls */
        wolfSSL_SetGlobalHeapHint(heap);
    }
    else {
        ESP_LOGE(TAG, "ERROR: failed to create static memory heap");
    }

    const WOLFSSL_METHOD* method = wolfTLSv1_2_server_method_ex(heap);
    ctx = wolfSSL_CTX_new_ex((WOLFSSL_METHOD*)method, heap);
    if (ctx == NULL) {
        halt_for_reboot("ERROR: failed to create ctx on static heap");
    }

    ret = wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");
    if (ret == WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_CTX_set_cipher_list  success");
    }
    else {
        halt_for_reboot("ERROR: failed wolfSSL_CTX_set_cipher_list");
    }

    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL,
                                            ioPool, IO_POOL_SZ,
                            WOLFMEM_IO_POOL_FIXED | WOLFMEM_TRACK_STATS,
                                            MAX_CONNS);
    if (ret == WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_CTX_load_static_memory IO Pool success");
    }
    else {
        halt_for_reboot("ERROR: failed to create static memory heap");
    }
    /*
        #define WOLFMEM_GENERAL       0x01
        #define WOLFMEM_IO_POOL       0x02
        #define WOLFMEM_IO_POOL_FIXED 0x04
        #define WOLFMEM_TRACK_STATS   0x08
      **/
#else

#endif /* ctx via heap or WOLFSSL_STATIC_MEMORY */

#if defined(USE_CERT_BUFFERS_1024)
    /* The x1024 test certs are in current user_settings.h, but not default.
     * Smaller certs are typically used with smaller RAM devices.(ESP8266)
     * Example client will need explicit params:
     *   ./examples/client/client -h 192.168.1.48  -p 11111 -v 3  \
     *                            -A ./certs/1024/ca-cert.pem     \
     *                            -c ./certs/1024/client-cert.pem \
     *                            -k ./certs/1024/client-key.pem -d
     */
    ESP_LOGW(TAG, "Example certificates USE_CERT_BUFFERS_1024 (not default)");
#endif
#if defined(USE_CERT_BUFFERS_2048)
    /* Anything other than this x2048 default is a warning or error.
     *
     * Example TLS 1.2 client with default build does not need explicit cert:
     *   ./examples/client/client -h 192.168.1.47  -p 11111 -v 3
     *
     * Example TLS 1.3 client:
     *   ./examples/client/client -h 192.168.1.47  -p 11111 -v 4
     */
    ESP_LOGI(TAG, "Example certificates USE_CERT_BUFFERS_2048");
#endif
#if defined(USE_CERT_BUFFERS_3072)
    /* The x3072 test certs are not in current user_settings.h */
    ESP_LOGE(TAG, "Example certificates USE_CERT_BUFFERS_3072 (not default)");
#endif
#if defined(USE_CERT_BUFFERS_4096)
    /* The x3072 test certs are not in current user_settings.h */
    ESP_LOGE(TAG, "Example certificates USE_CERT_BUFFERS_4096 (not default)");
#endif

#if (0)
        /* Optionally disable CRL checks */
        wolfSSL_CTX_DisableCRL(ctx);
#endif

#if (0)
    #if defined(WOLFSSL_SM2) || defined(WOLFSSL_SM3) || defined(WOLFSSL_SM4)
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
    #endif
#endif

#if (0)
    wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_3);
    wolfSSL_CTX_set_cipher_list(ctx, "TLS13-SM4-GCM-SM3");
#endif

    /* Identify certificates used, typically in wolfssl/certs_test[_sm].h */
    ESP_LOGI(TAG, "Loading server certificate %s", CTX_SERVER_CERT_NAME);
    /* Load server certificates into WOLFSSL_CTX, to send to client */
    ret = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,
                                                          CTX_SERVER_CERT,
                                                          CTX_SERVER_CERT_SIZE,
                                                          CTX_SERVER_CERT_TYPE);
    if (ret != SSL_SUCCESS) {
        /* Always clean up when errors encountered */
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
        halt_for_reboot("ERROR: failed to load cert");
    }

    ESP_LOGI(TAG, "Loading server key %s",  CTX_SERVER_KEY_NAME);
    /* Load server key into WOLFSSL_CTX */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                                            CTX_SERVER_KEY,
                                            CTX_SERVER_KEY_SIZE,
                                            CTX_SERVER_KEY_TYPE);
    if (ret != SSL_SUCCESS) {
        /* Always clean up when errors encountered */
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
        halt_for_reboot("ERROR: failed to load privatekey");
    }

#if defined(MY_PEER_VERIFY) && MY_PEER_VERIFY
    #if defined(USE_CERT_BUFFERS_256) && !defined(sizeof_server_ecc_cert)
        /* Currently there are only DER format ECC examples in certs_test.h so
         * only a leaf cert is available.
         *
         * Use a PEM for leaf + CA
         * or disable peer verification */
        #error "Peer verify not available for ECC USE_CERT_BUFFERS_256"
    #endif

    ESP_LOGI(TAG, "Set verify: verify peer, fail if no peer...");

    wolfSSL_CTX_set_verify(ctx,
                                (WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                                 WOLFSSL_VERIFY_PEER),
                                NULL);
    /* -A */
    ESP_LOGI(TAG, "Load verify cert %s", CTX_CLIENT_CERT_NAME);
    ret = wolfSSL_CTX_load_verify_buffer(ctx,
                                         CTX_CLIENT_CERT,
                                         CTX_CLIENT_CERT_SIZE,
                                         CTX_CLIENT_CERT_TYPE);
    if (ret != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
        halt_for_reboot("ERROR: failed to load wolfSSL_CTX_load_verify_buffer");
    }
#else
    ESP_LOGI(TAG, "CTX SSL_VERIFY_NONE");
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
#endif


/* TODO cleanup:
 * ./examples/client/client -h 192.168.1.107 -v 3   -l ECDHE-ECDSA-SM4-CBC-SM3   -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem   -A ./certs/sm2/ca-sm2.pem -C
   ./examples/client/client -v 3 -l  ECDHE-ECDSA-SM4-CBC-SM3  -h 192.168.1.107   -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem   -A ./certs/sm2/root-sm2.pem -C

./examples/client/client -v 4  -l  "$CIPHER"  -h 192.168.1.107  -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem  -A ./certs/sm2/root-sm2.pem -C

 **/

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
        halt_for_reboot("ERROR: failed to bind");
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(sockfd, 5) == -1) {
         ESP_LOGE(TAG, "ERROR: failed to listen on port %d",
                        TLS_SMP_DEFAULT_PORT);
        halt_for_reboot("sockd == -1");
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

    ESP_LOGI(TAG, "----------------------------------------------------------");
    ESP_LOGI(TAG, "Begin connection loop...");
    ESP_LOGI(TAG, "----------------------------------------------------------");
    /* Continue to accept clients until shutdown is issued */
    while (!shutdown) {
#ifdef HAVE_STACK_HEAP_INFO
        ret_i = esp_sdk_stack_heap_info(reset_heap);
        if (ret_i != ESP_OK) {
            ESP_LOGE(TAG, "ERROR: stack and heap check");
        }
#endif
#if defined(ESP_SDK_UTIL_LIB_VERSION) && \
           (ESP_SDK_UTIL_LIB_VERSION > 1)
        esp_sdk_device_show_info();
#endif
#ifdef USE_WOLFSSL_ESP_SDK_WIFI
        esp_sdk_wifi_show_ip();
#endif
#ifdef CTX_CERT_SET_NAME
        ESP_LOGI(TAG, "Certificate set in use:");
        ESP_LOGI(TAG, "-- %s", CTX_CERT_SET_NAME);
#else
        /* Check user_settings.h and wolfssl version. */
        ESP_LOGW(TAG, "Unknown Certificates in use!");
#endif
        ESP_LOGI(TAG, "Waiting for a connection on port %d ...",
                       TLS_SMP_DEFAULT_PORT);
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
            halt_for_reboot("ERROR: failed to create (WOLFSSL*) ssl object");
        }
        else {
#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_NO_MALLOC)
        ESP_LOGI(TAG, "\nCreated WOLFSSL object:");
        this_heap = esp_get_free_heap_size();
        ESP_LOGI(TAG, "tls_smp_client_task heap @ %p = %d",
                      &this_heap, this_heap);
#endif
#if defined(WOLFSSL_HAVE_MLKEM)
        /* Client sets the keyshare; we at the server only need to enable it. */
        ESP_LOGI(TAG, "WOLFSSL_HAVE_MLKEM is enabled");
        ret_i = WOLFSSL_SUCCESS;

    #if defined(WOLFSSL_KYBER1024)
        ESP_LOGI(TAG, "WOLFSSL_KYBER1024 is enabled");
    #elif defined(WOLFSSL_KYBER768)
        ESP_LOGI(TAG, "WOLFSSL_KYBER768 is enabled");
    #elif defined(WOLFSSL_KYBER512)
        ESP_LOGI(TAG, "WOLFSSL_KYBER512 is enabled");
    #else
        ESP_LOGW(TAG, "WOLFSSL_HAVE_MLKEM enabled but no key size available.");
        ret_i = ESP_FAIL;
    #endif

        if (ret_i == WOLFSSL_SUCCESS) {
            ESP_LOGI(TAG, "WOLFSSL_HAVE_MLKEM success");
        }
        else {
            ESP_LOGE(TAG, "WOLFSSL_HAVE_MLKEM failed");
        }
#else
        ESP_LOGI(TAG, "WOLFSSL_HAVE_MLKEM is not enabled, not using PQ.");
#endif
        }

#if defined(MY_PEER_VERIFY) && MY_PEER_VERIFY
        /* SSL verify peer enabled by default */
#else
        wolfSSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        ESP_LOGI(TAG, "ssl SSL_VERIFY_NONE");
#endif

        /* show what cipher connected for this WOLFSSL* object */
        ShowCiphers(ssl);

        /* Attach wolfSSL to the socket */
        wolfSSL_set_fd(ssl, connd);

        /* Establish TLS connection */
        ret = wolfSSL_accept(ssl);
        if (ret == SSL_SUCCESS) {
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
            if (wolfSSL_write(ssl, buff, len) == len) {
                success_ct++;
            }
            else {
                ESP_LOGE(TAG, "ERROR: failed to write");
                failure_ct++;
            }
        }
        else {
            ESP_LOGE(TAG, "wolfSSL_accept error %d",
                           wolfSSL_get_error(ssl, ret));
        }

        ESP_LOGI(TAG, "Done! Cleanup... ");
        /* Cleanup after this connection */
        ESP_LOGI(TAG, "wolfSSL_free...");
        wolfSSL_free(ssl);      /* Free the wolfSSL object              */
        ESP_LOGI(TAG, "close connection...");
        close(connd);           /* Close the connection to the client   */
#ifdef WOLFSSL_EXAMPLE_VERBOSITY
        ESP_LOGI(TAG, "Stack used: %d\n",
                TLS_SMP_SERVER_TASK_BYTES - uxTaskGetStackHighWaterMark(NULL));
#endif
        ESP_LOGI(TAG, "End connection loop: %d successes, %d failures",
                                               success_ct,   failure_ct);
    } /* -------------------------- !shutdown loop -------------------- */

    ESP_LOGI(TAG, "Done! Cleanup and delete this task.");
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

// TODO: these should always be available
#define TLS_SMP_SERVER_TASK_BYTES  (16 * 1024)
#define TLS_SMP_SERVER_TASK_NAME "task"
#define TLS_SMP_SERVER_TASK_PRIORITY 5

/* create task */
WOLFSSL_ESP_TASK tls_smp_server_init(void* args)
{
    int thisPort = 0;
    int ret_i = 0; /* interim return result */
#if defined(SINGLE_THREADED)
    #define TLS_SMP_CLIENT_TASK_RET ret
#else
    #define TLS_SMP_CLIENT_TASK_RET
#endif

#if ESP_IDF_VERSION_MAJOR >= 4
    TaskHandle_t _handle;
#else
    xTaskHandle _handle;
#endif

    if (thisPort == 0) {
        thisPort = TLS_SMP_DEFAULT_PORT;
    }

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
