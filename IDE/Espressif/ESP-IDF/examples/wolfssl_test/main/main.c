/* test main.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* ESP-IDF */
#include <esp_log.h>
#include "sdkconfig.h"

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
#if defined(WOLFSSL_USER_SETTINGS)
    #include <wolfssl/wolfcrypt/settings.h>
    #if defined(WOLFSSL_ESPIDF)
        #include <wolfssl/version.h>
        #include <wolfssl/wolfcrypt/types.h>
        #include <wolfcrypt/test/test.h>
        #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
        #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
        #if defined(WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE)
            #include <wolfssl/wolfcrypt/port/Espressif/esp32-ecdsa.h>
        #endif
        #if defined(WOLFSSL_ESP32C5_TEST_SHA_COPY)
            #include <wolfssl/wolfcrypt/sha256.h>
            #include <wolfssl/wolfcrypt/sha512.h>
        #endif
    #else
        #error "Problem with wolfSSL user_settings. "           \
               "Check components/wolfssl/include "              \
               "and confirm WOLFSSL_USER_SETTINGS is defined, " \
               "typically in the component CMakeLists.txt"
    #endif
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif

/* Hardware; include after other libraries,
 * particularly after freeRTOS from settings.h */
#include <driver/uart.h>

/* set to 0 for one test,
** set to 1 for continuous test loop */
#define TEST_LOOP 0

#define THIS_MONITOR_UART_RX_BUFFER_SIZE 200

#ifdef CONFIG_ESP8266_XTAL_FREQ_26
    /* 26MHz crystal: 74880 bps */
    #define THIS_MONITOR_UART_BAUD_DATE 74880
#else
    /* 40MHz crystal: 115200 bps */
    #define THIS_MONITOR_UART_BAUD_DATE 115200
#endif

/*
** the wolfssl component can be installed in either:
**
**   - the ESP-IDF component directory
**
**       ** OR **
**
**   - the local project component directory
**
** it is not recommended to install in both.
**
*/

/*
** although the wolfcrypt/test includes a default time setting,
** see the enclosed optional time helper for adding NNTP.
** be sure to add "time_helper.c" in main/CMakeLists.txt
*/
#undef WOLFSSL_USE_TIME_HELPER
#if defined(WOLFSSL_USE_TIME_HELPER)
    #include "time_helper.h"
#endif

/* see wolfssl/wolfcrypt/test/test.h */
extern void wolf_crypt_task();

static const char* const TAG = "wolfssl_test";

#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)

#include "wolfssl/wolfcrypt/port/atmel/atmel.h"

/* when you need to use a custom slot allocation, */
/* enable the definition CUSTOM_SLOT_ALLOCAION.   */
#if defined(CUSTOM_SLOT_ALLOCATION)

static byte mSlotList[ATECC_MAX_SLOT];

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
    int i, slot = ATECC_INVALID_SLOT;

    switch (slotType) {
        case ATMEL_SLOT_ENCKEY:
            slot = 4;
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
                } /* if */
            } /* for */
    } /* switch */

    return slot;
}

/* free slot array       */
void my_atmel_free(int slotId)
{
    if (slotId >= 0 && slotId < ATECC_MAX_SLOT) {
        mSlotList[slotId] = ATECC_INVALID_SLOT;
    }
}

#endif /* CUSTOM_SLOT_ALLOCATION                                        */
#endif /* WOLFSSL_ESPWROOM32SE && HAVE_PK_CALLBACK && WOLFSSL_ATECC508A */

/* entry point */
#if defined(WOLFSSL_ESP32C5_TEST_EFUSE_BLOCK) && \
    defined(WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE)
static int esp32c5_efuse_selftest(void)
{
    ecc_key key;
    ecc_key copy;
    WC_RNG rng;
    byte hash[32];
    byte signature[128];
    byte qx[32];
    byte qy[32];
    byte privateKey[32];
    word32 signatureLen;
    word32 qxLen = sizeof(qx);
    word32 qyLen = sizeof(qy);
    word32 privateKeyLen = sizeof(privateKey);
    int verified;
    int ret;
    int stage = 0;
    int i;

    ret = wc_ecc_init(&key);
    if (ret != 0) {
        return ret;
    }
    ret = wc_ecc_init(&copy);
    if (ret != 0) {
        wc_ecc_free(&key);
        return ret;
    }
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&copy);
        wc_ecc_free(&key);
        return ret;
    }

    for (i = 0; i < (int)sizeof(hash); i++) {
        hash[i] = (byte)i;
    }

    stage = 1;
    ret = wc_esp32_ecdsa_use_efuse_key(&key, ECC_SECP256R1,
        WOLFSSL_ESP32C5_TEST_EFUSE_BLOCK, -1);
    if (ret == 0) {
        stage = 2;
        ret = wc_ecc_set_curve(&copy, sizeof(privateKey), ECC_SECP256R1);
    }
    if (ret == 0) {
        stage = 3;
        ret = wc_esp32_ecdsa_copy(&key, &copy);
    }
    if (ret == 0) {
        stage = 4;
        ret = wc_ecc_copy_point(&key.pubkey, &copy.pubkey);
    }
    copy.type = key.type;

    /* Exercise repeated operations, including signing after verification. */
    for (i = 0; ret == 0 && i < 2; i++) {
        ecc_key* signingKey = (i == 0) ? &key : &copy;
        ecc_key* verifyKey = (i == 0) ? &copy : &key;

        hash[0] = (byte)(i + 1);
        signatureLen = sizeof(signature);
        verified = 0;
        stage = 10 + i;
        ret = wc_ecc_sign_hash(hash, sizeof(hash), signature,
            &signatureLen, &rng, signingKey);
        if (ret == 0) {
            stage = 20 + i;
            ret = wc_ecc_verify_hash(signature, signatureLen, hash,
                sizeof(hash), &verified, verifyKey);
        }
        if (ret == 0 && verified != 1) {
            stage = 30 + i;
            ret = -1;
        }
    }

    /* Public coordinates remain exportable, but private material never is. */
    if (ret == 0) {
        stage = 40;
        ret = wc_ecc_export_public_raw(&key, qx, &qxLen, qy, &qyLen);
    }
    if (ret == 0 && (qxLen != sizeof(qx) || qyLen != sizeof(qy))) {
        stage = 41;
        ret = -1;
    }
    if (ret == 0 && wc_ecc_export_private_only(&key, privateKey,
            &privateKeyLen) != NOT_COMPILED_IN) {
        stage = 42;
        ret = -1;
    }
    privateKeyLen = sizeof(privateKey);
    if (ret == 0 && wc_ecc_export_private_raw(&key, qx, &qxLen, qy, &qyLen,
            privateKey, &privateKeyLen) != NOT_COMPILED_IN) {
        stage = 43;
        ret = -1;
    }

    if (ret != 0) {
        ESP_LOGE(TAG, "eFuse self-test stage %d failed: %d", stage, ret);
    }
    wc_ForceZero(privateKey, sizeof(privateKey));
    wc_FreeRng(&rng);
    wc_ecc_free(&copy);
    wc_ecc_free(&key);
    return ret;
}
#endif

#if defined(WOLFSSL_ESP32C5_TEST_SHA_COPY)
static int esp32c5_sha_copy_selftest(void)
{
    byte input[128];
    byte suffix[3] = { 'a', 'b', 'c' };
    int ret = 0;

#define C5_SHA_COPY_TEST(NAME, CTX, INIT, UPDATE, COPY, FINAL, FREE, SIZE, \
    EXP) \
    do {                                                                       \
        CTX src;                                                               \
        CTX dst;                                                               \
        byte srcHash[SIZE];                                                    \
        byte dstHash[SIZE];                                                    \
        int localRet;                                                          \
        int srcInit = 0;                                                       \
        int dstInit = 0;                                                       \
        XMEMSET(input, 'a', sizeof(input));                                    \
        localRet = INIT(&src);                                                 \
        if (localRet == 0) {                                                   \
            srcInit = 1;                                                       \
            localRet = INIT(&dst);                                             \
            if (localRet == 0) {                                               \
                dstInit = 1;                                                   \
            }                                                                  \
        }                                                                      \
        if (localRet == 0) {                                                   \
            localRet = UPDATE(&src, input, sizeof(input));                     \
        }                                                                      \
        if (localRet == 0) {                                                   \
            localRet = UPDATE(&dst, input, sizeof(input));                     \
        }                                                                      \
        if (localRet == 0) {                                                   \
            localRet = COPY(&src, &dst);                                       \
        }                                                                      \
        if (localRet == 0) {                                                   \
            localRet = UPDATE(&src, suffix, sizeof(suffix));                   \
        }                                                                      \
        if (localRet == 0) {                                                   \
            localRet = UPDATE(&dst, suffix, sizeof(suffix));                   \
        }                                                                      \
        if (localRet == 0) {                                                   \
            localRet = FINAL(&src, srcHash);                                   \
        }                                                                      \
        if (localRet == 0) {                                                   \
            localRet = FINAL(&dst, dstHash);                                   \
        }                                                                      \
        if (localRet == 0 && (XMEMCMP(srcHash, EXP, SIZE) != 0 ||              \
                              XMEMCMP(dstHash, EXP, SIZE) != 0)) {             \
            localRet = -1;                                                     \
        }                                                                      \
        if (srcInit) {                                                         \
            FREE(&src);                                                        \
        }                                                                      \
        if (dstInit) {                                                         \
            FREE(&dst);                                                        \
        }                                                                      \
        if (localRet != 0) {                                                   \
            ESP_LOGE(TAG, NAME " active-copy self-test failed: %d", localRet); \
            ret = localRet;                                                    \
        }                                                                      \
    } while (0)

    static const byte sha224Expected[WC_SHA224_DIGEST_SIZE] = {
        0x1e, 0xf0, 0xc6, 0xde, 0x5c, 0x12, 0xca, 0xbd, 0x65, 0x37, 0x4f,
        0x20, 0x53, 0x7f, 0xac, 0x0e, 0x02, 0x4c, 0xe3, 0x08, 0x04, 0xf5,
        0x98, 0x37, 0x51, 0x01, 0x13, 0xd3
    };
    static const byte sha384Expected[WC_SHA384_DIGEST_SIZE] = {
        0x88, 0x98, 0x33, 0x2a, 0xf4, 0x67, 0x4c, 0xaf, 0x89, 0x98, 0xb6,
        0xb5, 0xf2, 0xe7, 0xf3, 0xf7, 0x30, 0x22, 0x8c, 0x79, 0x33, 0xfa,
        0x98, 0xad, 0x17, 0xb5, 0x5c, 0x09, 0x25, 0x39, 0xbc, 0xb3, 0x19,
        0x87, 0x6c, 0xd9, 0xdb, 0x9c, 0xf3, 0xab, 0x9c, 0xb4, 0x27, 0x73,
        0x64, 0x3c, 0xb1, 0x95
    };
    static const byte sha512224Expected[WC_SHA512_224_DIGEST_SIZE] = {
        0xd1, 0xcc, 0x4b, 0x66, 0xba, 0x66, 0xac, 0xc0, 0xeb, 0x0b, 0x3e,
        0x15, 0xc6, 0x5d, 0xcc, 0x84, 0x9a, 0xdf, 0xfe, 0x23, 0x93, 0xbf,
        0xf7, 0x42, 0x4a, 0x8e, 0x6e, 0x5f
    };

    C5_SHA_COPY_TEST("SHA-224", wc_Sha224, wc_InitSha224, wc_Sha224Update,
        wc_Sha224Copy, wc_Sha224Final, wc_Sha224Free, WC_SHA224_DIGEST_SIZE,
        sha224Expected);
    C5_SHA_COPY_TEST("SHA-384", wc_Sha384, wc_InitSha384, wc_Sha384Update,
        wc_Sha384Copy, wc_Sha384Final, wc_Sha384Free, WC_SHA384_DIGEST_SIZE,
        sha384Expected);
    C5_SHA_COPY_TEST("SHA-512/224", wc_Sha512, wc_InitSha512_224,
        wc_Sha512Update, wc_Sha512Copy, wc_Sha512_224Final, wc_Sha512Free,
        WC_SHA512_224_DIGEST_SIZE, sha512224Expected);

#undef C5_SHA_COPY_TEST

    return ret;
}
#endif

#if defined(WOLFSSL_ESP32C5_TEST_KM) && \
    defined(WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE)
static int esp32c5_km_selftest(void)
{
    ecc_key key;
    WC_RNG rng;
    esp_key_mgr_aes_key_config_t config;
    esp_key_mgr_key_recovery_info_t recovery;
    byte hash[32];
    /* DER-encoded P-256 signatures can exceed 64 bytes. */
    byte signature[128];
    byte privateKey[32];
    word32 signatureLen = sizeof(signature);
    word32 privateKeyLen = sizeof(privateKey);
    int verified = 0;
    int deployed = 0;
    int stage = 0;
    int ret;
    int i;

    XMEMSET(&config, 0, sizeof(config));
    XMEMSET(&recovery, 0, sizeof(recovery));
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        return ret;
    }
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&key);
        return ret;
    }

    for (i = 0; i < (int)sizeof(hash); i++) {
        hash[i] = (byte)(i + 1);
    }
    config.key_type = ESP_KEY_MGR_ECDSA_KEY;
    config.key_len = ESP_KEY_MGR_ECDSA_LEN_256;
    config.use_pre_generated_sw_init_key = 1;
    if (wc_RNG_GenerateBlock(&rng, config.k2_info,
            sizeof(config.k2_info)) != 0 ||
        wc_RNG_GenerateBlock(&rng, config.k1_encrypted[0],
            sizeof(config.k1_encrypted[0])) != 0 ||
        wc_RNG_GenerateBlock(&rng, config.sw_init_key,
            sizeof(config.sw_init_key)) != 0) {
        ret = WC_HW_E;
    }
    if (ret == 0) {
        stage = 1;
        ret = esp_key_mgr_deploy_key_in_aes_mode(&config, &recovery);
        if (ret != ESP_OK) {
            ret = WC_HW_E;
        }
    }
    if (ret == 0) {
        stage = 2;
        deployed = 1;
        ret = wc_esp32_ecdsa_use_km_key(&key, ECC_SECP256R1, &recovery);
    }
    if (ret == 0) {
        stage = 3;
        ret = wc_ecc_sign_hash(hash, sizeof(hash), signature,
            &signatureLen, &rng, &key);
    }
    if (ret == 0) {
        stage = 4;
        ret = wc_ecc_verify_hash(signature, signatureLen, hash,
            sizeof(hash), &verified, &key);
    }
    if (ret == 0 && verified != 1) {
        stage = 5;
        ret = -1;
    }
    if (ret == 0 && wc_ecc_export_private_only(&key, privateKey,
            &privateKeyLen) != NOT_COMPILED_IN) {
        stage = 6;
        ret = -1;
    }
    if (ret != 0) {
        ESP_LOGE(TAG, "KM self-test stage %d failed: %d", stage, ret);
    }
    if (deployed) {
        /* The PSA driver also deactivates after each operation. */
        (void)esp_key_mgr_deactivate_key(recovery.key_type);
    }

    wc_ForceZero(&config, sizeof(config));
    wc_ForceZero(&recovery, sizeof(recovery));
    wc_ForceZero(signature, sizeof(signature));
    wc_ForceZero(privateKey, sizeof(privateKey));
    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    return ret;
}
#endif

void app_main(void)
{
    uart_config_t uart_config = {
        .baud_rate = THIS_MONITOR_UART_BAUD_DATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
    };
    int stack_start = 0;
    int heap_start = 0;
    int heap_current = 0;
    int loops = 0;
    esp_err_t ret = 0;

    stack_start = esp_sdk_stack_pointer();

    /* uart_set_pin(UART_NUM_0, TX_PIN, RX_PIN,
     *              UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE); */

    /* Some targets may need to have UART speed set, such as ESP8266 */
    ESP_LOGI(TAG, "UART init");
    uart_param_config(UART_NUM_0, &uart_config);
    uart_driver_install(UART_NUM_0,
                        THIS_MONITOR_UART_RX_BUFFER_SIZE, 0, 0, NULL, 0);

    ESP_LOGI(TAG, "------------------ wolfSSL Test Example ----------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "---------------------- BEGIN MAIN ----------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "Stack Start: 0x%x", stack_start);

#ifdef WOLFSSL_ESP_NO_WATCHDOG
    ESP_LOGW(TAG, "Found WOLFSSL_ESP_NO_WATCHDOG, disabling...");
    esp_DisableWatchdog();
#endif

#ifdef ESP_TASK_MAIN_STACK
     ESP_LOGI(TAG, "ESP_TASK_MAIN_STACK: %d", ESP_TASK_MAIN_STACK);
#endif
#ifdef TASK_EXTRA_STACK_SIZE
     ESP_LOGI(TAG, "TASK_EXTRA_STACK_SIZE: %d", TASK_EXTRA_STACK_SIZE);
#endif

#ifdef INCLUDE_uxTaskGetStackHighWaterMark
    ESP_LOGI(TAG, "CONFIG_ESP_MAIN_TASK_STACK_SIZE = %d bytes (%d words)",
                   CONFIG_ESP_MAIN_TASK_STACK_SIZE,
                   (int)(CONFIG_ESP_MAIN_TASK_STACK_SIZE / sizeof(void*)));

    /* Returns the high water mark of the stack associated with xTask. That is,
     * the minimum free stack space there has been (in bytes not words, unlike
     * vanilla FreeRTOS) since the task started. The smaller the returned
     * number the closer the task has come to overflowing its stack.
     * see Espressif esp32/api-reference/system/freertos_idf.html
     */
    stack_start = uxTaskGetStackHighWaterMark(NULL);
    ESP_LOGI(TAG, "Stack Start HWM: %d bytes", stack_start);
#endif

#if defined(HAVE_VERSION_EXTENDED_INFO)
    esp_ShowExtendedSystemInfo();
#endif

    /* all platforms: stack high water mark check */
    ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));

#if defined (WOLFSSL_USE_TIME_HELPER)
    set_time();
#endif

/* when using atecc608a on esp32-WROOM-32se */
#if defined(WOLFSSL_ESPWROOM32SE) && defined(HAVE_PK_CALLBACKS) \
                                  && defined(WOLFSSL_ATECC508A)
    #if defined(CUSTOM_SLOT_ALLOCATION)
    my_atmel_slotInit();
    /* to register the callback, it needs to be initialized. */
    if ((wolfCrypt_Init()) != 0) {
        ESP_LOGE(TAG, "wolfCrypt_Init failed");
        return;
    }
    atmel_set_slot_allocator(my_atmel_alloc, my_atmel_free);
    #endif
#endif

#ifdef NO_CRYPT_TEST
    ESP_LOGI(TAG, "NO_CRYPT_TEST defined, skipping wolf_test_task");
#else
    /* Although wolfCrypt_Init() may be explicitly called above,
    ** note it is still always called in wolf_test_task.
    */
    stack_start = uxTaskGetStackHighWaterMark(NULL);
    heap_start = heap_caps_get_free_size(MALLOC_CAP_8BIT);

    do {
        heap_current = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        ESP_LOGI(TAG, "Free heap memory: %d bytes; Start %d",
                                         heap_current, heap_start);
        ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));

        ret = wolf_test_task();
#if defined(WOLFSSL_ESP32C5_TEST_SHA_COPY)
        if (ret == 0) {
            ret = esp32c5_sha_copy_selftest();
            ESP_LOGI(TAG, "ESP32-C5 SHA copy self-test: %d", ret);
        }
#endif
#if defined(WOLFSSL_ESP32C5_TEST_EFUSE_BLOCK) && \
    defined(WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE)
        if (ret == 0) {
            ret = esp32c5_efuse_selftest();
            ESP_LOGI(TAG, "ESP32-C5 eFuse ECDSA self-test: %d", ret);
        }
#endif
#if defined(WOLFSSL_ESP32C5_TEST_KM) && \
    defined(WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE)
        if (ret == 0) {
            ret = esp32c5_km_selftest();
            ESP_LOGI(TAG, "ESP32-C5 Key Manager ECDSA self-test: %d", ret);
        }
#endif
        #if defined(WOLFSSL_ESP32_CRYPT_RSA_PRI) && defined(WOLFSSL_HW_METRICS)
            esp_hw_show_metrics();
        #endif
        loops++; /* count of the number of tests run before fail. */
        ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));
        ESP_LOGI(TAG, "loops = %d", loops);

    } while (TEST_LOOP && (ret == 0));

    /* Reminder: wolfCrypt_Cleanup() should always be called at completion,
    ** and is called in wolf_test_task().  */

#if defined TEST_LOOP && (TEST_LOOP == 1)
    ESP_LOGI(TAG, "Test loops completed: %d", loops);
#endif

#if defined(SINGLE_THREADED)
    /* need stack monitor for single thread */
#else
    ESP_LOGI(TAG, "Stack HWM: %d\n", uxTaskGetStackHighWaterMark(NULL));
#endif

#if defined(WOLFSSL_HW_METRICS) && defined(WOLFSSL_ESP32_CRYPT_RSA_PRI)
    esp_hw_show_mp_metrics();
#endif

#ifdef INCLUDE_uxTaskGetStackHighWaterMark
    ESP_LOGI(TAG, "Stack HWM: %d", uxTaskGetStackHighWaterMark(NULL));

    ESP_LOGI(TAG, "Stack used: %d", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                    - (uxTaskGetStackHighWaterMark(NULL)));
#endif

#ifdef WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE
    if (ret == 0) {
        ESP_LOGI(TAG, WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE("Success!", ret));
    }
    else {
        ESP_LOGE(TAG, WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE("Failed!", ret));
    }
#elif defined(WOLFSSL_ESPIDF_EXIT_MESSAGE)
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_EXIT_MESSAGE);
#else
    ESP_LOGI(TAG, "\n\nDone!\n\n"
                  "If running from idf.py monitor, press twice: Ctrl+]");
#endif

    /* After completion, we'll just wait */
    while (1) {
#if defined(SINGLE_THREADED)
        while (1);
#else
        vTaskDelay(60000);
#endif
    } /* done while */
#endif
}
