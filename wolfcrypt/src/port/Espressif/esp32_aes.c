/* esp32_aes.c
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

/*
 * WOLFSSL_SUCCESS and WOLFSSL_FAILURE values should only
 * be used in the ssl layer, not in wolfCrypt
 **/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Reminder: user_settings.h is needed and included from settings.h
 * Be sure to define WOLFSSL_USER_SETTINGS, typically in CMakeLists.txt */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF */
#include "sdkconfig.h" /* programmatically generated from sdkconfig */
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>

#ifndef NO_AES

#if defined(WOLFSSL_ESP32_CRYPT) && !defined(NO_WOLFSSL_ESP32_CRYPT_AES)
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* breadcrumb tag text for ESP_LOG() */
static const char* TAG = "wolf_hw_aes";

/* mutex */
static wolfSSL_Mutex aes_mutex;

/* Maximum time to wait for AES HW in FreeRTOS ticks */
#define WOLFSSL_AES_MUTEX_WAIT 5000

/* keep track as to whether esp aes is initialized */
static int espaes_CryptHwMutexInit = 0;

#if defined(WOLFSSL_HW_METRICS)
    static unsigned long esp_aes_unsupported_length_usage_ct = 0;
#endif

/*
* lock hw engine.
* this should be called before using engine.
*
* returns 0 if the hw lock was initialized and mutex lock
*/
static int esp_aes_hw_InUse(void)
{
    int ret = ESP_OK;

    ESP_LOGV(TAG, "enter esp_aes_hw_InUse");

    if (espaes_CryptHwMutexInit == 0) {
        ret = esp_CryptHwMutexInit(&aes_mutex);
        if (ret == ESP_OK) {
            /* flag esp aes as initialized */
            espaes_CryptHwMutexInit = 1;
        }
        else {
            ESP_LOGE(TAG, "aes mutex initialization failed.");
        }
    }
    else {
        /* esp aes has already been initialized */
    }

    if (ret == ESP_OK) {
        /* lock hardware; there should be exactly one instance
         * of esp_CryptHwMutexLock(&aes_mutex ...) in code  */
        /* TODO - do we really want to wait?
         *    probably not */
        ret = esp_CryptHwMutexLock(&aes_mutex, WOLFSSL_AES_MUTEX_WAIT);
        if (ret == ESP_OK) {
            ESP_LOGV(TAG, "esp_CryptHwMutexLock aes success");
        }
        else {
            ESP_LOGW(TAG, "esp_CryptHwMutexLock aes timeout! %d", ret);
        }
    }
    else {
        ESP_LOGE(TAG, "aes engine lock failed.");
    }


    if (ret == ESP_OK) {
        /* Enable AES hardware */
        periph_module_enable(PERIPH_AES_MODULE);

        #if defined(CONFIG_IDF_TARGET_ESP32S2) || \
            defined(CONFIG_IDF_TARGET_ESP32S3)
        {
            /* Select working mode. Can be typical or DMA.
             * 0 => typical
             * 1 => DMA */
            DPORT_REG_WRITE(AES_DMA_ENABLE_REG, 0);
        }
        #elif defined(CONFIG_IDF_TARGET_ESP32C3) || \
              defined(CONFIG_IDF_TARGET_ESP32C6)
        {
            /* Select working mode. Can be typical or DMA.
             * 0 => typical
             * 1 => DMA */
            DPORT_REG_WRITE(AES_DMA_ENABLE_REG, 0);
        }
        #endif
    }

    ESP_LOGV(TAG, "leave esp_aes_hw_InUse");
    return ret;
} /* esp_aes_hw_InUse */

/*
*   release hw engine
*/
static void esp_aes_hw_Leave( void )
{
    ESP_LOGV(TAG, "enter esp_aes_hw_Leave");
    /* Disable AES hardware */
    periph_module_disable(PERIPH_AES_MODULE);

    /* unlock */
    esp_CryptHwMutexUnLock(&aes_mutex);

    ESP_LOGV(TAG, "leave esp_aes_hw_Leave");
} /* esp_aes_hw_Leave */

/*
 * set key to hardware key registers.
 * return ESP_OK = 0 on success; BAD_FUNC_ARG if mode isn't supported.
 */
static int esp_aes_hw_Set_KeyMode(Aes *ctx, ESP32_AESPROCESS mode)
{
    int ret = ESP_OK;
    word32 i;
    word32 mode_ = 0;

    ESP_LOGV(TAG, "  enter esp_aes_hw_Set_KeyMode %d", mode);

    /* check mode */
    if (mode == ESP32_AES_UPDATEKEY_ENCRYPT) {
        mode_ = 0;
    }
    else {
        if (mode == ESP32_AES_UPDATEKEY_DECRYPT) {
            mode_ = 4;
        }
        else {
            ESP_LOGE(TAG, "  >> unexpected error.");
            ret = BAD_FUNC_ARG;
        }
    } /* if mode */

    /*
    ** ESP32:    see table 22-1 in ESP32 Technical Reference
    ** ESP32-S3: see table 19-2 in ESP32-S3 Technical Reference
    ** ESP32-C3:
    ** ESP32-C6: see table 18-2 in ESP32-C6 Technical Reference
    **
    ** Mode     Algorithm             ESP32   ESP32S3  ESP32C3 ESP32C6
    **   0       AES-128 Encryption     y        y        y       y
    **   1       AES-192 Encryption     y        n        n       n
    **   2       AES-256 Encryption     y        y        y       y
    **   3       reserved               n        n        n       n
    **   4       AES-128 Decryption     y        y        y       y
    **   5       AES-192 Decryption     y        n        n       n
    **   6       AES-256 Decryption     y        y        y       y
    **   7       reserved               n        n        n       n
    */
    switch(ctx->keylen){
        case 24: mode_ += 1; break;
        case 32: mode_ += 2; break;
        default: break;
    }

    /* Some specific modes are not supported on some targets. */
#if defined(CONFIG_IDF_TARGET_ESP32)
    #define TARGET_AES_KEY_BASE AES_KEY_BASE
    if (mode_ == 3 || mode_ > 6) {
        /* this should have been detected in aes.c and fall back to SW */
        ESP_LOGE(TAG, "esp_aes_hw_Set_KeyMode unsupported mode: %i", mode_);
        ret = BAD_FUNC_ARG;
    }

#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    #define TARGET_AES_KEY_BASE AES_KEY_BASE
    if (mode_ == 1 || mode_ == 3 || mode_ == 5 || mode_ > 6) {
        /* this should have been detected in aes.c and fall back to SW */
        ESP_LOGE(TAG, "esp_aes_hw_Set_KeyMode unsupported mode: %i", mode_);
        ret = BAD_FUNC_ARG;
    }

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    #define TARGET_AES_KEY_BASE AES_KEY_BASE
    if (mode_ == 1 || mode_ == 3|| mode_ == 5 || mode_ > 6) {
        /* this should have been detected in aes.c and fall back to SW */
        ESP_LOGE(TAG, "esp_aes_hw_Set_KeyMode unsupported mode: %i", mode_);
        ret = BAD_FUNC_ARG;
    }
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    #define TARGET_AES_KEY_BASE AES_KEY_0_REG
    if (mode_ == 1 || mode_ == 3 || mode_ == 5 || mode_ > 6) {
        /* this should have been detected in aes.c and fall back to SW */
        ESP_LOGE(TAG, "esp_aes_hw_Set_KeyMode unsupported mode: %i", mode_);
        ret = BAD_FUNC_ARG;
    }
#else
    /* assume all modes supported, use AES_KEY_BASE */
    #define TARGET_AES_KEY_BASE AES_KEY_BASE
#endif

    /* */
    if (ret == ESP_OK) {
        /* update key */
        for (i = 0; i < (ctx->keylen) / sizeof(word32); i++) {
            DPORT_REG_WRITE((volatile word32*)(TARGET_AES_KEY_BASE + (i * 4)),
                            *(((word32*)ctx->key) + i)
                           );
        }

        if (ret == ESP_OK) {
            DPORT_REG_WRITE(AES_MODE_REG, mode_);
        }
        ESP_LOGV(TAG, "  leave esp_aes_hw_Setkey");
    }

    return ret;
} /* esp_aes_hw_Set_KeyMode */

/*
 * esp_aes_bk
 * Process a one block of AES
 * in: block of 16 bytes (4 x words32) to process
 * out: result of processing input bytes.
 */
static void esp_aes_bk(const byte* in, byte* out)
{
    const word32* inwords;
    uint32_t* outwords;

    inwords = (const word32*)in;
    outwords = (uint32_t*)out;

    ESP_LOGV(TAG, "enter esp_aes_bk");

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* copy text for encrypting/decrypting blocks */
    DPORT_REG_WRITE(AES_TEXT_BASE, inwords[0]);
    DPORT_REG_WRITE(AES_TEXT_BASE + 4, inwords[1]);
    DPORT_REG_WRITE(AES_TEXT_BASE + 8, inwords[2]);
    DPORT_REG_WRITE(AES_TEXT_BASE + 12, inwords[3]);

    /* start engine */
    DPORT_REG_WRITE(AES_START_REG, 1);

    /* wait until finishing the process */
    while (1) {
        if (DPORT_REG_READ(AES_IDLE_REG) == 1) {
            break;
        }
    }

    /* read-out blocks */
    esp_dport_access_read_buffer(outwords, AES_TEXT_BASE, 4);

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* See ESP32-C3 technical reference manual:
    ** 19.4.3 Operation process using CPU working mode.
    ** The ESP32-C3 also supports a DMA mode. (not ywt implemented)
    **
    ** Copy text for encrypting/decrypting blocks: */
    DPORT_REG_WRITE(AES_TEXT_IN_BASE, inwords[0]);
    DPORT_REG_WRITE(AES_TEXT_IN_BASE + 4, inwords[1]);
    DPORT_REG_WRITE(AES_TEXT_IN_BASE + 8, inwords[2]);
    DPORT_REG_WRITE(AES_TEXT_IN_BASE + 12, inwords[3]);

    /* start engine */
    DPORT_REG_WRITE(AES_TRIGGER_REG, 1);

    /* wait until finishing the process */
    while (DPORT_REG_READ(AES_STATE_REG) != 0) {
        /* waiting for the hardware accelerator to complete operation. */
    }

    /* read-out blocks */
    esp_dport_access_read_buffer((uint32_t*)outwords, AES_TEXT_OUT_BASE, 4);
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    /* See ESP32-C6 technical reference manual:
    ** 18.4.3 Operation process using CPU working mode.
    ** The ESP32-C6 also supports a DMA mode. (not ywt implemented)
    **
    ** Copy text for encrypting/decrypting blocks: */
    DPORT_REG_WRITE(AES_TEXT_IN_0_REG, inwords[0]);
    DPORT_REG_WRITE(AES_TEXT_IN_1_REG, inwords[1]);
    DPORT_REG_WRITE(AES_TEXT_IN_2_REG, inwords[2]);
    DPORT_REG_WRITE(AES_TEXT_IN_3_REG, inwords[3]);

    /* start engine */
    DPORT_REG_WRITE(AES_TRIGGER_REG, 1);

    /* wait until finishing the process */
    while (DPORT_REG_READ(AES_STATE_REG) != 0) {
        /* waiting for the hardware accelerator to complete operation. */
    }

    /* read-out blocks */
    esp_dport_access_read_buffer(outwords, AES_TEXT_OUT_0_REG, 4);

#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    /* See esp32 - s3 technical reference manual:
    ** 19.4.3 Operation process using CPU working mode.
    ** The ESP32-S3 also supports a DMA mode.
    **
    ** Copy text for encrypting/decrypting blocks: */
    DPORT_REG_WRITE(AES_TEXT_IN_BASE, inwords[0]);
    DPORT_REG_WRITE(AES_TEXT_IN_BASE + 4, inwords[1]);
    DPORT_REG_WRITE(AES_TEXT_IN_BASE + 8, inwords[2]);
    DPORT_REG_WRITE(AES_TEXT_IN_BASE + 12, inwords[3]);

    /* start engine */
    DPORT_REG_WRITE(AES_TRIGGER_REG, 1);

    /* wait until finishing the process */
    while (DPORT_REG_READ(AES_STATE_REG) != 0) {
        /* waiting for the hardware accelerator to complete operation. */
    }

    /* read-out blocks */
    esp_dport_access_read_buffer(outwords, AES_TEXT_OUT_BASE, 4);

#else
    ESP_LOGW(TAG, "Warning: esp_aes_bk called for unsupported target: %s",
                   CONFIG_IDF_TARGET)

#endif

    ESP_LOGV(TAG, "leave esp_aes_bk");
} /* esp_aes_bk */

/*
* wc_esp32AesSupportedKeyLen
* @brief: returns 1 if AES key length supported in HW, 0 if not
* @param aes:a value of a ley length */
int wc_esp32AesSupportedKeyLenValue(int keylen)
{
    int ret = ESP_OK;

#if defined(CONFIG_IDF_TARGET_ESP32)
    if (keylen == 16 || keylen == 24 || keylen == 32) {
        ret = 1;
    }
    else {
        ret = ESP_OK; /* keylen 24 (192 bit) not supported */
    }

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    if (keylen == 16 || keylen == 32) {
        ret = 1;
    }
    else {
        ret = ESP_OK; /* keylen 24 (192 bit) not supported */
    }

#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    if (keylen == 16 || keylen == 32) {
        ret = 1;
    }
    else {
        ret = ESP_OK; /* keylen 24 (192 bit) not supported */
    }

#elif defined(CONFIG_IDF_TARGET_ESP32H2)
    ret = ESP_OK; /* not yet implemented */

#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    if (keylen == 16 || keylen == 32) {
        ret = 1;
    }
    else {
        ret = ESP_OK; /* keylen 24 (192 bit) not supported */
    }

#else
    ret = ESP_OK; /* if we don't know, then it is not supported */

#endif
    return ret;
}

/*
* wc_esp32AesSupportedKeyLen
* @brief: returns 1 if AES key length supported in HW, 0 if not
* @param aes: a pointer of the AES object used to encrypt data */
int wc_esp32AesSupportedKeyLen(struct Aes* aes)
{
    int ret;
    if (aes == NULL) {
        ret = ESP_OK; /* we need a valid aes object to get its keylength */
    }
    else {
        ret = wc_esp32AesSupportedKeyLenValue(aes->keylen);
    }
    return ret;
}

/*
* wc_esp32AesEncrypt
* @brief: a one block encrypt of the input block, into the output block
* @param aes: a pointer of the AES object used to encrypt data
* @param in : a pointer of the input buffer containing
*             plain text to be encrypted
* @param out: a pointer of the output buffer in which to store the
*             cipher text of the encrypted message
* @return: 0 on success, BAD_FUNC_ARG if the AES algorithm isn't supported.
*/
int wc_esp32AesEncrypt(Aes *aes, const byte* in, byte* out)
{
    int ret = ESP_OK;

    ESP_LOGV(TAG, "enter wc_esp32AesEncrypt");
    /* lock the hw engine */
    ret = esp_aes_hw_InUse();

    if (ret == ESP_OK) {
        ret = esp_aes_hw_Set_KeyMode(aes, ESP32_AES_UPDATEKEY_ENCRYPT);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "wc_esp32AesEncrypt failed "
                          "during esp_aes_hw_Set_KeyMode");
        }
    }

    /* load the key into the register */
    if (ret == ESP_OK) {
        /* process a one block of AES */
        esp_aes_bk(in, out);
    }

    /* release hw */
    esp_aes_hw_Leave();
    return ret;
} /* wc_esp32AesEncrypt */

/*
* wc_esp32AesDecrypt
* @brief: a one block decrypt of the input block, into the output block
* @param aes: a pointer of the AES object used to decrypt data
* @param in : a pointer of the input buffer containing
*             plain text to be decrypted
* @param out: a pointer of the output buffer in which to store the
*             cipher text of the decrypted message
* @return: 0 on success, BAD_FUNC_ARG if the AES algorithm isn't supported.
*/
int wc_esp32AesDecrypt(Aes *aes, const byte* in, byte* out)
{
    int ret;

    ESP_LOGV(TAG, "enter wc_esp32AesDecrypt");
    /* lock the hw engine */
    esp_aes_hw_InUse();
    /* load the key into the register */
    ret = esp_aes_hw_Set_KeyMode(aes, ESP32_AES_UPDATEKEY_DECRYPT);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "wc_esp32AesDecrypt failed "
                      "during esp_aes_hw_Set_KeyMode");
        /* release hw */
        esp_aes_hw_Leave();
        ret = BAD_FUNC_ARG;
    }

    if (ret == ESP_OK) {
        /* process a one block of AES */
        esp_aes_bk(in, out);
        /* release hw engine */
        esp_aes_hw_Leave();
    }

    return ret;
} /* wc_esp32AesDecrypt */

/*
* wc_esp32AesCbcEncrypt
* @brief: Encrypts a plain text message from the input buffer, and places the
*         resulting cipher text into the output buffer using cipher block
*         chaining with AES.
* @param aes: a pointer of the AES object used to encrypt data
* @param out: a pointer of the output buffer in which to store the
              cipher text of the encrypted message
* @param in : a pointer of the input buffer containing
*             plain text to be encrypted
* @param sz : size of input message
* @return: 0 on success, BAD_FUNC_ARG if the AES algorithm isn't supported.
*/
int wc_esp32AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    int i;
    int offset = 0;
    word32 blocks = (sz / AES_BLOCK_SIZE);
    byte *iv;
    byte temp_block[AES_BLOCK_SIZE];

    ESP_LOGV(TAG, "enter wc_esp32AesCbcEncrypt");

    iv = (byte*)aes->reg;

    ret = esp_aes_hw_InUse();

    if (ret == ESP_OK) {
        ret = esp_aes_hw_Set_KeyMode(aes, ESP32_AES_UPDATEKEY_ENCRYPT);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "wc_esp32AesCbcEncrypt failed HW Set KeyMode");
        }
    } /* if set esp_aes_hw_InUse successful */

    if (ret == ESP_OK) {
        while (blocks--) {
            XMEMCPY(temp_block, in + offset, AES_BLOCK_SIZE);

            /* XOR block with IV for CBC */
            for (i = 0; i < AES_BLOCK_SIZE; i++) {
                temp_block[i] ^= iv[i];
            }

            esp_aes_bk(temp_block, (out + offset));

            offset += AES_BLOCK_SIZE;

            /* store IV for next block */
            XMEMCPY(iv, out + offset - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        } /* while (blocks--) */
    } /* if Set Mode successful (ret == ESP_OK) */

    esp_aes_hw_Leave();
    ESP_LOGV(TAG, "leave wc_esp32AesCbcEncrypt");
    return ret;
} /* wc_esp32AesCbcEncrypt */

/*
* wc_esp32AesCbcDecrypt
* @brief: Encrypts a plain text message from the input buffer, and places the
*         resulting cipher text into the output buffer using cipher block
*         chaining with AES.
* @param aes: a pointer of the AES object used to decrypt data
* @param out: a pointer of the output buffer in which to store the
*             cipher text of the decrypted message
* @param in : a pointer of the input buffer containing
*             plain text to be decrypted
* @param sz : size of input message
* @return: 0 on success, BAD_FUNC_ARG if the AES algorithm isn't supported.
*/
int wc_esp32AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;

    int i;
    int offset = 0;
    word32 blocks = (sz / AES_BLOCK_SIZE);
    byte* iv;
    byte temp_block[AES_BLOCK_SIZE];

    ESP_LOGV(TAG, "enter wc_esp32AesCbcDecrypt");

    iv = (byte*)aes->reg;

    ret = esp_aes_hw_InUse();

    if (ret == ESP_OK) {
        ret = esp_aes_hw_Set_KeyMode(aes, ESP32_AES_UPDATEKEY_DECRYPT);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "wc_esp32AesCbcDecrypt failed HW Set KeyMode");
        }
    }

    if (ret == ESP_OK) {
        while (blocks--) {
            XMEMCPY(temp_block, in + offset, AES_BLOCK_SIZE);

            esp_aes_bk((in + offset), (out + offset));

            /* XOR block with IV for CBC */
            for (i = 0; i < AES_BLOCK_SIZE; i++) {
                (out + offset)[i] ^= iv[i];
            }

            /* store IV for next block */
            XMEMCPY(iv, temp_block, AES_BLOCK_SIZE);

            offset += AES_BLOCK_SIZE;
        } /* while (blocks--) */
        esp_aes_hw_Leave();
    } /* if Set Mode was successful (ret == ESP_OK) */

    ESP_LOGV(TAG, "leave wc_esp32AesCbcDecrypt");
    return ret;
} /* wc_esp32AesCbcDecrypt */

#endif /* WOLFSSL_ESP32_CRYPT */
#endif /* NO_AES */

/* Metrics */
#if defined(WOLFSSL_ESP32_CRYPT) && !defined(NO_WOLFSSL_ESP32_CRYPT_AES)

#if defined(WOLFSSL_HW_METRICS)

/* increment esp_aes_unsupported_length_usage_ct and return current value */
int wc_esp32AesUnupportedLengthCountAdd(void) {
    esp_aes_unsupported_length_usage_ct++;
    return esp_aes_unsupported_length_usage_ct;
}

#endif /* WOLFSSL_HW_METRICS */

/* Show AES Metrics when enabled, otherwise callable but no action. */
int esp_hw_show_aes_metrics(void)
{
    int ret = ESP_OK;

#if defined(WOLFSSL_HW_METRICS)

    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "------------- wolfSSL ESP HW AES Metrics----------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");

    ESP_LOGI(TAG, "esp_aes_unsupported_length_usage_ct = %lu",
                   esp_aes_unsupported_length_usage_ct);
#else
    /* no HW math, no HW math metrics */

#endif /* WOLFSSL_HW_METRICS */

    return ret;
}
#endif /* WOLFSSL_ESP32_CRYPT && !NO_WOLFSSL_ESP32_CRYPT_AES */

#endif /* WOLFSSL_ESPIDF */
