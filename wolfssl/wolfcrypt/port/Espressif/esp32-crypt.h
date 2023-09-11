/* esp32-crypt.h
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
#ifndef __ESP32_CRYPT_H__

#define __ESP32_CRYPT_H__

#include "sdkconfig.h" /* ensure ESP-IDF settings are available everywhere */

/* wolfSSL  */
#include <wolfssl/wolfcrypt/settings.h> /* references user_settings.h */
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>    /* for MATH_INT_T */

/* Espressif */
#include <esp_idf_version.h>
#include <esp_types.h>
#include <esp_log.h>

/* exit codes to be used in tfm.c, sp_int.c, integer.c, etc.
 *
 * see wolfssl/wolfcrypt/error-crypt.h
 *
 * WC_HW_E - generic hardware failure. Consider falling back to SW.
 * WC_HW_WAIT_E - waited too long for HW, fall back to SW
 */

/* exit code only used in Espressif port */

/* MP_HW_FALLBACK: signal to caller to fall back to SW for math:
 *   algorithm not supported in SW
 *   known state needing only SW, (e.g. ctx copy)
 *   any other reason to force SW */
#define MP_HW_FALLBACK (-108)

/* MP_HW_VALIDATION_ACTIVE this is informative only:
 * typically also means "MP_HW_FALLBACK": fall back to SW.
 *  optional HW validation active, so compute in SW to compare.
 *  fall back to SW, typically only used during debugging
 */
#define MP_HW_VALIDATION_ACTIVE (-109)

/*
*******************************************************************************
*******************************************************************************
**
** Primary Settings:
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI
**   Defined in wolfSSL settings.h: this turns on or off esp32_mp math library.
**   Unless turned off, this is enabled by default for the ESP32
**
** NO_ESP32_CRYPT
**   When defined, disables all hardware acceleration on the ESP32
**
** NO_WOLFSSL_ESP32_CRYPT_HASH
**   Used to disabled only hash hardware algorithms: SHA2, etc.
**
**   WOLFSSL_NOSHA512_224
**     Define to disable SHA-512/224
**
**   WOLFSSL_NOSHA512_256
**     Define to disable SHA-512/512
**
** NO_WOLFSSL_ESP32_CRYPT_AES
**   Used to disable only AES hardware algorithms. Software used instead.
**
** NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
**   Turns off hardware acceleration esp_mp_mul()
**
** NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
**   Turns off hardware acceleration esp_mp_exptmod()
**
** NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
**   Turns off hardware acceleration esp_mp_mulmod()
**
*******************************************************************************
** Math library settings: TFM
*******************************************************************************
** Listed in increasing order of complexity:
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
**   When defined, use hardware acceleration esp_mp_mul()
**   for Large Number Multiplication: Z = X * Y
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
**   When defined, use hardware acceleration esp_mp_exptmod()
**   for Large Number Modular Exponentiation Z = X^Y mod M
**
** WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
**   When defined, use hardware acceleration esp_mp_mulmod()
**   for Large Number Modular Multiplication: Z = X * Y mod M
**
*******************************************************************************
** Optional Settings:
*******************************************************************************
**
** WOLFSSL_HW_METRICS
**   Enables metric counters for calls to HW, success, fall back, oddities.
**
** DEBUG_WOLFSSL
**   Turns on development testing. Validates HW accelerated results to software
**   - Automatically turns on WOLFSSL_HW_METRICS
**
** LOG_LOCAL_LEVEL
**   Debugging. Default value is ESP_LOG_DEBUG
**
** ESP_VERIFY_MEMBLOCK
**   Used to re-read data from registers in esp32_mp & verify written contents
**   actually match the source data.
**
** WOLFSSL_ESP32_CRYPT_DEBUG
**   When defined, enables hardware cryptography debugging
**
** NO_HW_MATH_TEST
**   Even if HW is enabled, do not run HW math tests. See HW_MATH_ENABLED.
**
** NO_ESP_MP_MUL_EVEN_ALT_CALC
**   Used during Z = X × Y mod M
**   By default, even moduli use a two step HW esp_mp_mul with SW mp_mod.
**   Enable this to instead fall back to pure software mp_mulmod.
**
** NO_RECOVER_SOFTWARE_CALC
**   When defined, will NOT recover software calculation result when not
**   matched with hardware. Useful only during development. Needs DEBUG_WOLFSSL
**
** ESP_PROHIBIT_SMALL_X
**   When set to 1 X operands less than 8 bits will fall back to SW
**
** ESP_NO_ERRATA_MITIGATION
**   Disable all errata mitigation code.
**
** USE_ESP_DPORT_ACCESS_READ_BUFFER
**   Sets ESP_NO_ERRATA_MITIGATION and uses esp_dport_access_read_buffer()
**
*******************************************************************************
** Settings used from <esp_idf_version.h>
*******************************************************************************
**
** ESP_IDF_VERSION_MAJOR
**
**
*******************************************************************************
** Settings used from ESP-IDF (sdkconfig.h)
*******************************************************************************
**
**
*******************************************************************************
**
**
*******************************************************************************
** Informative settings. Not meant to be edited
*******************************************************************************
**
** HW_MATH_ENABLED
**   Used to detect if any hardware math acceleration algorithms are used.
**   This is typically only used to flag wolfCrypt tests to run HW tests.
**   See NO_HW_MATH_TEST.
**
*******************************************************************************
*/
#ifdef WOLFSSL_ESP32_CRYPT_DEBUG
    #undef LOG_LOCAL_LEVEL
    #define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#else
    #undef LOG_LOCAL_LEVEL
    #define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#endif

#include <freertos/FreeRTOS.h>

#if defined(CONFIG_IDF_TARGET_ESP32)
    #include "soc/dport_reg.h"
    #include "soc/hwcrypto_reg.h"

    #if ESP_IDF_VERSION_MAJOR < 5
        #include "soc/cpu.h"
    #endif

    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include "esp_private/periph_ctrl.h"
    #else
        #include "driver/periph_ctrl.h"
    #endif

    #if ESP_IDF_VERSION_MAJOR >= 4
        #include <esp32/rom/ets_sys.h>
    #else
        #include <rom/ets_sys.h>
    #endif
    #define ESP_PROHIBIT_SMALL_X 0
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #include "soc/dport_reg.h"
    #include "soc/hwcrypto_reg.h"
    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include "esp_private/periph_ctrl.h"
    #else
        #include "driver/periph_ctrl.h"
    #endif
    #define ESP_PROHIBIT_SMALL_X 0
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    #include "soc/dport_reg.h"
    #include "soc/hwcrypto_reg.h"
    #if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
        #include "esp_private/periph_ctrl.h"
    #else
        #include "driver/periph_ctrl.h"
    #endif
    #define ESP_PROHIBIT_SMALL_X 0
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* no includes for ESP32C3 at this time (no HW implemented yet) */
#else
    /* not yet supported. no HW */
#endif

#if defined(USE_ESP_DPORT_ACCESS_READ_BUFFER)
    #define ESP_NO_ERRATA_MITIGATION
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    /*
    ******************************************************************************
    ** Some common esp utilities
    ******************************************************************************
    */

    WOLFSSL_LOCAL int esp_ShowExtendedSystemInfo(void);

    /* Compare MATH_INT_T A to MATH_INT_T B
     * During debug, the strings name_A and name_B can help
     * identify variable name. */
    WOLFSSL_LOCAL int esp_mp_cmp(char* name_A, MATH_INT_T* A, char* name_B, MATH_INT_T* B);

    /* Show MATH_INT_T value attributes.  */
    WOLFSSL_LOCAL int esp_show_mp_attributes(char* c, MATH_INT_T* X);

    /* Show MATH_INT_T value.
     *
     * Calls esp_show_mp_attributes().
     *
     * During debug, the string name_A can help
     * identify variable name. */
    WOLFSSL_LOCAL int esp_show_mp(char* name_X, MATH_INT_T* X);

    /* To use a Mutex, if must first be initialized */
    WOLFSSL_LOCAL int esp_CryptHwMutexInit(wolfSSL_Mutex* mutex);

    /* When the HW is in use, the mutex will be locked. */
    WOLFSSL_LOCAL int esp_CryptHwMutexLock(wolfSSL_Mutex* mutex, TickType_t block_time);

    /* Release the mutex to indicate the HW is no longer in use. */
    WOLFSSL_LOCAL int esp_CryptHwMutexUnLock(wolfSSL_Mutex* mutex);

#ifndef NO_AES

    #if ESP_IDF_VERSION_MAJOR >= 4
        #include "esp32/rom/aes.h"
    #else
        #include "rom/aes.h"
    #endif

    typedef enum tagES32_AES_PROCESS
    {
        ESP32_AES_LOCKHW            = 1,
        ESP32_AES_UPDATEKEY_ENCRYPT = 2,
        ESP32_AES_UPDATEKEY_DECRYPT = 3,
        ESP32_AES_UNLOCKHW          = 4
    } ESP32_AESPROCESS;

    struct Aes; /* see aes.h */
    WOLFSSL_LOCAL int wc_esp32AesSupportedKeyLenValue(int keylen);
    WOLFSSL_LOCAL int wc_esp32AesSupportedKeyLen(struct Aes* aes);
    WOLFSSL_LOCAL int wc_esp32AesCbcEncrypt(struct Aes* aes,
                              byte* out,
                              const byte* in,
                              word32 sz);
    WOLFSSL_LOCAL int wc_esp32AesCbcDecrypt(struct Aes* aes,
                              byte* out,
                              const byte* in,
                              word32 sz);
    WOLFSSL_LOCAL int wc_esp32AesEncrypt(struct Aes *aes, const byte* in, byte* out);
    WOLFSSL_LOCAL int wc_esp32AesDecrypt(struct Aes *aes, const byte* in, byte* out);

#endif /* ! NO_AES */

#ifdef WOLFSSL_ESP32_CRYPT_DEBUG

    void wc_esp32TimerStart(void);
    uint64_t  wc_esp32elapsedTime(void);

#endif /* WOLFSSL_ESP32_CRYPT_DEBUG */

#if !defined(NO_WOLFSSL_ESP32_CRYPT_HASH) &&     \
   (!defined(NO_SHA) || !defined(NO_SHA256) ||          \
     defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512) \
   )

    /* RAW hash function APIs are not implemented with
     * esp32 hardware acceleration*/
    #define WOLFSSL_NO_HASH_RAW
    #define SHA_CTX ETS_SHAContext

    #if ESP_IDF_VERSION_MAJOR >= 4
        #if defined(CONFIG_IDF_TARGET_ESP32)
            #include "esp32/rom/sha.h"
            #define WC_ESP_SHA_TYPE enum SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32C2)
            #include "esp32c2/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32C3)
            #include "esp32c3/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32H2)
            #include "esp32h2/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32S2)
            #include "esp32s2/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #elif defined(CONFIG_IDF_TARGET_ESP32S3)
            #include "esp32s3/rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #else
            #include "rom/sha.h"
            #define WC_ESP_SHA_TYPE SHA_TYPE
        #endif
    #else
        #include "rom/sha.h"
    #endif

    #undef SHA_CTX

    typedef enum
    {
        ESP32_SHA_INIT             = 0,
        ESP32_SHA_HW               = 1,
        ESP32_SHA_SW               = 2,
        ESP32_SHA_HW_COPY          = 3,
        ESP32_SHA_FAIL_NEED_UNROLL = -1
    } ESP32_MODE;

    typedef struct
    {
        /* pointer to object the initialized HW; to track copies */
        void* initializer;

        /* an ESP32_MODE value; typically:
        **   0 init,
        **   1 HW,
        **   2 SW     */
        ESP32_MODE mode;

        /* see esp_rom/include/esp32/rom/sha.h
        **
        **  the Espressif type: SHA1, SHA256, etc.
        */

        WC_ESP_SHA_TYPE sha_type;

        /* we'll keep track of our own locks.
        ** actual enable/disable only occurs for ref_counts[periph] == 0
        **
        **  see ref_counts[periph] in periph_ctrl.c */
        byte lockDepth : 7; /* 7 bits for a small number, pack with below. */

        /* 0 (false) this is NOT first block.
        ** 1 (true ) this is first block.  */
        byte isfirstblock : 1; /* 1 bit only for true / false */
    } WC_ESP32SHA;

    WOLFSSL_LOCAL int esp_sha_init(WC_ESP32SHA* ctx, enum wc_HashType hash_type);
    WOLFSSL_LOCAL int esp_sha_init_ctx(WC_ESP32SHA* ctx);
    WOLFSSL_LOCAL int esp_sha_try_hw_lock(WC_ESP32SHA* ctx);
    WOLFSSL_LOCAL int esp_sha_hw_unlock(WC_ESP32SHA* ctx);

    struct wc_Sha;
    WOLFSSL_LOCAL int esp_sha_ctx_copy(struct wc_Sha* src, struct wc_Sha* dst);
    WOLFSSL_LOCAL int esp_sha_digest_process(struct wc_Sha* sha, byte blockprocess);
    WOLFSSL_LOCAL int esp_sha_process(struct wc_Sha* sha, const byte* data);

    #ifndef NO_SHA256
    struct wc_Sha256;
    WOLFSSL_LOCAL int esp_sha224_ctx_copy(struct wc_Sha256* src, struct wc_Sha256* dst);
    WOLFSSL_LOCAL int esp_sha256_ctx_copy(struct wc_Sha256* src, struct wc_Sha256* dst);
    WOLFSSL_LOCAL int esp_sha256_digest_process(struct wc_Sha256* sha, byte blockprocess);
    WOLFSSL_LOCAL int esp_sha256_process(struct wc_Sha256* sha, const byte* data);
    WOLFSSL_LOCAL int esp32_Transform_Sha256_demo(struct wc_Sha256* sha256, const byte* data);
#endif

    /* TODO do we really call esp_sha512_process for WOLFSSL_SHA384 ? */
    #if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
    struct wc_Sha512;
    WOLFSSL_LOCAL int esp_sha384_ctx_copy(struct wc_Sha512* src, struct wc_Sha512* dst);
    WOLFSSL_LOCAL int esp_sha512_ctx_copy(struct wc_Sha512* src, struct wc_Sha512* dst);
    WOLFSSL_LOCAL int esp_sha512_process(struct wc_Sha512* sha);
    WOLFSSL_LOCAL int esp_sha512_digest_process(struct wc_Sha512* sha, byte blockproc);
#endif

#endif /* NO_SHA && etc */


#if !defined(NO_RSA) || defined(HAVE_ECC)

    #if !defined(ESP_RSA_TIMEOUT_CNT)
        #define ESP_RSA_TIMEOUT_CNT     0x249F00
    #endif

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
    /*
     * The parameter names in the Espressif implementation are arbitrary.
     *
     * The wolfSSL names come from DH: Y=G^x mod M  (see wolfcrypt/tfm.h)
     *
     * G=base, X is the private exponent, Y is the public value w
     **/

    /* Z = (X ^ Y) mod M   : Espressif generic notation    */
    /* Y = (G ^ X) mod P   : wolfSSL DH reference notation */
    WOLFSSL_LOCAL int esp_mp_exptmod(MATH_INT_T* X,    /* G  */
                                     MATH_INT_T* Y,    /* X  */
                                     MATH_INT_T* M,    /* P  */
                                     MATH_INT_T* Z);   /* Y  */
    /* HW_MATH_ENABLED is typically used in wolfcrypt tests */
    #undef  HW_MATH_ENABLED
    #define HW_MATH_ENABLED
    #endif /* ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */

    #ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
        /* Z = X * Y */
    WOLFSSL_LOCAL int esp_mp_mul(MATH_INT_T* X,
                                 MATH_INT_T* Y,
                                 MATH_INT_T* Z);
    /* HW_MATH_ENABLED is typically used in wolfcrypt tests */
    #undef  HW_MATH_ENABLED
    #define HW_MATH_ENABLED
#endif /* ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL */

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    /* Z = X * Y (mod M) */
    WOLFSSL_LOCAL int esp_mp_mulmod(MATH_INT_T* X,
                                    MATH_INT_T* Y,
                                    MATH_INT_T* M,
                                    MATH_INT_T* Z);
    /* HW_MATH_ENABLED is typically used in wolfcrypt tests */
    #undef  HW_MATH_ENABLED
    #define HW_MATH_ENABLED
#endif /* ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD */

#endif /* !NO_RSA || HAVE_ECC*/


    WOLFSSL_LOCAL int esp_hw_validation_active(void);

#ifdef WOLFSSL_HW_METRICS
    int esp_hw_show_mp_metrics(void);
#endif

#define ESP_MP_HW_LOCK_MAX_DELAY ( TickType_t ) 0xffUL

/*
 * Errata Mitigation. See
 * https://www.espressif.com/sites/default/files/documentation/esp32_errata_en.pdf
 * https://www.espressif.com/sites/default/files/documentation/esp32-c3_errata_en.pdf
 * https://www.espressif.com/sites/default/files/documentation/esp32-s3_errata_en.pdf
 */
#if defined(CONFIG_IDF_TARGET_ESP32) && !defined(ESP_NO_ERRATA_MITIGATION)
    /* some of these may be tuned for specific silicon versions */
    #define ESP_EM__MP_HW_WAIT_CLEAN     {__asm__ __volatile__("memw");}
    #define ESP_EM__MP_HW_WAIT_DONE      {__asm__ __volatile__("memw");}
    #define ESP_EM__POST_SP_MP_HW_LOCK   {__asm__ __volatile__("memw");}
    #define ESP_EM__PRE_MP_HW_WAIT_CLEAN {__asm__ __volatile__("memw");}
    #define ESP_EM__PRE_DPORT_READ       {__asm__ __volatile__("memw");}
    #define ESP_EM__PRE_DPORT_WRITE      {__asm__ __volatile__("memw");}

    /* Non-FIFO read may not be needed in chip revision v3.0. */
    #define ESP_EM__READ_NON_FIFO_REG    {DPORT_SEQUENCE_REG_READ(0x3FF40078);}

    /* When the CPU frequency is 160 MHz, add six �nop� between two consecutive
    ** FIFO reads. When the CPU frequency is 240 MHz, add seven �nop� between
    ** two consecutive FIFO reads.  See 3.16 */
    #if defined(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_80)
        #define ESP_EM__3_16 { \
            __asm__ __volatile__("memw");              \
            __asm__ __volatile__("nop"); /* 1 */       \
            __asm__ __volatile__("nop"); /* 2 */       \
            __asm__ __volatile__("nop"); /* 3 */       \
            __asm__ __volatile__("nop"); /* 4 */       \
            __asm__ __volatile__("nop"); /* 5 */       \
        };
    #elif defined(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_160)
        #define ESP_EM__3_16 { \
            __asm__ __volatile__("memw");              \
            __asm__ __volatile__("nop"); /* 1 */       \
            __asm__ __volatile__("nop"); /* 2 */       \
            __asm__ __volatile__("nop"); /* 3 */       \
            __asm__ __volatile__("nop"); /* 4 */       \
            __asm__ __volatile__("nop"); /* 5 */       \
            __asm__ __volatile__("nop"); /* 6 */       \
            __asm__ __volatile__("nop"); /* 7 */       \
        };
    #elif defined(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240)
        #define ESP_EM__3_16 { \
            __asm__ __volatile__("memw");              \
            __asm__ __volatile__("nop"); /* 1 */       \
            __asm__ __volatile__("nop"); /* 2 */       \
            __asm__ __volatile__("nop"); /* 3 */       \
            __asm__ __volatile__("nop"); /* 4 */       \
            __asm__ __volatile__("nop"); /* 5 */       \
            __asm__ __volatile__("nop"); /* 6 */       \
            __asm__ __volatile__("nop"); /* 7 */       \
            __asm__ __volatile__("nop"); /* 8 */       \
            __asm__ __volatile__("nop"); /* 9 */       \
        };
    #else
        #define ESP_EM__3_16  {};
    #endif

    #define ESP_EM__POST_PROCESS_START { ESP_EM__3_16 };
    #define ESP_EM__DPORT_FIFO_READ    { ESP_EM__3_16 };
#else
    #define ESP_EM__3_16                 {};
    #define ESP_EM__MP_HW_WAIT_CLEAN     {};
    #define ESP_EM__MP_HW_WAIT_DONE      {};
    #define ESP_EM__POST_SP_MP_HW_LOCK   {};
    #define ESP_EM__PRE_MP_HW_WAIT_CLEAN {};
    #define ESP_EM__POST_PROCESS_START   {};
    #define ESP_EM__DPORT_FIFO_READ      {};
    #define ESP_EM__READ_NON_FIFO_REG    {};
    #define ESP_EM__PRE_DPORT_READ       {};
    #define ESP_EM__PRE_DPORT_WRITE      {};
#endif

/* end c++ wrapper */
#ifdef __cplusplus
}
#endif

#endif  /* __ESP32_CRYPT_H__ */
