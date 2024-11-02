/* esp32_mp.c
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
 * See ESP32 Technical Reference Manual - RSA Accelerator Chapter
 *
 * esp_mp_exptmod()  Large Number Modular Exponentiation Z = X^Y mod M
 * esp_mp_mulmod()   Large Number Modular Multiplication Z = X * Y mod M
 * esp_mp_mul()      Large Number Multiplication         Z = X * Y
 *
 * The ESP32 RSA Accelerator supports operand lengths of:
 * N in {512, 1024, 1536, 2048, 2560, 3072, 3584, 4096} bits. The bit length
 * of arguments Z, X, Y , M, and r can be any one from the N set, but all
 * numbers in a calculation must be of the same length.
 *
 * The bit length of M' is always 32.
 *
 * Also, beware: "we have uint32_t == unsigned long for both Xtensa and RISC-V"
 * see https://github.com/espressif/esp-idf/issues/9511#issuecomment-1207342464
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Reminder: user_settings.h is needed and included from settings.h
 * Be sure to define WOLFSSL_USER_SETTINGS, typically in CMakeLists.txt */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF */
#include "sdkconfig.h" /* programmatically generated from sdkconfig */
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#if !defined(NO_RSA) || defined(HAVE_ECC)

#if defined(WOLFSSL_ESP32_CRYPT_RSA_PRI) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI)

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#include <wolfssl/wolfcrypt/wolfmath.h>

#ifndef SINGLE_THREADED
    /* Espressif freeRTOS */
    #include <freertos/semphr.h>
#endif

#define ESP_HW_RSAMIN_BIT           512
#define ESP_HW_RSAMAX_BIT           4096
#if defined(CONFIG_IDF_TARGET_ESP32)
    /* See 24.3.2 Large Number Modular Exponentiation:
     *     esp32_technical_reference_manual_en.pdf
     * The RSA Accelerator supports specific operand lengths of N
     * {512, 1024, 1536, 2048, 2560, 3072, 3584, 4096} bits
     *
     * 24.3.4 Large Number Multiplication
     * The length of Z is twice that of X and Y . Therefore, the RSA Accelerator
     * supports large-number multiplication with only four operand lengths of
     * N in {512, 1024, 1536, 2048} */
    #define ESP_HW_MOD_RSAMAX_BITS      4096
    #define ESP_HW_MULTI_RSAMAX_BITS    2048
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    /* See 18.3.1 Large Number Modular Exponentiation
     *     esp32-s2_technical_reference_manual_en.pdf
     * RSA Accelerator supports operands of length N = (32 * x),
     * where x in {1, 2, 3, . . . , 128}. The bit lengths of arguments
     * Z, X, Y , M, and r can be arbitrary N, but all numbers in a calculation
     * must be of the same length. 32 * 128 = 4096 */
    #define ESP_HW_MOD_RSAMAX_BITS      4096
    #define ESP_HW_MULTI_RSAMAX_BITS    2048
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    /* See 20.3.1 Large Number Modular Exponentiation
     *     esp32-s3_technical_reference_manual_en.pdf
     * RSA Accelerator supports operands of length N = (32 * x),
     * where x in {1, 2, 3, . . . , 128}. The bit lengths of arguments
     * Z, X, Y , M, and r can be arbitrary N, but all numbers in a calculation
     * must be of the same length. 32 * 128 = 4096 */
    #define ESP_HW_MOD_RSAMAX_BITS      4096
    #define ESP_HW_MULTI_RSAMAX_BITS    2048
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* See 20.3.1 Large Number Modular Exponentiation
     *     esp32-c3_technical_reference_manual_en.pdf
     * RSA Accelerator supports operands of length N = (32 * x),
     * where x in {1, 2, 3, . . . , 96}. The bit lengths of arguments
     * Z, X, Y , M, and r can be arbitrary N, but all numbers in a calculation
     * must be of the same length. 32 * 96 = 3072 */
    #define ESP_HW_MOD_RSAMAX_BITS      3072
    /* The length of result Z is twice that of operand X and operand Y.
     * Therefore, the RSA accelerator only supports large-number multiplication
     * with operand length N = 32 * x, where x in {1, 2, 3, . . . , 48}.
     * 32 * (96/2) = 32 * (48/2) = 1536 */
    #define ESP_HW_MULTI_RSAMAX_BITS    1536
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    /* See 22.3.1 Large-number Modular Exponentiation
     *   esp32-c6_technical_reference_manual_en.pdf
     * The RSA accelerator supports operands of length N = (32 * x),
     * where x in {1, 2, 3, . . . , 96}. The bit lengths of arguments
     * Z, X, Y , M, and r can be arbitrary N, but all numbers in a calculation
     * must be of the same length. 32 * 96 = 3072 */
    #define ESP_HW_MOD_RSAMAX_BITS      3072
    /* The length of result Z is twice that of operand X and operand Y.
     * Therefore, the RSA accelerator only supports large-number multiplication
     * with operand length N = 32 * x, where x in {1, 2, 3, . . . , 48}.
     * 32 * (96/2) = 32 * (48/2) = 1536 */
    #define ESP_HW_MULTI_RSAMAX_BITS    1536
#else
    /* No HW on ESP8266, but then we'll not even use this lib.
     * Other ESP32 devices not implemented: */
    #define ESP_HW_MOD_RSAMAX_BITS      0
    #define ESP_HW_MULTI_RSAMAX_BITS    0
#endif

/* (s+(4-1))/ 4    */
#define BYTE_TO_WORDS(s)            (((s+3)>>2))

/* (s+(32-1))/ 8/ 4*/
#define BITS_TO_WORDS(s)            (((s+31)>>3)>>2)

#define BITS_IN_ONE_WORD            32

/* Some minimum operand sizes, fall back to SW if too small: */
#ifndef ESP_RSA_MULM_BITS
    #define ESP_RSA_MULM_BITS 16
#endif

#ifndef ESP_RSA_EXPT_XBITS
    #define ESP_RSA_EXPT_XBITS 8
#endif

#ifndef ESP_RSA_EXPT_YBITS
    #define ESP_RSA_EXPT_YBITS 8
#endif

/* RSA math calculation timeout */
#ifndef ESP_RSA_TIMEOUT_CNT
    #define ESP_RSA_TIMEOUT_CNT 0x5000000
#endif
#define ESP_TIMEOUT(cnt)         (cnt >= ESP_RSA_TIMEOUT_CNT)

/* Hardware Ready Timeout */
#ifndef ESP_RSA_WAIT_TIMEOUT_CNT
    #define ESP_RSA_WAIT_TIMEOUT_CNT 0x20
#endif
#define ESP_WAIT_TIMEOUT(cnt)    (cnt >= ESP_RSA_WAIT_TIMEOUT_CNT)

#if defined(CONFIG_IDF_TARGET_ESP32C3)
    #include <soc/system_reg.h>
    #include <soc/hwcrypto_reg.h>
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    #include <soc/pcr_reg.h>
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #include <soc/system_reg.h>
    #include <soc/hwcrypto_reg.h>
#endif

static const char* const TAG = "wolfssl_esp32_mp";

#ifdef DEBUG_WOLFSSL
    static int hw_validation = 0; /* validating HW and SW? (prevent HW call) */
    #define SET_HW_VALIDATION {hw_validation = 1;}
    #define CLR_HW_VALIDATION {hw_validation = 0;}
    #define IS_HW_VALIDATION (hw_validation == 1)
    #undef WOLFSSL_HW_METRICS

    /* usage metrics always on during debug */
    #define WOLFSSL_HW_METRICS
#endif

/* For esp_mp_exptmod and esp_mp_mulmod we need a variety of calculated helper
** values to properly setup the hardware. See esp_mp_montgomery_init() */
struct esp_mp_helper
{
    MATH_INT_T r_inv; /* result of calculated Montgomery helper */
    word32 exp;
    word32 Xs;  /* how many bits in X operand  */
    word32 Ys;  /* how many bits in Y operand  */
    word32 Ms;  /* how many bits in M operand  */
    word32 Rs;  /* how many bits in R_inv calc */
    word32 maxWords_sz; /* maximum words expected */
    word32 hwWords_sz;
    mp_digit mp; /* result of calculated Montgomery M' helper */
#ifdef DEBUG_WOLFSSL
    mp_digit mp2; /* optional compare to alternate Montgomery calc */
#endif
};

static portMUX_TYPE wc_rsa_reg_lock = portMUX_INITIALIZER_UNLOCKED;

/* usage metrics can be turned on independently of debugging */
#ifdef WOLFSSL_HW_METRICS
        static unsigned long esp_mp_max_used = 0;

        static unsigned long esp_mp_max_timeout = 0; /* Calc duration */
        static unsigned long esp_mp_max_wait_timeout; /* HW wait duration */

    /* HW Multiplication Metrics */
    #ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
        static unsigned long esp_mp_mul_usage_ct = 0;
        static unsigned long esp_mp_mul_error_ct = 0;
        static unsigned long esp_mp_mul_tiny_ct = 0;
        static unsigned long esp_mp_mul_max_exceeded_ct = 0;
    #endif /* !NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL */

    /* HW Modular Multiplication Metrics */
    #ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
        static unsigned long esp_mp_mulmod_small_x_ct = 0;
        static unsigned long esp_mp_mulmod_small_y_ct = 0;
        static unsigned long esp_mp_mulmod_max_exceeded_ct = 0;
        static unsigned long esp_mp_mulmod_usage_ct = 0;
        static unsigned long esp_mp_mulmod_fallback_ct = 0;
        static unsigned long esp_mp_mulmod_even_mod_ct = 0;
        static unsigned long esp_mp_mulmod_error_ct = 0;
     #endif

    /* HW Modular Exponentiation Metrics */
    #ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
        static unsigned long esp_mp_exptmod_usage_ct = 0;
        static unsigned long esp_mp_exptmod_error_ct = 0;
        static unsigned long esp_mp_exptmod_max_exceeded_ct = 0;
        static unsigned long esp_mp_exptmod_fallback_ct = 0;
    #endif /* !NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */
#endif /* WOLFSSL_HW_METRICS */

/* mutex */
#ifdef SINGLE_THREADED
    /* Although freeRTOS is multithreaded, if we know we'll only be in
     * a single thread for wolfSSL, we can avoid the complexity of mutexes. */
    static int single_thread_locked = 0;
#else
    static wolfSSL_Mutex mp_mutex;
    static int espmp_CryptHwMutexInit = 0;
#endif

#ifdef DEBUG_WOLFSSL
    /* when debugging, we'll double-check the mutex with call depth */
    #ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
        static int esp_mp_exptmod_depth_counter = 0;
    #endif /* NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */
#endif /* DEBUG_WOLFSSL */

/*
* check if the HW is ready before accessing it
*
* See 24.3.1 Initialization of ESP32 Technical Reference Manual
*   esp32_technical_reference_manual_en.pdf
*
* The RSA Accelerator is activated by enabling the corresponding peripheral
* clock, and by clearing the DPORT_RSA_PD bit in the DPORT_RSA_PD_CTRL_REG
* register. This releases the RSA Accelerator from reset.
*
* See esp_mp_hw_lock().
*
* Note we'll also keep track locally if the lock was called at all.
* For instance, fallback to SW for very small operand and we won't lock HW.
*
* When the RSA Accelerator is released from reset, the register RSA_CLEAN_REG
* reads 0 and an initialization process begins. Hardware initializes the four
* memory blocks by setting them to 0. After initialization is complete,
* RSA_CLEAN_REG reads 1. For this reason, software should query RSA_CLEAN_REG
* after being released from reset, and before writing to any RSA Accelerator
* memory blocks or registers for the first time.
*/
static int esp_mp_hw_wait_clean(void)
{
    int ret = MP_OKAY;
    word32 timeout = 0;

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* RSA_CLEAN_REG is now called RSA_QUERY_CLEAN_REG.
    ** hwcrypto_reg.h maintains RSA_CLEAN_REG for backwards compatibility:
    ** so this block _might_ not be needed in some circumstances. */
    ESP_EM__PRE_MP_HW_WAIT_CLEAN

    /* wait until ready,
    ** or timeout counter exceeds ESP_RSA_TIMEOUT_CNT in user_settings */
    while(!ESP_TIMEOUT(++timeout) && DPORT_REG_READ(RSA_CLEAN_REG) == 0) {
        /*  wait. expected delay 1 to 2 uS  */
        ESP_EM__MP_HW_WAIT_CLEAN
    }
#elif defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6)
    ESP_EM__PRE_MP_HW_WAIT_CLEAN
    while (!ESP_TIMEOUT(++timeout) &&
        DPORT_REG_READ(RSA_QUERY_CLEAN_REG) != 1) {
        /*  wait. expected delay 1 to 2 uS  */
        ESP_EM__MP_HW_WAIT_CLEAN
    }
#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    ESP_EM__PRE_MP_HW_WAIT_CLEAN
    while (!ESP_TIMEOUT(++timeout) &&
            DPORT_REG_READ(RSA_QUERY_CLEAN_REG) != 1) {
        /*  wait. expected delay 1 to 2 uS  */
        ESP_EM__MP_HW_WAIT_CLEAN
    }
#else
    /* no HW timeout if we don't know the platform. assumes no HW */
#endif

#if defined(WOLFSSL_HW_METRICS)
    /* The wait timeout is separate from the overall max calc timeout. */
    if (timeout > esp_mp_max_wait_timeout) {
        esp_mp_max_wait_timeout = timeout;
    }
    /* Also see if the overall timeout has been increased. */
    if (timeout > esp_mp_max_timeout) {
        esp_mp_max_timeout = timeout;
    }
#endif

    if (ESP_TIMEOUT(timeout)) {
        /* This is highly unusual and will likely only occur in multi-threaded
         * application. wolfSSL ctx is not thread safe. */
    #ifndef SINGLE_THREADED
        ESP_LOGI(TAG, "Consider #define SINGLE_THREADED. See docs");
    #endif
        ESP_LOGE(TAG, "esp_mp_hw_wait_clean waiting HW ready timed out.");
        ret = WC_HW_WAIT_E; /* hardware is busy, MP_HW_BUSY; */
    }
    return ret;
}

/*
** esp_mp_hw_islocked() - detect if we've locked the HW for use.
**
** WARNING: this does *not* detect separate calls to the
**          periph_module_disable() and periph_module_enable().
*/
static int esp_mp_hw_islocked(void)
{
    int ret = FALSE;
#ifdef SINGLE_THREADED
    if (single_thread_locked == FALSE) {
        /* not in use */
        ESP_LOGV(TAG, "SINGLE_THREADED esp_mp_hw_islocked = false");
    }
    else {
        ESP_LOGV(TAG, "SINGLE_THREADED esp_mp_hw_islocked = true");
        ret = TRUE;
    }
#else
    TaskHandle_t mutexHolder = xSemaphoreGetMutexHolder(mp_mutex);
    if (mutexHolder == NULL) {
        /* Mutex is not in use */
        ESP_LOGV(TAG, "multi-threaded esp_mp_hw_islocked = false");
    }
    else {
        ESP_LOGV(TAG, "multi-threaded esp_mp_hw_islocked = true");
        ret = TRUE;
    }
#endif
    return ret;
}

/*
* esp_mp_hw_lock()
*
* Lock HW engine.
* This should be called before using engine.
*
* Returns 0 (ESP_OK) if the HW lock was initialized and mutex lock.
*
* See Chapter 24:
*   esp32_technical_reference_manual_en.pdf
*
* The RSA Accelerator is activated by enabling the corresponding peripheral
* clock, and by clearing the DPORT_RSA_PD bit in the DPORT_RSA_PD_CTRL_REG
* register. This releases the RSA Accelerator from reset.
*
* When the RSA Accelerator is released from reset, the register RSA_CLEAN_REG
* reads 0 and an initialization process begins. Hardware initializes the four
* memory blocks by setting them to 0. After initialization is complete,
* RSA_CLEAN_REG reads 1. For this reason, software should query RSA_CLEAN_REG
* after being released from reset, and before writing to any RSA Accelerator
* memory blocks or registers for the first time.
*/
static int esp_mp_hw_lock(void)
{
    int ret = ESP_OK;

    ESP_LOGV(TAG, "enter esp_mp_hw_lock");
#ifdef SINGLE_THREADED
    single_thread_locked = TRUE;
#else
    if (espmp_CryptHwMutexInit == ESP_OK) {
        ret = esp_CryptHwMutexInit(&mp_mutex);
        if (ret == ESP_OK) {
            /* flag esp mp as initialized */
            espmp_CryptHwMutexInit = TRUE;
        }
        else {
            ESP_LOGE(TAG, "mp mutex initialization failed.");
        }
    }
    else {
        /* mp_mutex has already been initialized */
    }

    /* Set our mutex to indicate the HW is in use */
    if (ret == ESP_OK) {
        /* lock hardware; there should be exactly one instance
         * of esp_CryptHwMutexLock(&mp_mutex ...) in code  */

        ret = esp_CryptHwMutexLock(&mp_mutex, ESP_MP_HW_LOCK_MAX_DELAY);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "mp engine lock failed.");
            ret = WC_HW_WAIT_E; /* caller is expected to fall back to SW */
        }
   }
#endif /* not SINGLE_THREADED */

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* Enable RSA hardware */
    if (ret == ESP_OK) {
        periph_module_enable(PERIPH_RSA_MODULE);
        portENTER_CRITICAL_SAFE(&wc_rsa_reg_lock);
        {
            /* clear bit to enable hardware operation; (set to disable) */
            DPORT_REG_CLR_BIT(DPORT_RSA_PD_CTRL_REG, DPORT_RSA_PD);
            ESP_EM__POST_SP_MP_HW_LOCK

        }
        portEXIT_CRITICAL_SAFE(&wc_rsa_reg_lock);
    }
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* Activate the RSA accelerator. See 20.3 of ESP32-C3 technical manual.
     * periph_module_enable doesn't seem to be documented and in private folder
     * with v5 release. Maybe it will be deprecated?
     *
     * The ESP32-C3 RSA Accelerator is activated by:
     * setting the SYSTEM_CRYPTO_RSA_CLK_EN bit in the SYSTEM_PERIP_CLK_EN1_REG
     * register and:
     * clearing the SYSTEM_RSA_MEM_PD bit in the SYSTEM_RSA_PD_CTRL_REG reg.
     * This releases the RSA Accelerator from reset.*/
    if (ret == ESP_OK) {
        periph_module_enable(PERIPH_RSA_MODULE);
        portENTER_CRITICAL_SAFE(&wc_rsa_reg_lock);
        {
            DPORT_REG_SET_BIT((volatile void *)(SYSTEM_PERIP_CLK_EN1_REG),
                                                SYSTEM_CRYPTO_RSA_CLK_EN );
            DPORT_REG_CLR_BIT((volatile void *)(SYSTEM_RSA_PD_CTRL_REG),
                                                SYSTEM_RSA_MEM_PD );
        }
        portEXIT_CRITICAL_SAFE(&wc_rsa_reg_lock);
    }
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    /* See: 21.3 Functional Description
     *
     * The RSA accelerator is activated on the ESP32-C6 by:
     *   setting  the PCR_RSA_CLK_EN bit
     *      and
     *   clearing the PCR_RSA_RST_EN bit
     * in the PCR_RSA_CONF_REG register.
     *
     * Additionally, users also need to clear PCR_DS_RST_EN bit to
     * reset Digital Signature (DS).*/
    if (ret == ESP_OK) {
        periph_module_enable(PERIPH_RSA_MODULE);
        portENTER_CRITICAL_SAFE(&wc_rsa_reg_lock);
        {
            /* TODO: When implementing DS (Digital Signature HW), need to
             * check if it is in use before disabling: */
            DPORT_REG_CLR_BIT((volatile void *)(PCR_DS_CONF_REG),
                                                PCR_DS_RST_EN );

            DPORT_REG_SET_BIT((volatile void *)(PCR_RSA_CONF_REG),
                                                PCR_RSA_CLK_EN );
            DPORT_REG_CLR_BIT((volatile void *)(PCR_RSA_CONF_REG),
                                                PCR_RSA_RST_EN );
        }
        portEXIT_CRITICAL_SAFE(&wc_rsa_reg_lock);
    }
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    /* Activate the RSA accelerator. See 18.3 of ESP32-S2 technical manual.
     * periph_module_enable doesn't seem to be documented and in private folder
     * with v5 release. Maybe it will be deprecated? */
    if (ret == ESP_OK) {
        periph_module_enable(PERIPH_RSA_MODULE);
        portENTER_CRITICAL_SAFE(&wc_rsa_reg_lock);
        {
            /* Note these names are different from those in the documentation!
             *
             * Documentation lists the same names as the ESP32-C3:
             *
             * DPORT_REG_SET_BIT((volatile void *)(SYSTEM_PERIP_CLK_EN1_REG),
             *                   SYSTEM_CRYPTO_RSA_CLK_EN );
             * DPORT_REG_CLR_BIT((volatile void *)(SYSTEM_RSA_PD_CTRL_REG),
             *                   SYSTEM_RSA_MEM_PD );
             *
             * However, in the sytem_reg.h, the names below were found:
             */
            DPORT_REG_SET_BIT((volatile void *)(DPORT_CPU_PERIP_CLK_EN1_REG),
                                                DPORT_CRYPTO_RSA_CLK_EN );
            DPORT_REG_CLR_BIT((volatile void *)(DPORT_RSA_PD_CTRL_REG),
                                                DPORT_RSA_MEM_PD );
        }
        portEXIT_CRITICAL_SAFE(&wc_rsa_reg_lock);
    }
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    /* Activate the RSA accelerator. See 20.3 of ESP32-S3 technical manual.
     * periph_module_enable doesn't seem to be documented and in private folder
     * with v5 release. Maybe it will be deprecated? */
    if (ret == ESP_OK) {
        periph_module_enable(PERIPH_RSA_MODULE);
        portENTER_CRITICAL_SAFE(&wc_rsa_reg_lock);
        {
            /* clear bit to enable hardware operation; (set to disable) */
            DPORT_REG_CLR_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);
        }
        portEXIT_CRITICAL_SAFE(&wc_rsa_reg_lock);
    }
#else
    /* when unknown or not implemented, assume there's no HW to lock */
#endif

    /* reminder: wait until RSA_CLEAN_REG reads 1
    **   see esp_mp_hw_wait_clean() */
    ESP_LOGV(TAG, "leave esp_mp_hw_lock");
    return ret;
}

/*
**  Release RSA HW engine
*/
static int esp_mp_hw_unlock(void)
{
    int ret = MP_OKAY;
    if (esp_mp_hw_islocked()) {

#if defined(CONFIG_IDF_TARGET_ESP32)
        /* set bit to disabled hardware operation; (clear to enable) */
        DPORT_REG_SET_BIT(DPORT_RSA_PD_CTRL_REG, DPORT_RSA_PD);

        /* Disable RSA hardware */
        periph_module_disable(PERIPH_RSA_MODULE);
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
        /* Deactivate the RSA accelerator.
         * See 20.3 of ESP32-C3 technical manual.
         * periph_module_enable doesn't seem to be documented and in private
         * folder with v5 release. Maybe it will be deprecated?
         * The ESP32-C3 RSA Accelerator is activated by:
         * setting the SYSTEM_CRYPTO_RSA_CLK_EN bit
         *      in the SYSTEM_PERIP_CLK_EN1_REG register and:
         * clearing the SYSTEM_RSA_MEM_PD bit
         *      in the SYSTEM_RSA_PD_CTRL_REG reg.
         * This releases the RSA Accelerator from reset.*/
        portENTER_CRITICAL_SAFE(&wc_rsa_reg_lock);
        {
            DPORT_REG_CLR_BIT(
                 (volatile void *)(DR_REG_RSA_BASE + SYSTEM_CRYPTO_RSA_CLK_EN),
                                   SYSTEM_PERIP_CLK_EN1_REG);
            DPORT_REG_SET_BIT(
                (volatile void *)(DR_REG_RSA_BASE + SYSTEM_RSA_MEM_PD),
                                  SYSTEM_RSA_PD_CTRL_REG);
        }
        portEXIT_CRITICAL_SAFE(&wc_rsa_reg_lock);
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
        /* TODO: When implementing DS (Digital Signature HW), need to
         * notify RSA HW is available. */

        portENTER_CRITICAL_SAFE(&wc_rsa_reg_lock);
        {
            DPORT_REG_SET_BIT((volatile void *)(PCR_RSA_CONF_REG),
                                                PCR_RSA_RST_EN);
            DPORT_REG_CLR_BIT((volatile void *)(PCR_RSA_CONF_REG),
                                                PCR_RSA_CLK_EN);
        }
        portEXIT_CRITICAL_SAFE(&wc_rsa_reg_lock);

#elif defined(CONFIG_IDF_TARGET_ESP32S2)
        /* Deactivate the RSA accelerator.
         * See 20.3 of ESP32-S3 technical manual.
         * periph_module_enable doesn't seem to be documented and is
         * in private folder with v5 release. Maybe it will be deprecated? */
        DPORT_REG_SET_BIT(DPORT_RSA_PD_CTRL_REG, DPORT_RSA_MEM_PD);
        periph_module_disable(PERIPH_RSA_MODULE);

#elif defined(CONFIG_IDF_TARGET_ESP32S3)
        /* Deactivate the RSA accelerator.
         * See 20.3 of ESP32-S3 technical manual.
         * periph_module_enable doesn't seem to be documented and is
         * in private folder with v5 release. Maybe it will be deprecated? */
        DPORT_REG_SET_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);
        periph_module_disable(PERIPH_RSA_MODULE);
#else
        /* unknown platform, assume no HW to unlock  */
        ESP_LOGW(TAG, "Warning: esp_mp_hw_unlock called for unknown target");
#endif  /* per-SoC unlock */

#if defined(SINGLE_THREADED)
        single_thread_locked = FALSE;
#else
        esp_CryptHwMutexUnLock(&mp_mutex);
#endif /* SINGLE_THREADED */

        ESP_LOGV(TAG, "exit esp_mp_hw_unlock");
    }
    else {
#ifdef WOLFSSL_ESP32_HW_LOCK_DEBUG
        ESP_LOGW(TAG, "Warning: esp_mp_hw_unlock called when not locked.");
#endif
    }

    return ret;
}

/* Only mulmod and mulexp_mod HW accelerator need Montgomery math prep: M' */
#if !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD) \
      || \
    !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD)

static int esp_calc_Mdash(MATH_INT_T *M, word32 k, mp_digit* md)
{
    int ret = MP_OKAY;
    ESP_LOGV(TAG, "\nBegin esp_calc_Mdash \n");

#ifdef USE_ALT_MPRIME
    /* M' = M^(-1) mod b; b = 2^32 */

    /* Call Large Number Modular Exponentiation
     *
     *    Z = X^Y mod M
     *
     *    mp_exptmod notation: Y = (G ^ X) mod P
     *
     *    G is our parameter: M
     */
    MATH_INT_T X[1] = { };
    MATH_INT_T P[1] = { };
    MATH_INT_T Y[1] = { };
    word32 Xs;

    ESP_LOGV(TAG, "\nBegin esp_calc_Mdash USE_ALT_MPRIME\n");

    mp_init(X);
    mp_init(P);
    mp_init(Y);

    /* MATH_INT_T value of (-1) */
    X->dp[0] = 1;
    X->sign = MP_NEG;
    X->used = 1;

    Xs = mp_count_bits(X);

    /* MATH_INT_T value of 2^32 */
    P->dp[1] = 1;
    P->used = 2;

    /* this fails due to even P number; ((b & 1) == 0) in fp_montgomery_setup()
     * called from _fp_exptmod_ct, called from fp_exptmod */
    ret = mp_exptmod(M, X, P, Y);

    *md = Y->dp[0];
    ESP_LOGI(TAG, "esp_calc_Mdash %u", *md);
#else
    /* this is based on an article by Cetin Kaya Koc,
     * A New Algorithm for Inversion: mod p^k, June 28 2017 */
    int i;
    int xi;
    int b0 = 1;
    int bi;
    word32  N = 0;
    word32  x;
    ESP_LOGV(TAG, "\nBegin esp_calc_Mdash\n");

    N = M->dp[0];
    bi = b0;
    x  = 0;

    for (i = 0; i < k; i++) {
        xi = bi % 2;
        if (xi < 0) {
            xi *= -1;
        }
        bi = (bi - N * xi) / 2;
        x |= (xi << i);
    }
    /* 2's complement */
    *md = ~x + 1;
#endif

    ESP_LOGV(TAG, "\nEnd esp_calc_Mdash \n");
    return ret;
}
#endif /* !NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_[MULMOD/EXPTMOD] for M' */

/* the result may need to have extra bytes zeroed or used length adjusted */
static int esp_clean_result(MATH_INT_T* Z, int used_padding)
{
    int ret = MP_OKAY;
    uint16_t this_extra;

/* TODO remove this section if MP_SIZE accepted into sp_int.h
** See https://github.com/wolfSSL/wolfssl/pull/6565 */
    uint16_t dp_length = 0; (void) dp_length;
#ifdef USE_FAST_MATH
    #undef MP_SIZE
    #define MP_SIZE FP_SIZE
    dp_length = FP_SIZE;
#else
    #undef MP_SIZE
    #define MP_SIZE 128
    dp_length = SP_INT_DIGITS;
#endif
/* TODO end */

    this_extra = Z->used;
    if (this_extra > MP_SIZE) {
        ESP_LOGW(TAG, "Warning (Z->used: %d) > (MP_SIZE: %d); adjusting...",
                                Z->used,        MP_SIZE);
        this_extra = MP_SIZE;
    }

    while (Z->dp[this_extra] > 0 && (this_extra < MP_SIZE)) {
        ESP_LOGV(TAG, "Adjust! %d", this_extra);
        Z->dp[this_extra] = 0;
        this_extra++;
    }

    /* trim any trailing zeros and adjust z.used size */
    if (Z->used > 0) {
        ESP_LOGV(TAG, "ZTrim: Z->used = %d", Z->used);
        for (size_t i = Z->used; i > 0; i--) {
            if (Z->dp[i - 1] == 0) {
                /* last element in zero based array */
                Z->used = i - 1;
            }
            else {
                break; /* if not zero, nothing else to do */
            }
        }
        ESP_LOGV(TAG, "New Z->used = %d", Z->used);
    }
    else {
        ESP_LOGV(TAG, "no z-trim needed");
    }

#if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
    if (Z->sign != 0) {
        mp_setneg(Z); /* any value other than zero is assumed negative */
    }
#endif

    /* a result of 1 is interesting */
    if ((Z->dp[0] == 1) && (Z->used == 1)) {
        /*
         * When the exponent is 0: In this case, the result of the modular
         * exponentiation operation will always be 1, regardless of the value
         * of the base.
         *
         * When the base is 1: If the base is equal to 1, then the result of
         * the modular exponentiation operation will always be 1, regardless
         * of the value of the exponent.
         *
         * When the exponent is equal to the totient of the modulus: If the
         * exponent is equal to the totient of the modulus, and the base is
         * relatively prime to the modulus, then the result of the modular
         * exponentiation operation will be 1.
         */
        ESP_LOGV(TAG, "Z->dp[0] == 1");
    }

    return ret;
}

/* Start HW process. Reg is SoC-specific register. */
static int process_start(u_int32_t reg)
{
    int ret = MP_OKAY;
    /* see 3.16 "software needs to always use the "volatile"
    ** attribute when accessing registers in these two address spaces. */
    DPORT_REG_WRITE((volatile word32*)reg, 1);
    ESP_EM__POST_PROCESS_START;

    return ret;
}

/* wait until RSA math register indicates operation completed */
static int wait_until_done(word32 reg)
{
    int ret = MP_OKAY;
    word32 timeout = 0;

    /* wait until done && not timeout */
    ESP_EM__MP_HW_WAIT_DONE;
    while (!ESP_TIMEOUT(++timeout) && DPORT_REG_READ(reg) != 1) {
        asm volatile("nop"); /* wait */
    }
    ESP_EM__DPORT_FIFO_READ;

#if defined(CONFIG_IDF_TARGET_ESP32C6)
    /* Write 1 or 0 to the RSA_INT_ENA_REG register to
     * enable or disable the interrupt function. */
    DPORT_REG_WRITE(RSA_INT_CLR_REG, 1); /* write 1 to clear */
    DPORT_REG_WRITE(RSA_INT_ENA_REG, 0); /* disable */

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* not currently clearing / disable on C3 */
    DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

#else
    /* clear interrupt */
    DPORT_REG_WRITE(RSA_INTERRUPT_REG, 1);

#endif

#if defined(WOLFSSL_HW_METRICS)
    if (timeout > esp_mp_max_timeout) {
        esp_mp_max_timeout = timeout;
    }
#endif

    if (ESP_TIMEOUT(timeout)) {
        ESP_LOGE(TAG, "rsa operation timed out.");
        ret = WC_HW_E; /* MP_HW_ERROR; */
    }

    return ret;
}

/* read data from memory into mp_init          */
static int esp_memblock_to_mpint(const word32 mem_address,
                                 MATH_INT_T* mp,
                                 word32 numwords)
{
    int ret = MP_OKAY;
#ifdef USE_ESP_DPORT_ACCESS_READ_BUFFER
    esp_dport_access_read_buffer((word32*)mp->dp, mem_address, numwords);
#else
    ESP_EM__PRE_DPORT_READ;
    DPORT_INTERRUPT_DISABLE();
    ESP_EM__READ_NON_FIFO_REG;
    for (volatile word32 i = 0;  i < numwords; ++i) {
        ESP_EM__3_16;
        mp->dp[i] = DPORT_SEQUENCE_REG_READ(
                        (volatile word32)(mem_address + i * 4));
    }
    DPORT_INTERRUPT_RESTORE();
#endif
    mp->used = numwords;

#if defined(ESP_VERIFY_MEMBLOCK)
    ret = XMEMCMP((const word32 *)mem_address, /* HW reg memory */
                  (const word32 *)&mp->dp,     /* our dp value  */
                  numwords * sizeof(word32));

    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Validation Failure esp_memblock_to_mpint.\n"
                      "Reading %u Words at Address =  0x%08x",
                       (int)(numwords * sizeof(word32)),
                       (unsigned int)mem_address);
        ESP_LOGI(TAG, "Trying again... ");
        esp_dport_access_read_buffer((word32*)mp->dp, mem_address, numwords);
        mp->used = numwords;
        if (0 != XMEMCMP((const void *)mem_address,
                         (const void *)&mp->dp,
                         numwords * sizeof(word32))) {
            ESP_LOGE(TAG, "Validation Failure esp_memblock_to_mpint "
                           "a second time. Giving up.");
            ret = MP_VAL;
        }
        else {
            ESP_LOGI(TAG, "Successfully re-read after Validation Failure.");
            ret = MP_VAL;
        }
    }
#endif
    return ret;
}

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
/* Write 0x00 to [wordSz] words of register memory starting at mem_address */
#if defined(CONFIG_IDF_TARGET_ESP32)
/* only the classic has memblock clear due to slightly different data layout */
static int esp_zero_memblock(u_int32_t mem_address, int wordSz)
{
    int ret = MP_OKAY;

    ESP_EM__PRE_DPORT_WRITE;
    DPORT_INTERRUPT_DISABLE();
    for (int i=0; i < wordSz; i++) {
        DPORT_REG_WRITE(
            (volatile u_int32_t *)(mem_address + (i * sizeof(word32))),
            (u_int32_t)(0) /* zero memory blocks [wordSz] words long */
        );
    }
    DPORT_INTERRUPT_RESTORE();
    return ret;
}
#endif /* CONFIG_IDF_TARGET_ESP32 */
#endif /* not NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL */

/* write MATH_INT_T mp value (dp[]) into memory block */
static int esp_mpint_to_memblock(u_int32_t mem_address,
                                 const MATH_INT_T* mp,
                                 const word32 bits,
                                 const word32 hwords)
{
    int ret = MP_OKAY;

    /* init */
    word32 i; /* memory offset counter */
    word32 len; /* actual number of words to write to register */

    len = (bits / 8 + ((bits & 7) != 0 ? 1 : 0));
    len = (len + sizeof(word32)-1) / sizeof(word32);

    /* write */
    ESP_EM__PRE_DPORT_WRITE;
    DPORT_INTERRUPT_DISABLE();
    for (i=0; i < hwords; i++) {
        if (i < len) {
            /* write our data */
            ESP_LOGV(TAG, "Write i = %d value.", i);
            DPORT_REG_WRITE(
                (volatile u_int32_t*)(mem_address + (i * sizeof(word32))),
                mp->dp[i]
            ); /* DPORT_REG_WRITE */
        }
        else {
            /* write zeros */
            /* TODO we may be able to skip zero in certain circumstances */
            if (i == 0) {
                ESP_LOGV(TAG, "esp_mpint_to_memblock zero?");
            }
            ESP_LOGV(TAG, "Write i = %d value = zero.", i);
            DPORT_REG_WRITE(
                (volatile u_int32_t*)(mem_address + (i * sizeof(word32))),
                (u_int32_t)0 /* writing 4 bytes of zero */
            ); /* DPORT_REG_WRITE */
        }
    }
    DPORT_INTERRUPT_RESTORE();

    /* optional re-read verify */
#if defined(ESP_VERIFY_MEMBLOCK)
    len = XMEMCMP((const void *)mem_address, /* HW reg memory */
                  (const void *)&mp->dp,     /* our dp value  */
                  hwords * sizeof(word32)
                 );
    if (len != 0) {
        ESP_LOGE(TAG, "esp_mpint_to_memblock compare fails at %d", len);
    #ifdef DEBUG_WOLFSSL
        esp_show_mp("mp", (MATH_INT_T*)mp);
    #endif
        ret = MP_VAL;
    }
#endif
    return ret;
}

/* return needed HW words.
 * supported words length
 *  words    : { 16,   32,  48,    64,   80,   96,  112,  128}
 *  bits     : {512, 1024, 1536, 2048, 2560, 3072, 3584, 4096}
 */
static word32 words2hwords(word32 wd)
{
    const word32 bit_shift  = 4;

    return (((wd + 0xf) >> bit_shift) << bit_shift);
}

/* count the number of words is needed for bits */
static word32 bits2words(word32 bits)
{
    /* 32 bits */
    const word32 d = sizeof(word32) * WOLFSSL_BIT_SIZE;

    return ((bits + (d - 1)) / d);
}

/* exptmod and mulmod helpers as needed */
#if !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD) \
      ||  \
    !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD)
/* rinv and M' only used for mulmod and mulexp_mod */

/* get rinv */
static int esp_get_rinv(MATH_INT_T *rinv, MATH_INT_T *M, word32 exp)
{
#ifdef DEBUG_WOLFSSL
    MATH_INT_T rinv2[1];
    MATH_INT_T M2[1];
    int reti = MP_OKAY;
#endif
    int ret = MP_OKAY;

    ESP_LOGV(TAG, "\nBegin esp_get_rinv \n");
#ifdef DEBUG_WOLFSSL
    mp_copy(M, M2); /* copy (src = M) to (dst = M2) */
    mp_copy(rinv, rinv2); /* copy (src = M) to (dst = M2) */
#endif

    /* 2^(exp)
     *
     * rinv will have all zeros with a 1 in last word.
     * e.g. exp=2048 will have a 1 in dp[0x40] = dp[64]
     * this is the 65'th element (zero based)
     * Value for used = 0x41 = 65
     **/
    ret = mp_2expt(rinv, exp);
    if (ret == MP_OKAY) {
        ret = mp_mod(rinv, M, rinv);
    }
    else {
        ESP_LOGE(TAG, "failed to calculate mp_2expt()");
    }

    /* r_inv = R^2 mod M(=P) */
    if (ret == MP_OKAY) {
        ESP_LOGV(TAG, "esp_get_rinv compute success");
    }
    else {
        ESP_LOGE(TAG, "failed to calculate mp_mod()");
    }

#ifdef DEBUG_WOLFSSL
    if (ret == MP_OKAY) {

        /* computes a = B**n mod b without division or multiplication useful for
        * normalizing numbers in a Montgomery system. */
        reti = mp_montgomery_calc_normalization(rinv2, M2);
        if (reti == MP_OKAY) {
            ESP_LOGV(TAG, "mp_montgomery_calc_normalization = %d", reti);
        }
        else {
            ESP_LOGW(TAG, "Error Montgomery calc M2 result = %d", reti);
        }
    }
#endif

    ESP_LOGV(TAG, "\nEnd esp_get_rinv \n");
    return ret;
}
#endif /* ! xEXPTMOD || ! xMULMOD for rinv */

/* during debug, we'll compare HW to SW results */
int esp_hw_validation_active(void)
{
#ifdef DEBUG_WOLFSSL
    return IS_HW_VALIDATION;
#else
    return 0; /* we're never validating when not debugging */
#endif
}

/* useful during debugging and error display,
 * we can show all the mp helper calc values */
int esp_show_mph(struct esp_mp_helper* mph)
{
    int ret = MP_OKAY;

    if (mph == NULL) {
        /* if a bad mp helper passed, we cannot use HW */
        ESP_LOGE(TAG, "ERROR: Bad esp_mp_helper for esp_show_mph");
        return MP_VAL;
    }

    if (mph->Xs != 0)
        ESP_LOGI(TAG, "Xs %d", mph->Xs);
    if (mph->Ys != 0)
        ESP_LOGI(TAG, "Ys %d", mph->Ys);
    if (mph->Ms != 0)
        ESP_LOGI(TAG, "Ms %d", mph->Ms);
    if (mph->Rs != 0)
        ESP_LOGI(TAG, "Rs %d", mph->Rs);
    if (mph->maxWords_sz != 0)
        ESP_LOGI(TAG, "maxWords_sz %d", mph->maxWords_sz);
    if (mph->hwWords_sz != 0)
        ESP_LOGI(TAG, "hwWords_sz %d", mph->hwWords_sz);
    if (mph->mp != 0)
        ESP_LOGI(TAG, "mp %d", mph->mp);
#ifdef DEBUG_WOLFSSL
    if (mph->mp2 != 0)
        ESP_LOGI(TAG, "mp2 %d", mph->mp2);
#endif
    if (mph->r_inv.used != 0)
        esp_show_mp("r_inv", &(mph->r_inv));
    return ret;
}

#if !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD) \
      ||  \
    !defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD)
/* only when using exptmod or mulmod, we have some helper functions. */

/* given X, Y, M - setup mp hardware and other helper values.*/
int esp_mp_montgomery_init(MATH_INT_T* X, MATH_INT_T* Y, MATH_INT_T* M,
                           struct esp_mp_helper* mph)
{
    int ret = MP_OKAY;
    int exp;

    if (mph == NULL) {
        /* if a bad mp helper passed, we cannot use HW */
        ESP_LOGE(TAG, "ERROR: Bad esp_mp_helper, falling back to SW");
        return MP_HW_FALLBACK;
    }
    if ((X == NULL) || (Y == NULL) || (M == NULL) ) {
        /* if a bad operand passed, we cannot use HW */
        ESP_LOGE(TAG, "ERROR: Bad Montgomery operand, falling back to SW");
        return MP_HW_FALLBACK;
    }
    XMEMSET(mph, 0, sizeof(struct esp_mp_helper));
    mph->Xs = mp_count_bits(X); /* X's = the number of bits needed */

#if (ESP_PROHIBIT_SMALL_X == TRUE)
    /* optionally prohibit small X.
    ** note this is very common in ECC: [1] * [Y] mod [M] */
    if ((X->used == 1) && (X->dp[1] < (1 << 8))) {
    #ifdef WOLFSSL_HW_METRICS
        esp_mp_mulmod_small_x_ct++;
    #endif
        ESP_LOGW(TAG, "esp_mp_montgomery_init MP_HW_FALLBACK Xs = %d",
                       mph->Xs);
        ret = MP_HW_FALLBACK;
    }
#endif

    /* prohibit small Y */
    if (ret == MP_OKAY) {
        mph->Ys = mp_count_bits(Y); /* init Y's to pass to Montgomery init */

        if (mph->Xs <= ESP_RSA_EXPT_XBITS) {
            /* hard floor 8 bits, problematic in some older ESP32 chips */
            #ifdef WOLFSSL_HW_METRICS
            {
                /* track how many times we fall back */
                esp_mp_mulmod_small_x_ct++;
            }
            #endif
            ESP_LOGV(TAG,
                "esp_mp_montgomery_init MP_HW_FALLBACK Xs = %d",
                mph->Xs);
            ret = MP_HW_FALLBACK; /* fall back to software calc at exit */
        } /* mph->Xs <= ESP_RSA_EXPT_XBITS */
        else {
            if (mph->Ys <= ESP_RSA_EXPT_YBITS) {
            /* hard floor 8 bits, problematic in some older ESP32 chips */
            #ifdef WOLFSSL_HW_METRICS
            {
                /* track how many times we fall back */
                esp_mp_mulmod_small_y_ct++;
            }
            #endif
            ESP_LOGV(TAG,
                "esp_mp_montgomery_init MP_HW_FALLBACK Ys = %d",
                mph->Ys);
            ret = MP_HW_FALLBACK; /* fall back to software calc at exit */
            } /* Ys <= ESP_RSA_EXPT_YBITS */
            else {
                /* X and Y size ok, continue... */
                mph->Ms = mp_count_bits(M);
                /* maximum bits and words for writing to HW */
                mph->maxWords_sz = bits2words(max(mph->Xs,
                                                  max(mph->Ys, mph->Ms)));
                mph->hwWords_sz  = words2hwords(mph->maxWords_sz);

                if ((mph->hwWords_sz << 5) > ESP_HW_RSAMAX_BIT) {
            #if defined(WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS) || \
                defined(WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS)
                    ESP_LOGW(TAG, "Warning: hwWords_sz = %d (%d bits)"
                                  " exceeds HW maximum bits (%d), "
                                  " falling back to SW.",
                        mph->hwWords_sz,
                        mph->hwWords_sz << 5,
                        ESP_HW_RSAMAX_BIT);
            #endif
                    /* The fallback error code is expected to be handled by
                     * caller to perform software instead. */
                    ret = MP_HW_FALLBACK;
                } /* hwWords_sz check  */
            } /* X and Y size ok */
        } /* X size check */
    } /* Prior operation ok */

    ESP_LOGV(TAG, "hwWords_sz = %d", mph->hwWords_sz);

    /* calculate r_inv = R^2 mode M
    *    where: R = b^n, and b = 2^32
    *    accordingly R^2 = 2^(n*32*2)
    */
#if defined(CONFIG_IDF_TARGET_ESP32)
    exp = mph->hwWords_sz << 6;
#elif defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6)
    exp = mph->maxWords_sz * BITS_IN_ONE_WORD * 2;
#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    exp = mph->maxWords_sz * BITS_IN_ONE_WORD * 2;
#else
    exp = 0; /* no HW, no Montgomery HW init */
#endif

    if (ret == MP_OKAY && (M != NULL)) {
        ret = mp_init((mp_int*)&(mph->r_inv));
        if (ret == MP_OKAY) {
            ret = esp_get_rinv( (mp_int*)&(mph->r_inv), M, exp);
            if (ret == MP_OKAY) {
                mph->Rs = mp_count_bits((mp_int*)&(mph->r_inv));
            }
            else {
                ESP_LOGE(TAG, "calculate r_inv failed.");
                ret = MP_VAL;
            } /* esp_get_rinv check */
        } /* mp_init success */
        else {
            ESP_LOGE(TAG, "calculate r_inv failed mp_init.");
            ret = MP_MEM;
        } /* mp_init check */
    } /* calculate r_inv */

    /* if we were successful in r_inv, next get M' */
    if (ret == MP_OKAY) {
#ifdef DEBUG_WOLFSSL
        ret = mp_montgomery_setup(M, &(mph->mp2) );
#endif
        /* calc M' */
        /* if Pm is odd, uses mp_montgomery_setup() */
        ret = esp_calc_Mdash(M, 32/* bits */, &(mph->mp));
        if (ret != MP_OKAY) {
            ESP_LOGE(TAG, "failed esp_calc_Mdash()");
        }
    }

#ifdef DEBUG_WOLFSSL
    if (ret == MP_OKAY) {
        if (mph->mp == mph->mp2) {
            ESP_LOGV(TAG, "M' match esp_calc_Mdash vs mp_montgomery_setup "
                          "= %ul  !", mph->mp);
        }
        else {
            ESP_LOGW(TAG,
                     "\n\n"
                     "M' MISMATCH esp_calc_Mdash = 0x%08x = %d \n"
                     "vs mp_montgomery_setup     = 0x%08x = %d \n\n",
                     mph->mp,
                     mph->mp,
                     mph->mp2,
                     mph->mp2);
            mph->mp = mph->mp2;
        }
    }
    else {
    #if 0
        esp_show_mp("X", X);
        esp_show_mp("Y", Y);
        esp_show_mp("M", M);
        esp_show_mph(mph);
    #endif

        if (ret == MP_HW_FALLBACK) {
            ESP_LOGV(TAG, "esp_mp_montgomery_init exit falling back.");

        }
        else {
            ESP_LOGE(TAG, "esp_mp_montgomery_init failed: return code = %d",
                           ret);
        }
    }
#endif

    return ret;
} /* esp_mp_montgomery_init */

#endif /* ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_[EXPTMOD|MULMOD] */

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
/* Large Number Multiplication
 *
 * See 24.3.3 of the ESP32 Technical Reference Manual
 *
 * Z = X * Y;  */
int esp_mp_mul(MATH_INT_T* X, MATH_INT_T* Y, MATH_INT_T* Z)
{
/* During debug, we may be validating against SW result. */
#ifdef DEBUG_WOLFSSL
    /* create a place to store copies to perform duplicate operations.
    ** copies needed as some operations overwrite operands: e.g. X = X * Y */
    MATH_INT_T X2[1];
    MATH_INT_T Y2[1];
    MATH_INT_T Z2[1];
    MATH_INT_T PEEK[1];
#endif

    int ret = MP_OKAY; /* assume success until proven wrong */
    int mp_mul_lock_called = FALSE; /* May fall back to SW; track if locked */

    /* we don't use the mph helper for mp_mul, so we'll calculate locally: */
    word32 Xs;
    word32 Ys;
    word32 Zs;
    word32 maxWords_sz = 0;
    word32 hwWords_sz = 0;
    word32 resultWords_sz = 0;

#if defined(CONFIG_IDF_TARGET_ESP32)
    word32 left_pad_offset = 0;
#endif

/* if we are supporting negative numbers, check that first since operands
 * may be later modified (e.g. Z = Z * X) */
#if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
    /* neg check: X*Y becomes negative */
    int res_sign;

    /* aka (X->sign == Y->sign) ? MP_ZPOS : MP_NEG; , but with mp_isneg(): */
    res_sign = (mp_isneg(X) == mp_isneg(Y)) ? MP_ZPOS : MP_NEG;
    if (res_sign) {
        /* Negative numbers are relatively infrequent.
         * May be interesting during verbose debugging: */
        ESP_LOGV(TAG, "mp_isneg(X) = %d; mp_isneg(Y) = %d; neg = %d ",
                       mp_isneg(X),      mp_isneg(Y),           res_sign);
    }
#endif

#ifdef WOLFSSL_HW_METRICS
    esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used : esp_mp_max_used;
    esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used : esp_mp_max_used;
#endif

    /* if either operand is zero, there's nothing to do.
     * Y checked first, as it was observed to be zero during
     * wolfcrypt tests more often than X */
    if (mp_iszero(Y) || mp_iszero(X)) {
        mp_forcezero(Z);
        return MP_OKAY;
    }

#ifdef DEBUG_WOLFSSL
    /* The caller should have checked if the call was for a SW validation.
     * During debug, we'll return an error. */
    if (esp_hw_validation_active()) {
        return MP_HW_VALIDATION_ACTIVE;
    }

    /* these occur many times during RSA calcs */
    if (X == Z) {
        ESP_LOGV(TAG, "mp_mul X == Z");
    }
    if (Y == Z) {
        ESP_LOGV(TAG, "mp_mul Y == Z");
    }

    mp_init(X2);
    mp_init(Y2);
    mp_init(Z2);

    mp_copy(X, X2); /* copy (src = X) to (dst = X2) */
    mp_copy(Y, Y2); /* copy (src = Y) to (dst = Y2) */
    mp_copy(Z, Z2); /* copy (src = Z) to (dst = Z2) */

    if (IS_HW_VALIDATION) {
        ESP_LOGE(TAG, "Caller must not try HW when validation active.");
    }
    else {
        SET_HW_VALIDATION; /* force next mp_mul to SW for compare */
        mp_mul(X2, Y2, Z2);
        CLR_HW_VALIDATION;
    }
#endif /* DEBUG_WOLFSSL */

    Xs = mp_count_bits(X);
    Ys = mp_count_bits(Y);
    Zs = Xs + Ys;

    /* RSA Accelerator only supports Large Number Multiplication
     * with certain operand lengths N = (32 * x); See above. */
    if (Xs > ESP_HW_MULTI_RSAMAX_BITS) {
#if defined(WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS)
        ESP_LOGW(TAG, "mp-mul X %d bits exceeds max bit length (%d)",
                        Xs, ESP_HW_MULTI_RSAMAX_BITS);
#endif
        esp_mp_mul_max_exceeded_ct++;
        return MP_HW_FALLBACK;
    }
    if (Ys > ESP_HW_MULTI_RSAMAX_BITS) {
#if defined(WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS)
        ESP_LOGW(TAG, "mp-mul Y %d bits exceeds max bit length (%d)",
                        Ys, ESP_HW_MULTI_RSAMAX_BITS);
#endif
        esp_mp_mul_max_exceeded_ct++;
        return MP_HW_FALLBACK;
    }

    /* sizeof(mp_digit) is typically 4 bytes.
     * If the total Zs fits into a 4 * 8 = 32 bit word, just do regular math: */
    if (Zs <= sizeof(mp_digit) * 8) {
        Z->dp[0] = X->dp[0] * Y->dp[0];
        Z->used = 1;
#if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
        Z->sign = res_sign; /* See above mp_isneg() for negative detection */
#endif
#if defined(WOLFSSL_HW_METRICS)
        esp_mp_mul_tiny_ct++;
#endif
        return MP_OKAY;
    }

    if (ret == MP_OKAY) {
        /* maximum bits and words for writing to HW */
        maxWords_sz = bits2words(max(Xs, Ys));
        hwWords_sz  = words2hwords(maxWords_sz);

        resultWords_sz = bits2words(Xs + Ys);

        /* Final parameter sanity check */
        if ( (hwWords_sz << 5) > ESP_HW_MULTI_RSAMAX_BITS) {
    #if defined(WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS)
            ESP_LOGW(TAG, "mp-mul exceeds max bit length (%d)",
                           ESP_HW_MULTI_RSAMAX_BITS);
    #endif
    #if defined(WOLFSSL_HW_METRICS)
            esp_mp_mul_max_exceeded_ct++;
    #endif
            return MP_HW_FALLBACK; /*  Fallback to use SW */
        }
    }

    /* If no initial exit, proceed to hardware multiplication calculations: */
#if defined(CONFIG_IDF_TARGET_ESP32)
    /* assumed to be regular ESP32 Xtensa here */

    /*Steps to use HW in the following order:
    * 1. wait until clean HW engine
    * 2. Write(2*N/512bits - 1 + 8) to MULT_MODE_REG
    * 3. Write X and Y to memory blocks
    *    need to write data to each memory block only according to the length
    *    of the number.
    * 4. Write 1  to MUL_START_REG
    * 5. Wait for the first operation to be done.
    *      Poll INTERRUPT_REG until it reads 1.
    *      (Or until the INTER interrupt is generated.)
    * 6. Write 1 to RSA_INTERRUPT_REG to clear the interrupt.
    * 7. Read the Z from RSA_Z_MEM
    * 8. Write 1 to RSA_INTERUPT_REG to clear the interrupt.
    * 9. Release the HW engine
    */

    /* Y (left-extend)
     * Accelerator supports large-number multiplication with only
     * four operand lengths of N in {512, 1024, 1536, 2048} */
    left_pad_offset = maxWords_sz << 2;
    if (left_pad_offset <= 512 >> 3) {
        left_pad_offset = 512 >> 3; /* 64 bytes (16 words) */
    }
    else {
        if (left_pad_offset <= 1024 >> 3) {
            left_pad_offset = 1024 >> 3; /* 128 bytes = 32 words */
        }
        else {
            if (left_pad_offset <= 1536 >> 3) {
                left_pad_offset = 1536 >> 3; /* 192 bytes = 48 words */
            }
            else {
                if (left_pad_offset <= 2048 >> 3) {
                    left_pad_offset = 2048 >> 3; /* 256 bytes = 64 words */
                }
                else {
                    ret = MP_VAL;
                    ESP_LOGE(TAG, "Unsupported operand length: %d",
                                   hwWords_sz);
                }
            }
        }
    }

    /* lock HW for use, enable peripheral clock */
    if (ret == MP_OKAY) {
        mp_mul_lock_called = TRUE; /* we'll not try to unlock
                                    * unless we locked it here. */
        #ifdef WOLFSSL_HW_METRICS
        {
            /* Only track max values when using HW */
            esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used :
                                                            esp_mp_max_used;
            esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used :
                                                            esp_mp_max_used;
        }
        #endif

        ret = esp_mp_hw_lock();
    }

    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    if (ret == MP_OKAY) {
        /* step.1  (2*N/512) => N/256. 512 bits => 16 words */
        /* Write 2*N/512 - 1 + 8  */

        DPORT_REG_WRITE(RSA_MULT_MODE_REG,
                        (2 * left_pad_offset * 8 / 512) - 1 + 8);

        /* step.2 write X into memory */
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              Xs,
                              hwWords_sz);

        /* write zeros from RSA_MEM_Z_BLOCK_BASE to left_pad_offset - 1 */
        esp_zero_memblock(RSA_MEM_Z_BLOCK_BASE,
                          (left_pad_offset - 1) / sizeof(int));

        /* write the left-padded Y value into Z */
        esp_mpint_to_memblock(RSA_MEM_Z_BLOCK_BASE + (left_pad_offset),
                              Y,
                              Ys,
                              hwWords_sz);

    #ifdef DEBUG_WOLFSSL
        /* save value to peek at the result stored in RSA_MEM_Z_BLOCK_BASE */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE,
                              PEEK,
                              128);
    #endif

        /* step.3 start process                           */
        process_start(RSA_MULT_START_REG);

        /* step.4,5 wait until done                       */
        ret = wait_until_done(RSA_INTERRUPT_REG);

        /* step.6 read the result form MEM_Z              */
        if (ret == MP_OKAY) {
            esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, Z, resultWords_sz);
        }
#ifndef DEBUG_WOLFSSL
        else {
            ESP_LOGE(TAG, "ERROR: wait_until_done failed in esp32_mp");
        }
#endif
    } /* end of processing */
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* Unlike the ESP32 that is limited to only four operand lengths,
     * the ESP32-C3 The RSA Accelerator supports large-number modular
     * multiplication with operands of 128 different lengths.
     *
     * X & Y must be represented by the same number of bits. Must be
     * enough to represent the larger one. */

    /* Figure out how many words we need to
     * represent each operand & the result. */

    /* Make sure we are within capabilities of hardware. */
    if ((hwWords_sz * BITS_IN_ONE_WORD) > ESP_HW_MULTI_RSAMAX_BITS) {
#ifdef WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
        ESP_LOGW(TAG, "exceeds max bit length(%d)",
                       ESP_HW_MULTI_RSAMAX_BITS);
#endif
        ret = MP_HW_FALLBACK; /* let SW figure out how to deal with it */
    }
    if ((hwWords_sz * BITS_IN_ONE_WORD * 2) > ESP_HW_RSAMAX_BIT) {
#ifdef WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
        ESP_LOGW(TAG, "result exceeds max bit length(%d) * 2",
                       ESP_HW_RSAMAX_BIT );
#endif
        ret = MP_HW_FALLBACK; /* let SW figure out how to deal with it */
    }

    /* Steps to perform large number multiplication. Calculates Z = X * Y.
     *  The number of bits in the operands (X, Y) is N. N can be 32x, where
     *  x = {1,2,3,...64}, so the maximum number of bits in X and Y is 2048.
     * See 20.3.3 of ESP32-S3 technical manual
     *  1. Lock the hardware so no-one else uses it and wait until it is ready.
     *  2. Enable/disable interrupt that signals completion
     *       -- we don't use the interrupt.
     *  3. Write number of words required for result to the RSA_MODE_REG
     *     (now called RSA_LENGTH_REG).
     *     Number of words required for the result is 2 * words for operand - 1
     *  4. Load X, Y operands to memory blocks.
     *     Note the Y value must be written to as right aligned.
     *  5. Start the operation by writing 1 to RSA_MULT_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  6. Read the result out.
     *  7. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. lock HW for use & wait until it is ready. */
    /* lock HW for use, enable peripheral clock */
    if (ret == MP_OKAY) {
        mp_mul_lock_called = TRUE; /* Do not try to unlock unless we locked */
        #ifdef WOLFSSL_HW_METRICS
        {
            /* Only track max values when using HW */
            esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used :
                                                            esp_mp_max_used;
            esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used :
                                                            esp_mp_max_used;
        }
        #endif

        ret = esp_mp_hw_lock();
    }  /* the only thing we expect is success or busy */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    /* HW multiply */
    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INTERRUPT_REG, 0);

        /* 3. Write number of words required for result. */
        DPORT_REG_WRITE(RSA_LENGTH_REG, (hwWords_sz * 2 - 1));

        /* 4. Load X, Y operands. Maximum is 64 words (64*8*4 = 2048 bits) */
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              Xs,
                              hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Z_BLOCK_BASE + hwWords_sz * 4,
                              Y,
                              Ys,
                              hwWords_sz);

        /* 5. Start operation and wait until it completes. */
        process_start(RSA_MULT_START_REG);
        ret = wait_until_done(RSA_QUERY_INTERRUPT_REG);
    }
    if (ret == MP_OKAY) {
        /* 6. read the result form MEM_Z              */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, Z, resultWords_sz);
    }
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    /* Unlike the ESP32 that is limited to only four operand lengths,
     * the ESP32-C6 The RSA Accelerator supports large-number modular
     * multiplication with operands of 96 different lengths. (1 .. 96 words)
     *
     * X & Y must be represented by the same number of bits. Must be
     * enough to represent the larger one.
     *
     * Multiplication is limited to 48 different lengths (1 .. 48 words) */

    /* Figure out how many words we need to
     * represent each operand & the result. */

    /* Make sure we are within capabilities of hardware. */

    if ((hwWords_sz * BITS_IN_ONE_WORD) > ESP_HW_MULTI_RSAMAX_BITS) {
#ifdef WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
        ESP_LOGW(TAG, "RSA mul result hwWords_sz %d exceeds max bit length %d",
                       hwWords_sz, ESP_HW_MULTI_RSAMAX_BITS);
#endif
        ret = MP_HW_FALLBACK; /* let SW figure out how to deal with it */
    }
    if ((hwWords_sz * BITS_IN_ONE_WORD * 2) > ESP_HW_RSAMAX_BIT) {
#ifdef WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
        ESP_LOGW(TAG, "RSA max result hwWords_sz %d exceeds max bit length %d",
                       hwWords_sz, ESP_HW_RSAMAX_BIT );
#endif
        ret = MP_HW_FALLBACK; /* let SW figure out how to deal with it */
    }

    /* Steps to perform large number multiplication. Calculates Z = X * Y.
     * The number of bits in the operands (X, Y) is N.
     * N can be 32x, where x = {1,2,3,...64},
     * so the maximum number of bits in the X and Y is 2048.
     * See 20.3.3 of ESP32-S3 technical manual
     *  1. Lock the hardware so no-one else uses it and wait until it is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write number of words required for result to the RSA_MODE_REG
     *     (now called RSA_LENGTH_REG).
     *     Number of words required for the result is 2 * words for operand - 1
     *  4. Load X, Y operands to memory blocks.
     *     Note the Y value must be written to right aligned.
     *  5. Start the operation by writing 1 to RSA_MULT_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  6. Read the result out.
     *  7. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. lock HW for use & wait until it is ready. */
    /* lock HW for use, enable peripheral clock */
    if (ret == MP_OKAY) {
        mp_mul_lock_called = TRUE; /* Do not try to unlock unless we locked */
        #ifdef WOLFSSL_HW_METRICS
        {
            /* Only track max values when using HW */
            esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used :
                                                            esp_mp_max_used;
            esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used :
                                                            esp_mp_max_used;
        }
        #endif

        ret = esp_mp_hw_lock();
    } /* the only thing we expect is success or busy */

    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    /* HW multiply */
    if (ret == MP_OKAY) {
        /* 1. Disable completion interrupt signal; we don't use.
         * Write 1 (enable) or 0 (disable) to the RSA_INT_ENA_REG register.
         *    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INT_ENA_REG, 0);
        /* 2. Write number of words required for result. */
        /* see 21.3.3 Write (/N16 - 1) to the RSA_MODE_REG register */
        DPORT_REG_WRITE(RSA_MODE_REG, (hwWords_sz * 2 - 1));

        /* 3. Write Xi and Yi for {0, 1, . . . , n - 1} to memory blocks
         * RSA_X_MEM and RSA_Z_MEM
         * Maximum is 64 words (64*8*4 = 2048 bits) */
        esp_mpint_to_memblock(RSA_X_MEM,
                              X,
                              Xs,
                              hwWords_sz);
        esp_mpint_to_memblock(RSA_Z_MEM + hwWords_sz * 4,
                              Y,
                              Ys,
                              hwWords_sz);

        /* 4. Write 1 to the RSA_SET_START_MULT register */
        ret = process_start(RSA_SET_START_MULT_REG);

    }
    /* 5. Wait for the completion of computation, which happens when the
        * content of RSA_QUERY_IDLE becomes 1 or the RSA interrupt occurs. */
    if (ret == MP_OKAY) {
        ret = wait_until_done(RSA_QUERY_IDLE_REG);
    }

    if (ret == MP_OKAY) {
        /* 6. read the result from MEM_Z */
        esp_memblock_to_mpint(RSA_Z_MEM, Z, resultWords_sz);
    }
    /* end ESP32-C6 */

#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    /* Unlike the ESP32 that is limited to only four operand lengths,
     * the ESP32-S3 The RSA Accelerator supports large-number modular
     * multiplication with operands of 128 different lengths.
     *
     * X & Y must be represented by the same number of bits. Must be
     * enough to represent the larger one. */

    /* Figure out how many words we need to
     * represent each operand & the result. */

    /* Make sure we are within capabilities of hardware. */
    if ((hwWords_sz * BITS_IN_ONE_WORD) > ESP_HW_MULTI_RSAMAX_BITS) {
#ifdef WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
        ESP_LOGW(TAG, "exceeds max bit length(%d)", ESP_HW_MULTI_RSAMAX_BITS);
#endif
        ret = MP_HW_FALLBACK; /* let SW figure out how to deal with it */
    }
    if ((hwWords_sz * BITS_IN_ONE_WORD * 2) > ESP_HW_RSAMAX_BIT) {
#ifdef WOLFSSL_DEBUG_ESP_HW_MULTI_RSAMAX_BITS
        ESP_LOGW(TAG, "result exceeds max bit length(%d)", ESP_HW_RSAMAX_BIT );
#endif
        ret = MP_HW_FALLBACK; /* let SW figure out how to deal with it */
    }

    /* Steps to perform large number multiplication. Calculates Z = X * Y.
     * The number of bits in the operands (X, Y) is N.
     * N can be 32x, where x = {1,2,3,...64},
     * so the maximum number of bits in the X and Y is 2048.
     * See 20.3.3 of ESP32-S3 technical manual
     *  1. Lock the hardware so no-one else uses it and wait until it is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write number of words required for result to the RSA_MODE_REG
     *     (now called RSA_LENGTH_REG).
     *     Number of words required for the result is 2 * words for operand - 1
     *  4. Load X, Y operands to memory blocks.
     *     Note the Y value must be written to right aligned.
     *  5. Start the operation by writing 1 to RSA_MULT_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  6. Read the result out.
     *  7. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. lock HW for use & wait until it is ready. */
    if (ret == MP_OKAY) {
        mp_mul_lock_called = TRUE; /* Don't try to unlock unless we locked. */
        #ifdef WOLFSSL_HW_METRICS
        {
            /* Only track max values when using HW */
            esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used :
                                                            esp_mp_max_used;
            esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used :
                                                            esp_mp_max_used;
        }
        #endif

        ret = esp_mp_hw_lock();
    } /* the only thing we expect is success or busy */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    /* HW multiply */
    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INTERRUPT_REG, 0);

        /* 3. Write number of words required for result. */
        DPORT_REG_WRITE(RSA_LENGTH_REG, (hwWords_sz * 2 - 1));

        /* 4. Load X, Y operands. Maximum is 64 words (64*8*4 = 2048 bits) */
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              Xs,
                              hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Z_BLOCK_BASE + hwWords_sz * 4,
                              Y,
                              Ys,
                              hwWords_sz);

        /* 5. Start operation and wait until it completes. */
        process_start(RSA_MULT_START_REG);
        ret = wait_until_done(RSA_QUERY_INTERRUPT_REG);
    }
    if (ret == MP_OKAY) {
        /* 6. read the result form MEM_Z              */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, Z, resultWords_sz);
    }

    /*
    ** end if CONFIG_IDF_TARGET_ESP32S3
    */
#else
    ret = MP_HW_FALLBACK;
#endif /* target HW calcs*/

    /* common exit for all chipset types */

    /* step.7 clear and release HW                    */
    if (mp_mul_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        ESP_LOGV(TAG, "Lock not called");
    }

#if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
    if (ret == MP_OKAY) {
        if (!mp_iszero(Z) && res_sign) {
            /* for non-zero negative numbers, set negative flag for our result:
             *   Z->sign = FP_NEG */
            ESP_LOGV(TAG, "Setting Z to negative result!");
            mp_setneg(Z);
        }
        else {
            Z->sign = MP_ZPOS;
        }
    }
#endif

    if (ret == MP_OKAY) {
        /* never clean the result for anything other than success, as we may
         * fall back to SW and we don't want to muck up operand values. */
        esp_clean_result(Z, 0);
    }

#ifdef DEBUG_WOLFSSL
    if (mp_cmp(X, X2) != 0) {
        /* this may be interesting when operands change (e.g. z=x*z mode m) */
        /* ESP_LOGE(TAG, "mp_mul X vs X2 mismatch!"); */
    }
    if (mp_cmp(Y, Y2) != 0) {
        /* this may be interesting when operands change (e.g. z=y*z mode m) */
        /* ESP_LOGE(TAG, "mp_mul Y vs Y2 mismatch!"); */
    }
    if (mp_cmp(Z, Z2) != 0) {
        int found_z_used = Z->used;

        ESP_LOGE(TAG, "mp_mul Z vs Z2 mismatch!");
        ESP_LOGI(TAG, "Xs            = %d", Xs);
        ESP_LOGI(TAG, "Ys            = %d", Ys);
        ESP_LOGI(TAG, "Zs            = %d", Zs);
        ESP_LOGI(TAG, "found_z_used  = %d", found_z_used);
        ESP_LOGI(TAG, "z.used        = %d", Z->used);
        ESP_LOGI(TAG, "hwWords_sz    = %d", hwWords_sz);
        ESP_LOGI(TAG, "maxWords_sz   = %d", maxWords_sz);
#if defined(CONFIG_IDF_TARGET_ESP32)
        ESP_LOGI(TAG, "left_pad_offset = %d", left_pad_offset);
#endif
        ESP_LOGI(TAG, "hwWords_sz<<2   = %d", hwWords_sz << 2);
        esp_show_mp("X", X2);  /* show X2 copy, as X may have been clobbered */
        esp_show_mp("Y", Y2);  /* show Y2 copy, as Y may have been clobbered */
        esp_show_mp("Peek Z", PEEK); /* this is the Z before start */
        esp_show_mp("Z", Z);   /* this is the HW result */
        esp_show_mp("Z2", Z2); /* this is the SW result */
    #ifndef NO_RECOVER_SOFTWARE_CALC
        ESP_LOGW(TAG, "Recovering mp_mul error with software result");
        mp_copy(Z2, Z); /* copy (src = Z2) to (dst = Z) */
    #else
        ret = MP_VAL;
    #endif
    }
#endif

#ifdef WOLFSSL_HW_METRICS
    esp_mp_mul_usage_ct++;
    esp_mp_max_used = (Z->used > esp_mp_max_used) ? Z->used : esp_mp_max_used;
    if (ret != MP_OKAY) {
        esp_mp_mul_error_ct++; /* includes fallback */
    }
#endif

    ESP_LOGV(TAG, "\nEnd esp_mp_mul \n");

    return ret;
} /* esp_mp_mul() */
#endif /* Use HW mp_mul: ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL*/

#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
/* Large Number Modular Multiplication
 *
 * See 24.3.3 of the ESP32 Technical Reference Manual
 *
 * Z = X * Y mod M */
int esp_mp_mulmod(MATH_INT_T* X, MATH_INT_T* Y, MATH_INT_T* M, MATH_INT_T* Z)
{
    struct esp_mp_helper mph[1]; /* we'll save some values in this mp helper */
    MATH_INT_T tmpZ[1] = { };
#ifdef DEBUG_WOLFSSL
    MATH_INT_T X2[1] = { };
    MATH_INT_T Y2[1] = { };
    MATH_INT_T M2[1] = { };
    MATH_INT_T Z2[1] = { };
    MATH_INT_T PEEK[1] = { };
    (void) PEEK;
#endif

    int ret = MP_OKAY;
    int mulmod_lock_called = FALSE;
    word32 zwords = 0;

#if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
    int negcheck = 0;
#endif

#ifdef DEBUG_WOLFSSL
    int reti = 0; /* interim return value used only during HW==SW validation */
#endif

#if defined(CONFIG_IDF_TARGET_ESP32)

#elif defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6)
    word32 OperandBits;
    int WordsForOperand;
#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    word32 OperandBits;
    int WordsForOperand;
#else
    ret = MP_HW_FALLBACK;
#endif

    ESP_LOGV(TAG, "\nBegin esp_mp_mulmod \n");

    /* do we have an even moduli? */
    if ((M->dp[0] & 1) == 0) {
#ifndef NO_ESP_MP_MUL_EVEN_ALT_CALC
        /*  Z = X * Y mod M in mixed HW & SW */
    #if defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL)
        ret = mp_mul(X, Y, tmpZ);     /* SW X * Y */
    #else
        ret = esp_mp_mul(X, Y, tmpZ); /* HW X * Y */
    #endif
        if (ret == MP_OKAY) {
            /* z = tmpZ mod M, 0 <= Z < M */
            ret = mp_mod(tmpZ, M, Z); /* SW mod M */
        }
        ESP_LOGV(TAG, "alternate mp_mul calc!");
        return ret;
#else
    #ifdef WOLFSSL_HW_METRICS
        esp_mp_mulmod_even_mod_ct++;
    #endif
        ESP_LOGV(TAG, "esp_mp_mulmod does not support even numbers");
        ret = MP_HW_FALLBACK; /* let the software figure out what to do */
        return ret;
#endif /* NO_ESP_MP_MUL_EVEN_ALTERNATE */
    } /* even moduli check */

#ifdef DEBUG_WOLFSSL
    /* we're only validating HW when in debug mode */
    if (esp_hw_validation_active()) {
        ESP_LOGV(TAG, "MP_HW_VALIDATION_ACTIVE");
        return MP_HW_VALIDATION_ACTIVE;
    }
#endif

#ifdef DEBUG_WOLFSSL
    if (IS_HW_VALIDATION) {
        ESP_LOGE(TAG, "Caller must not try HW when validation active.");
    }
    else {
        /* when validating, save SW in [V]2 for later comparison to HW */
        mp_init(X2);
        mp_init(Y2);
        mp_init(M2);
        mp_init(Z2);

        mp_copy(X, X2); /* copy (src = X) to (dst = X2) */
        mp_copy(Y, Y2); /* copy (src = Y) to (dst = Y2) */
        mp_copy(M, M2); /* copy (src = M) to (dst = M2) */
        mp_copy(Z, Z2); /* copy (src = Z) to (dst = Z2) */

        SET_HW_VALIDATION; /* for the next mulmod to be SW for HW validation */
        reti = mp_mulmod(X2, Y2, M2, Z2);
        if (reti == 0) {
            ESP_LOGV(TAG, "wolfSSL mp_mulmod during validation success");
        }
        else {
            ESP_LOGE(TAG, "wolfSSL mp_mulmod during validation failed");
        }
        CLR_HW_VALIDATION;
    }
#endif /* DEBUG_WOLFSSL */

    if (ret == MP_OKAY) {

        /* neg check: X*Y becomes negative, we'll need adjustment  */
    #if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
        negcheck = mp_isneg(X) != mp_isneg(Y) ? 1 : 0;
    #endif

        /* calculate r_inv = R^2 mod M
        *    where: R = b^n, and b = 2^32
        *    accordingly R^2 = 2^(n*32*2)
        */
        ret = esp_mp_montgomery_init(X, Y, M, mph);
        if (ret == MP_OKAY) {
            ESP_LOGV(TAG, "esp_mp_exptmod esp_mp_montgomery_init success.");
        }
        else {
            #ifdef WOLFSSL_HW_METRICS
            if (ret == MP_HW_FALLBACK) {
                esp_mp_mulmod_fallback_ct++;
            }
            else {
                esp_mp_mulmod_error_ct++;
            }
            #endif
            return ret;
        }
        zwords = bits2words(min(mph->Ms, mph->Xs + mph->Ys));
    }

    /* we'll use hardware only for a minimum number of bits */
    if (mph->Xs <= ESP_RSA_MULM_BITS || mph->Ys <= ESP_RSA_MULM_BITS) {
        #ifdef WOLFSSL_HW_METRICS
        {
            esp_mp_mulmod_small_y_ct++; /* track how many times we fall back */
        }
        #endif
        ret = MP_HW_FALLBACK;
        #ifdef WOLFSSL_DEBUG_ESP_RSA_MULM_BITS
        {
            ESP_LOGW(TAG, "esp_mp_mulmod falling back for ESP_RSA_MULM_BITS!");
        }
        #endif
    }

    /* lock HW for use, enable peripheral clock */
    if (ret == MP_OKAY) {
        #ifdef WOLFSSL_HW_METRICS
        {
            /* Only track max values when using HW */
            esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used :
                                                            esp_mp_max_used;
            esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used :
                                                            esp_mp_max_used;
            esp_mp_max_used = (M->used > esp_mp_max_used) ? M->used :
                                                            esp_mp_max_used;
        }
        #endif

        ret = esp_mp_hw_lock();
        if (ret == ESP_OK) {
            mulmod_lock_called = TRUE; /* Don't try to unlock unless locked */
        }
        else {
            ret = WC_HW_WAIT_E;
        }
    }

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* Classic ESP32, non-S3 Xtensa */

    /*Steps to use HW in the following order:
    * prep:  wait until clean HW engine
    *
    * 1. Write (N/512bits - 1) to MULT_MODE_REG
    * 2. Write X,M(=G, X, P) to memory blocks
    *    need to write data to each memory block only according to the length
    *    of the number.
    * 3. Write M' to M_PRIME_REG
    * 4. Write 1  to MODEXP_START_REG
    * 5. Wait for the first round of the operation to be completed.
    *    Poll RSA_INTERRUPT_REG until it reads 1,
    *    or until the RSA_INTR interrupt is generated.
    *    (Or until the INTER interrupt is generated.)
    * 6. Write 1 to RSA_INTERRUPT_REG to clear the interrupt.
    * 7. Write Yi (i in [0, n) intersect N) to RSA_X_MEM
    *    Users need to write to the memory block only according to the length
    *    of the number. Data beyond this length is ignored.
    * 8. Write 1 to RSA_MULT_START_REG
    * 9. Wait for the second operation to be completed.
    *    Poll INTERRUPT_REG until it reads 1.
    * 10. Read the Zi (i in [0, n) intersect N) from RSA_Z_MEM
    * 11. Write 1 to RSA_INTERUPT_REG to clear the interrupt.
    *
    * post: Release the HW engine
    *
    * After the operation, the RSA_MULT_MODE_REG register, and memory blocks
    * RSA_M_MEM and RSA_M_PRIME_REG remain unchanged. Users do not need to
    * refresh these registers or memory blocks if the values remain the same.
    */

    if (ret == MP_OKAY) {
        /* Prep wait for the engine */
        ret = esp_mp_hw_wait_clean();
    }

    if (ret == MP_OKAY) {
        /* step.1
         *  Write (N/512bits - 1) to MULT_MODE_REG
         *  512 bits => 16 words */
        DPORT_REG_WRITE(RSA_MULT_MODE_REG, (mph->hwWords_sz >> 4) - 1);
#if defined(DEBUG_WOLFSSL)
        ESP_LOGV(TAG, "RSA_MULT_MODE_REG = %d", (mph->hwWords_sz >> 4) - 1);
#endif /* WOLFSSL_DEBUG */

        /* step.2 write X, M, and r_inv into memory.
         * The capacity of each memory block is 128 words.
         * The memory blocks use the little endian format for storage, i.e.
         * the least significant digit of each number is in lowest address.*/
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X, mph->Xs, mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_M_BLOCK_BASE,
                              M, mph->Ms, mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Z_BLOCK_BASE,
                              &(mph->r_inv), mph->Rs, mph->hwWords_sz);

        /* step.3 write M' into memory                   */
        /* confirmed that mp2 does not support even modulus.
         * indeed we see a failure, but we can predict when modules is odd
         * or when mp != mp2[0] */
        DPORT_REG_WRITE(RSA_M_DASH_REG, mph->mp);
        ESP_EM__3_16;

        /* step.4 start process                           */
        process_start(RSA_MULT_START_REG);

        /* step.5,6 wait until done                       */
        wait_until_done(RSA_INTERRUPT_REG);

        /* step.7 Y to MEM_X                              */
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              Y, mph->Ys,
                              mph->hwWords_sz);

#ifdef DEBUG_WOLFSSL
        /* save value to peek at the result stored in RSA_MEM_Z_BLOCK_BASE */
        esp_memblock_to_mpint(RSA_MEM_X_BLOCK_BASE,
                              PEEK,
                              128);
        esp_clean_result(PEEK, 0);
#endif /* DEBUG_WOLFSSL */

        /* step.8 start process                           */
        process_start(RSA_MULT_START_REG);

        /* step.9,11 wait until done                      */
        wait_until_done(RSA_INTERRUPT_REG);

        /* step.12 read the result from MEM_Z             */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, tmpZ, zwords);
    } /* step 1 .. 12 */

    /* step.13 clear and release HW                   */
    if (mulmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        ESP_LOGV(TAG, "Lock not called");
    }
    /* end of ESP32 */

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* Steps to perform large number modular multiplication.
     * Calculates Z = (X * Y) modulo M.
     * The number of bits in the operands (X, Y) is N. N can be 32x, where
     * x = {1,2,3,...64}, so the maximum number of bits in the X and Y is 2048.
     * We must use the same number of words to represent bits in X, Y and M.
     * See 20.3.3 of ESP32-C3 technical manual
     *  1. Wait until the hardware is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write the number of words required to represent the operands to the
     *     RSA_MODE_REG (now called RSA_LENGTH_REG).
     *  4. Write M' value into RSA_M_PRIME_REG (now called RSA_M_DASH_REG).
     *  5. Load X, Y, M, r' operands to memory blocks.
     *  6. Start the operation by writing 1 to RSA_MOD_MULT_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  7. Read the result out.
     *  8. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. Wait until hardware is ready. */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INTERRUPT_REG, 0);

        /* 3. Write (N_result_bits/32 - 1) to the RSA_MODE_REG. */
        OperandBits = max(max(mph->Xs, mph->Ys), mph->Ms);
        if (OperandBits > ESP_HW_MOD_RSAMAX_BITS) {
    #ifdef WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
            ESP_LOGW(TAG, "result exceeds max bit length");
    #endif
            return MP_HW_FALLBACK; /*  Error: value is not able to be used. */
        }
        WordsForOperand = bits2words(OperandBits);
        /* alt inline calc:
         * DPORT_REG_WRITE(RSA_MULT_MODE_REG, (mph->hwWords_sz >> 4) - 1); */
        DPORT_REG_WRITE(RSA_LENGTH_REG, WordsForOperand - 1);

        /* 4. Write M' value into RSA_M_PRIME_REG
         *    (now called RSA_M_DASH_REG) */
        DPORT_REG_WRITE(RSA_M_DASH_REG, mph->mp);

        /* Select acceleration options. */
        DPORT_REG_WRITE(RSA_CONSTANT_TIME_REG, 0);

        /* 5. Load X, Y, M, r' operands.
         * Note RSA_MEM_RB_BLOCK_BASE == RSA_MEM_Z_BLOC_BASE on ESP32s3*/
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              mph->Xs,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Y_BLOCK_BASE,
                              Y,
                              mph->Ys,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_M_BLOCK_BASE,
                              M,
                              mph->Ms,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_RB_BLOCK_BASE,
                              &(mph->r_inv),
                              mph->Rs,
                              mph->hwWords_sz);

        /* 6. Start operation and wait until it completes. */
        process_start(RSA_MOD_MULT_START_REG); /* esp_mp_mulmod */
    }

    if (ret == MP_OKAY) {
        ret = wait_until_done(RSA_QUERY_INTERRUPT_REG);
    }

    if (ret == MP_OKAY) {
        /* 7. read the result from MEM_Z              */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, tmpZ, zwords);
    }

    /* 8. clear and release HW                    */
    if (mulmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        ESP_LOGV(TAG, "Lock not called, esp_mp_hw_unlock skipped");
    }
    /* end if CONFIG_IDF_TARGET_ESP32C3 */

#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    /* Steps to perform large number modular multiplication.
     * Calculates Z = (X * Y) modulo M.
     * The number of bits in the operands (X, Y) is N. N can be 32x,where
     * x = {1,2,3,...64}, so the maximum number of bits in  X and Y is 2048.
     * We must use the same number of words to represent the bits X, Y and M.
     * See 20.3.3 of ESP32-S3 technical manual
     *  1. Wait until the hardware is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write the number of words required to represent the operands to the
     *     RSA_MODE_REG (now called RSA_LENGTH_REG).
     *  4. Write M' value into RSA_M_PRIME_REG (now called RSA_M_DASH_REG).
     *  5. Load X, Y, M, r' operands to memory blocks.
     *  6. Start the operation by writing 1 to RSA_MOD_MULT_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  7. Read the result out.
     *  8. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. Wait until hardware is ready for esp_mp_mulmod. */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }
    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INT_ENA_REG, 0);

        /* 3. Write (N_result_bits/32 - 1) to the RSA_MODE_REG. */
        OperandBits = max(max(mph->Xs, mph->Ys), mph->Ms);
        if (OperandBits > ESP_HW_MOD_RSAMAX_BITS) {
    #ifdef WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
            ESP_LOGW(TAG, "mulmod OperandBits = %d "
                          "result exceeds max bit length %d",
                           OperandBits, ESP_HW_MOD_RSAMAX_BITS);
    #endif
            if (mulmod_lock_called) {
                ret = esp_mp_hw_unlock();
            }
            return MP_HW_FALLBACK; /*  Error: value is not able to be used. */
        }
        WordsForOperand = bits2words(OperandBits);
        /* alt inline calc:
         * DPORT_REG_WRITE(RSA_MULT_MODE_REG, (mph->hwWords_sz >> 4) - 1); */
        DPORT_REG_WRITE(RSA_MODE_REG, WordsForOperand - 1);

        /* 4. Write M' value into RSA_M_PRIME_REG
         *    (now called RSA_M_DASH_REG) */
        DPORT_REG_WRITE(RSA_M_PRIME_REG, mph->mp);

        /* Select acceleration options. */
        DPORT_REG_WRITE(RSA_CONSTANT_TIME_REG, 0);
        DPORT_REG_WRITE(RSA_SEARCH_POS_REG, 0); /* or RSA_SEARCH_ENABLE */

        /* 5. Load X, Y, M, r' operands.
         * Note RSA_MEM_RB_BLOCK_BASE == RSA_M_MEM on ESP32-C6*/
        esp_mpint_to_memblock(RSA_X_MEM,
                              X,
                              mph->Xs,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_Y_MEM,
                              Y,
                              mph->Ys,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_M_MEM,
                              M,
                              mph->Ms,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_Z_MEM,
                              &(mph->r_inv),
                              mph->Rs,
                              mph->hwWords_sz);

        /* 6. Start operation and wait until it completes. */
        process_start(RSA_SET_START_MODMULT_REG); /* reminder: esp_mp_mulmod */
    }

    /* 5. Wait for the completion of computation, which happens when the
     * content of RSA_QUERY_IDLE becomes 1 or the RSA interrupt occurs. */
    if (ret == MP_OKAY) {
        ret = wait_until_done(RSA_QUERY_IDLE_REG);
    }
    if (ret == MP_OKAY) {
        /* 7. read the result from MEM_Z              */
        esp_memblock_to_mpint(RSA_Z_MEM, tmpZ, zwords);
    }

    /* 8. clear and release HW                    */
    if (mulmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        ESP_LOGV(TAG, "Lock not called, esp_mp_hw_unlock skipped");
    }

    /* end if CONFIG_IDF_TARGET_ESP32C3 or CONFIG_IDF_TARGET_ESP32C6 */
#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    /* Steps to perform large number modular multiplication.
     * Calculates Z = (X * Y) modulo M.
     * The number of bits in the operands (X, Y) is N. N can be 32x, where
     * x = {1,2,3,...64}, so the maximum number of bits in the X and Y is 2048.
     * We must use the same number of words to represent bits in X, Y and M.
     * See 20.3.3 of ESP32-S3 technical manual.
     *  1. Wait until the hardware is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write the number of words required to represent the operands to the
     *     RSA_MODE_REG (now called RSA_LENGTH_REG).
     *  4. Write M' value into RSA_M_PRIME_REG (now called RSA_M_DASH_REG).
     *  5. Load X, Y, M, r' operands to memory blocks.
     *  6. Start the operation by writing 1 to RSA_MOD_MULT_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  7. Read the result out.
     *  8. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. Wait until hardware is ready. */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INTERRUPT_REG, 0);

        /* 3. Write (N_result_bits/32 - 1) to the RSA_MODE_REG. */
        OperandBits = max(max(mph->Xs, mph->Ys), mph->Ms);
        if (OperandBits > ESP_HW_MOD_RSAMAX_BITS) {
    #ifdef WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
            ESP_LOGW(TAG, "mp_mulmod OperandBits %d exceeds max bit length %d.",
                           OperandBits, ESP_HW_MOD_RSAMAX_BITS);
    #endif
            return MP_HW_FALLBACK; /*  Error: value is not able to be used. */
        }
        WordsForOperand = bits2words(OperandBits);
        /* alt inline calc:
         * DPORT_REG_WRITE(RSA_MULT_MODE_REG, (mph->hwWords_sz >> 4) - 1); */
        DPORT_REG_WRITE(RSA_LENGTH_REG, WordsForOperand - 1);

        /* 4. Write M' value into RSA_M_PRIME_REG
         * (now called RSA_M_DASH_REG) */
        DPORT_REG_WRITE(RSA_M_DASH_REG, mph->mp);

        /* Select acceleration options. */
        DPORT_REG_WRITE(RSA_CONSTANT_TIME_REG, 0);

        /* 5. Load X, Y, M, r' operands.
         * Note RSA_MEM_RB_BLOCK_BASE == RSA_MEM_Z_BLOC_BASE on ESP32s3*/
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              mph->Xs,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Y_BLOCK_BASE,
                              Y,
                              mph->Ys,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_M_BLOCK_BASE,
                              M,
                              mph->Ms,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_RB_BLOCK_BASE,
                              &(mph->r_inv),
                              mph->Rs,
                              mph->hwWords_sz);

        /* 6. Start operation and wait until it completes. */
        process_start(RSA_MOD_MULT_START_REG); /* Reminder: esp_mp_mulmod() */
        asm volatile("memw");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
    }

    if (ret == MP_OKAY) {
        ret = wait_until_done(RSA_QUERY_INTERRUPT_REG);
    }

    if (ret == MP_OKAY) {
        /* 7. read the result from MEM_Z              */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, tmpZ, zwords);
    }

    /* 8. clear and release HW                    */
    if (mulmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        if (ret == MP_HW_FALLBACK) {
            ESP_LOGV(TAG, "Lock not called due to no-lock MP_HW_FALLBACK");
        }
        else {
    #ifdef WOLFSSL_ESP32_HW_LOCK_DEBUG
            ESP_LOGW(TAG, "Lock unexpectedly not called for mp_mulmod");
    #endif
        }
    }

    /* end if CONFIG_IDF_TARGET_ESP32S3 */
#else
    /* for all non-supported chipsets, fall back to SW calcs */
    ret = MP_HW_FALLBACK;
#endif

    if (ret == MP_OKAY) {
        /* additional steps                               */
        /* this is needed for known issue when Z is greater than M */
        if (mp_cmp(tmpZ, M) == MP_GT) {
            /*  Z -= M  */
            mp_sub(tmpZ, M, tmpZ);
            ESP_LOGV(TAG, "Z is greater than M");
        }
    #if defined(WOLFSSL_SP_INT_NEGATIVE) || defined(USE_FAST_MATH)
        if (negcheck) {
            mp_sub(M, tmpZ, tmpZ);
            ESP_LOGV(TAG, "neg check adjustment");
        }
    #endif
        mp_copy(tmpZ, Z); /* copy tmpZ to result Z */

        esp_clean_result(Z, 0);
    }

#ifdef WOLFSSL_HW_METRICS
    esp_mp_mulmod_usage_ct++;
    if (ret == MP_HW_FALLBACK) {
        ESP_LOGV(TAG, "esp_mp_mulmod HW Fallback tick");
        esp_mp_mulmod_fallback_ct++;
    }
#endif

#ifdef DEBUG_WOLFSSL
    if (ret == MP_HW_FALLBACK) {
        ESP_LOGI(TAG, "HW Fallback");
    }
    else {
        if (mp_cmp(X, X2) != 0) {
            ESP_LOGV(TAG, "mp_mul X vs X2 mismatch!");
        }
        if (mp_cmp(Y, Y2) != 0) {
            ESP_LOGV(TAG, "mp_mul Y vs Y2 mismatch!");
        }

        if (mp_cmp(Z, Z2) != 0) {
            ESP_LOGE(TAG, "esp_mp_mulmod Z vs Z2 mismatch!");

            esp_mp_mulmod_error_ct++;
            int found_z_used = Z->used;

            ESP_LOGI(TAG, "Xs            = %d", mph->Xs);
            ESP_LOGI(TAG, "Ys            = %d", mph->Ys);
            ESP_LOGI(TAG, "found_z_used  = %d", found_z_used);
            ESP_LOGI(TAG, "z.used        = %d", Z->used);
            ESP_LOGI(TAG, "hwWords_sz    = %d", mph->hwWords_sz);
            ESP_LOGI(TAG, "maxWords_sz   = %d", mph->maxWords_sz);
            ESP_LOGI(TAG, "hwWords_sz<<2   = %d", mph->hwWords_sz << 2);

            /* parameters may have been collbered; Show cpied values */
            esp_show_mp("X", X2);
            esp_show_mp("Y", Y2);
            esp_show_mp("M", M2);

            ESP_LOGI(TAG, "Xs            = %d", mph->Xs);
            ESP_LOGI(TAG, "Ys            = %d", mph->Ys);
            ESP_LOGI(TAG, "found_z_used  = %d", found_z_used);
            ESP_LOGI(TAG, "z.used        = %d", Z->used);
            ESP_LOGI(TAG, "hwWords_sz    = %d", mph->hwWords_sz);
            ESP_LOGI(TAG, "maxWords_sz   = %d", mph->maxWords_sz);
            ESP_LOGI(TAG, "hwWords_sz<<2   = %d", mph->hwWords_sz << 2);
            esp_show_mp("X", X2); /* X2 copy, as X may have been clobbered */
            esp_show_mp("Y", Y2); /* Y2 copy, as Y may have been clobbered */
            esp_show_mp("M", M2); /* M2 copy, as M may have been clobbered */
            esp_show_mp("r_inv", &(mph->r_inv)); /*show r_inv  */
            ESP_LOGI(TAG, "mp            = 0x%08x = %u", mph->mp, mph->mp);

            if (mph->mp == mph->mp2) {
                ESP_LOGI(TAG, "M' match esp_calc_Mdash vs mp_montgomery_setup"
                              " = %d  !", mph->mp);
            }
            else {
                ESP_LOGW(TAG,
                         "\n\n"
                         "M' MISMATCH esp_calc_Mdash = 0x%08x = %d \n"
                         "vs mp_montgomery_setup     = 0x%08x = %d \n\n",
                         mph->mp,
                         mph->mp,
                         mph->mp2,
                         mph->mp2);
                mph->mp = mph->mp2;
            }


            esp_show_mp("HW Z", Z); /* this is the HW result */
            esp_show_mp("SW Z2", Z2); /* this is the SW result */
            ESP_LOGI(TAG, "esp_mp_mulmod_usage_ct = %lu tries",
                           esp_mp_mulmod_usage_ct);
            ESP_LOGI(TAG, "esp_mp_mulmod_error_ct = %lu failures",
                           esp_mp_mulmod_error_ct);
            ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);
            esp_show_mp("HW Z", Z); /* this is the HW result */
            esp_show_mp("SW Z2", Z2); /* this is the SW result */
            ESP_LOGI(TAG, "esp_mp_mulmod_usage_ct = %lu tries",
                           esp_mp_mulmod_usage_ct);
            ESP_LOGI(TAG, "esp_mp_mulmod_error_ct = %lu failures",
                           esp_mp_mulmod_error_ct);
            ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE);


            #ifndef NO_RECOVER_SOFTWARE_CALC
            {
                ESP_LOGW(TAG, "Recovering mp_mul error with software result");
                mp_copy(Z2, Z); /* copy (src = Z2) to (dst = Z) */
            }
            #else
            {
                /* If we are not recovering, then we have an error. */
                ret = MP_VAL;
            }
            #endif
        }
        else {
            ESP_LOGV(TAG, "esp_mp_mulmod success!");
        }
    }

#endif /* DEBUG_WOLFSSL */

    /* cleanup and exit */
    mp_clear(tmpZ);
    mp_clear(&(mph->r_inv));

    ESP_LOGV(TAG, "\nEnd esp_mp_mulmod \n");
    if (ret == MP_OKAY || ret == MP_HW_FALLBACK) {
        ESP_LOGV(TAG, "esp_mp_mulmod exit success ");
    }
    else {
        ESP_LOGW(TAG, "esp_mp_mulmod exit failed = %d", ret);
    }

#ifdef WOLFSSL_HW_METRICS
    /* calculate max used after any cleanup */
    esp_mp_max_used = (Z->used > esp_mp_max_used) ? Z->used : esp_mp_max_used;
#endif
    return ret;
} /* esp_mp_mulmod */
#endif /* Use HW mulmod: ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD */


#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
/* Large Number Modular Exponentiation
 *
 *    Z = X^Y mod M
 *
 *  ESP32, Section 24.3.2  esp32_technical_reference_manual_en.pdf
 *  ESP32S3, Section 20.3.1, esp32-s3_technical_reference_manual_en.pdf
 *
 * The operation is based on Montgomery multiplication. Aside from the
 * arguments X, Y , and M, two additional ones are needed -r and M'
.* These arguments are calculated in advance by software.
.*
.* The RSA Accelerator supports operand lengths of N in {512, 1024, 1536, 2048,
.* 2560, 3072, 3584, 4096} bits on the ESP32 and N in [32, 4096] bits
 * on the ESP32s3.
.* The bit length of arguments Z, X, Y , M, and r can be any one from
 * the N set, but all numbers in a calculation must be of the same length.
.* The bit length of M' is always 32.
.*
 * Z = (X ^ Y) mod M   : Espressif generic notation
 * Y = (G ^ X) mod P   : wolfSSL DH reference notation */
int esp_mp_exptmod(MATH_INT_T* X, MATH_INT_T* Y, MATH_INT_T* M, MATH_INT_T* Z)
{
    /* Danger! Do not initialize any function parameters, not even the result Z.
     * Some operations such as (rnd = rnd^e) will wipe out the rnd operand
     * value upon initialization.
     * (e.g. the address of X and Z could be the same when called) */
    struct esp_mp_helper mph[1]; /* we'll save some mp helper data here */
    int ret = MP_OKAY;
    int exptmod_lock_called = FALSE;

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* different calc */
#elif defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6)
    word32 OperandBits;
    word32 WordsForOperand;
#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    word32 OperandBits;
    word32 WordsForOperand;
#else
    /* no HW */
#endif

    ESP_LOGV(TAG, "\nBegin esp_mp_exptmod \n");
#ifdef WOLFSSL_HW_METRICS
    esp_mp_exptmod_usage_ct++;
    esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used : esp_mp_max_used;
    esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used : esp_mp_max_used;
    esp_mp_max_used = (M->used > esp_mp_max_used) ? M->used : esp_mp_max_used;
#endif

    if (mp_iszero(M)) {
#ifdef DEBUG_WOLFSSL
        ESP_LOGI(TAG, "esp_mp_exptmod M is zero!");
#endif
#ifdef WOLFSSL_HW_METRICS
        esp_mp_exptmod_fallback_ct++;
#endif
        return MP_HW_FALLBACK; /* fall back and let SW decide how to handle */
    }

    if (mp_isone(M)) {
#ifdef DEBUG_WOLFSSL
        ESP_LOGI(TAG, "esp_mp_exptmod M is one!");
#endif
        mp_clear(Z);
        return MP_OKAY; /* mod zero is zero */
    }

    ret = esp_mp_montgomery_init(X, Y, M, mph);

    if (ret == MP_OKAY) {
        ESP_LOGV(TAG, "esp_mp_exptmod esp_mp_montgomery_init success.");
    }
    else {
#ifdef WOLFSSL_HW_METRICS
        if (ret == MP_HW_FALLBACK) {
            esp_mp_exptmod_fallback_ct++;
        }
        else {
            esp_mp_exptmod_error_ct++;
        }
#endif
        return ret;
    }

#ifdef DEBUG_WOLFSSL
    if (esp_hw_validation_active()) {
        /* recall there's only one HW for all math accelerations */
        return MP_HW_VALIDATION_ACTIVE;
    }

    if (esp_mp_exptmod_depth_counter != 0) {
        ESP_LOGE(TAG, "esp_mp_exptmod Depth Counter Error!");
    }
    esp_mp_exptmod_depth_counter++;
#endif

 /*
 max bits = 0x400 = 1024 bits
1024 / 8 = 128 bytes
 128 / 4 = 32 words (0x20)
 */

    /* lock and init the HW                           */
    if (ret == MP_OKAY) {
        exptmod_lock_called = TRUE; /* Don't try to unlock unless we locked */
        #ifdef WOLFSSL_HW_METRICS
        {
            /* Only track max values when using HW */
            esp_mp_max_used = (X->used > esp_mp_max_used) ? X->used :
                                                            esp_mp_max_used;
            esp_mp_max_used = (Y->used > esp_mp_max_used) ? Y->used :
                                                            esp_mp_max_used;
        }
        #endif

        ret = esp_mp_hw_lock();
        if (ret != MP_OKAY) {
            ESP_LOGE(TAG, "esp_mp_hw_lock failed");
            #ifdef DEBUG_WOLFSSL
                esp_mp_exptmod_depth_counter--;
            #endif
            return MP_HW_FALLBACK; /* If we can't lock HW, fall back to SW */
        }
    } /* the only thing we expect is success or busy */

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* non-ESP32S3 Xtensa (regular ESP32) */

    /* Steps to use HW in the following order:
    * 1. Write(N/512bits - 1) to MODEXP_MODE_REG
    * 2. Write X, Y, M and r_inv to memory blocks
    *    need to write data to each memory block only according to the length
    *    of the number.
    * 3. Write M' to M_PRIME_REG
    * 4. Write 1  to MODEXP_START_REG
    * 5. Wait for the operation to be done. Poll INTERRUPT_REG until it reads 1.
    *    (Or until the INTER interrupt is generated.)
    * 6. Read the result Z(=Y) from Z_MEM
    * 7. Write 1 to INTERRUPT_REG to clear the interrupt.
    */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    #ifdef WOLFSSL_HW_METRICS
        if (ret != MP_OKAY) {
            esp_mp_exptmod_error_ct++;
        }
    #endif
    }

    if (ret == MP_OKAY) {
        /* step.1                                         */
        ESP_LOGV(TAG,
                 "hwWords_sz = %d, num = %d",
                 mph->hwWords_sz,
                 (mph->hwWords_sz >> 4) - 1
                );

        DPORT_REG_WRITE(RSA_MODEXP_MODE_REG, (mph->hwWords_sz >> 4) - 1);
        /* step.2 write G, X, P, r_inv and M' into memory */
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              mph->Xs,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Y_BLOCK_BASE,
                              Y, mph->Ys,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_M_BLOCK_BASE,
                              M,
                              mph->Ms,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Z_BLOCK_BASE,
                              &(mph->r_inv),
                              mph->Rs,
                              mph->hwWords_sz);

        /* step.3 write M' into memory                    */
        ESP_LOGV(TAG, "M' = %d", mph->mp);
        DPORT_REG_WRITE(RSA_M_DASH_REG, mph->mp);
        ESP_EM__3_16;

        /* step.4 start process                           */
        process_start(RSA_MODEXP_START_REG); /* was RSA_START_MODEXP_REG;
                                             * RSA_MODEXP_START_REG in docs? */

        /* step.5 wait until done                         */
        wait_until_done(RSA_INTERRUPT_REG);
        /* step.6 read a result form memory               */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, Z, BITS_TO_WORDS(mph->Ms));
    }

    /* step.7 clear and release expt_mod HW               */
    if (exptmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        ESP_LOGV(TAG, "Lock not called");
    }

#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    OperandBits = max(max(mph->Xs, mph->Ys), mph->Ms);
    if (OperandBits > ESP_HW_MOD_RSAMAX_BITS) {
    #ifdef WOLFSSL_HW_METRICS
        ESP_LOGW(TAG, "exptmod operand bits %d exceeds max bit length %d",
                       OperandBits, ESP_HW_MOD_RSAMAX_BITS);
        esp_mp_mulmod_max_exceeded_ct++;
    #endif
       if (exptmod_lock_called) {
            ret = esp_mp_hw_unlock();
        }
        ESP_LOGV(TAG, "Return esp_mp_exptmod fallback");

        /* HW not capable for this size, return error to fall back to SW: */
        return MP_HW_FALLBACK;
    }
    else {
        WordsForOperand = bits2words(OperandBits);
    }

    /* Steps to perform large number modular exponentiation.
     * Calculates Z = (X ^ Y) modulo M.
     * The number of bits in the operands (X, Y) is N. N can be 32x,
     * where x = {1,2,3,...64}; maximum number of bits in the X and Y is 2048.
     * See 20.3.3 of ESP32-S3 technical manual
     *  1. Wait until the hardware is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write (N_bits/32 - 1) to the RSA_MODE_REG
     *     (now called RSA_LENGTH_REG).
     *     Here N_bits is the maximum number of bits in X, Y and M.
     *  4. Write M' value into RSA_M_PRIME_REG (now called RSA_M_DASH_REG).
     *  5. Load X, Y, M, r' operands to memory blocks.
     *  6. Start the operation by writing 1 to RSA_MODEXP_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  7. Read the result out.
     *  8. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. Wait until hardware is ready. */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INTERRUPT_REG, 0);

        /* 3. Write (N_result_bits/32 - 1) to the RSA_MODE_REG. */
        DPORT_REG_WRITE(RSA_LENGTH_REG, WordsForOperand - 1);

        /* 4. Write M' value into RSA_M_PRIME_REG
         * (now called RSA_M_DASH_REG) */
        DPORT_REG_WRITE(RSA_M_DASH_REG, mph->mp);

        /* 5. Load X, Y, M, r' operands. */
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              mph->Xs,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Y_BLOCK_BASE,
                              Y,
                              mph->Ys,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_M_BLOCK_BASE,
                              M,
                              mph->Ms,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Z_BLOCK_BASE,
                              &(mph->r_inv),
                              mph->Rs,
                              mph->hwWords_sz);

        /* 6. Start operation and wait until it completes. */
        process_start(RSA_MODEXP_START_REG);
        ret = wait_until_done(RSA_QUERY_INTERRUPT_REG);
    }

    if (MP_OKAY == ret) {
        /* 7. read the result form MEM_Z              */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, Z, BITS_TO_WORDS(mph->Ms));
    }

    /* 8. clear and release HW                    */
    if (exptmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        ESP_LOGV(TAG, "Lock not called");
    }
    /* end if CONFIG_IDF_TARGET_ESP32C3 */

#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    OperandBits = max(max(mph->Xs, mph->Ys), mph->Ms);
    if (OperandBits > ESP_HW_MOD_RSAMAX_BITS) {
    #ifdef WOLFSSL_HW_METRICS
        ESP_LOGW(TAG, "exptmod operand bits %d exceeds max bit length %d",
                       OperandBits, ESP_HW_MOD_RSAMAX_BITS);
        esp_mp_mulmod_max_exceeded_ct++;
    #endif
       if (exptmod_lock_called) {
            ret = esp_mp_hw_unlock();
        }
        ESP_LOGV(TAG, "Return esp_mp_exptmod fallback");

        /* HW not capable for this size, return error to fall back to SW: */
        return MP_HW_FALLBACK;
    }
    else {
        WordsForOperand = bits2words(OperandBits);
    }

    /* Steps to perform large number modular exponentiation.
     * Calculates Z = (X ^ Y) modulo M.
     * The number of bits in the operands (X, Y) is N. N can be 32x,
     * where x = {1,2,3,...64}; maximum number of bits in the X and Y is 2048.
     * See 20.3.3 of ESP32-S3 technical manual
     *  1. Wait until the hardware is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write (N_bits/32 - 1) to the RSA_MODE_REG
     *     (now called RSA_LENGTH_REG).
     *     Here N_bits is the maximum number of bits in X, Y and M.
     *  4. Write M' value into RSA_M_PRIME_REG (now called RSA_M_DASH_REG).
     *  5. Load X, Y, M, r' operands to memory blocks.
     *  6. Start the operation by writing 1 to RSA_MODEXP_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  7. Read the result out.
     *  8. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. Wait until hardware is ready. */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INT_ENA_REG, 0);

        /* 3. Write (N_result_bits/32 - 1) to the RSA_MODE_REG. */
        DPORT_REG_WRITE(RSA_MODE_REG, WordsForOperand - 1);

        /* 4. Write M' value into RSA_M_PRIME_REG  */
        DPORT_REG_WRITE(RSA_M_PRIME_REG, mph->mp);

        /* 5. Load X, Y, M, r' operands. */
        esp_mpint_to_memblock(RSA_X_MEM,
                              X,
                              mph->Xs,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_Y_MEM,
                              Y,
                              mph->Ys,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_M_MEM,
                              M,
                              mph->Ms,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_Z_MEM,
                              &(mph->r_inv),
                              mph->Rs,
                              mph->hwWords_sz);

        /* 6. Start operation and wait until it completes. */
        /* Write 1 to the RSA_SET_START_MODEXP field of the
         * RSA_SET_START_MODEXP_REG register to start computation.*/
        process_start(RSA_SET_START_MODEXP_REG);
        ret = wait_until_done(RSA_QUERY_IDLE_REG);
    }

    if (MP_OKAY == ret) {
        /* 7. read the result form MEM_Z              */
        esp_memblock_to_mpint(RSA_Z_MEM, Z, BITS_TO_WORDS(mph->Ms));
    }

    /* 8. clear and release HW                    */
    #ifdef WOLFSSL_ESP32_HW_LOCK_DEBUG
        ESP_LOGI(TAG, "Unlock esp_mp_exptmod");
    #endif
    if (exptmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
    #ifdef WOLFSSL_ESP32_HW_LOCK_DEBUG
        ESP_LOGV(TAG, "Lock not called");
    #endif
    }
    /* end if CONFIG_IDF_TARGET_ESP32C6 */

#elif defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    /* Steps to perform large number modular exponentiation.
     * Calculates Z = (X ^ Y) modulo M.
     * The number of bits in the operands (X, Y) is N. N can be 32x,
     * where x = {1,2,3,...64}; the maximum number of bits in X and Y is 2048.
     * See 20.3.3 of ESP32-S3 technical manual:
     *  1. Wait until the hardware is ready.
     *  2. Enable/disable interrupt that signals completion
     *     -- we don't use the interrupt.
     *  3. Write (N_bits/32 - 1) to the RSA_MODE_REG
     *     (now called RSA_LENGTH_REG).
     *     Here N_bits is the maximum number of bits in X, Y and M.
     *  4. Write M' value into RSA_M_PRIME_REG (now called RSA_M_DASH_REG).
     *  5. Load X, Y, M, r' operands to memory blocks.
     *  6. Start the operation by writing 1 to RSA_MODEXP_START_REG,
     *     then wait for it to complete by monitoring RSA_IDLE_REG
     *     (which is now called RSA_QUERY_INTERRUPT_REG).
     *  7. Read the result out.
     *  8. Release the hardware lock so others can use it.
     *  x. Clear the interrupt flag, if you used it (we don't). */

    /* 1. Wait until hardware is ready. */
    if (ret == MP_OKAY) {
        ret = esp_mp_hw_wait_clean();
    }

    if (ret == MP_OKAY) {
        OperandBits = max(max(mph->Xs, mph->Ys), mph->Ms);
        if (OperandBits > ESP_HW_MOD_RSAMAX_BITS) {
    #ifdef WOLFSSL_DEBUG_ESP_HW_MOD_RSAMAX_BITS
            ESP_LOGW(TAG, "exptmod operand bits %d exceeds max bit length %d",
                           OperandBits, ESP_HW_MOD_RSAMAX_BITS);
    #endif
            ret = MP_HW_FALLBACK; /*  Error: value is not able to be used. */
        }
        else {
            WordsForOperand = bits2words(OperandBits);
        }
    }

    if (ret == MP_OKAY) {
        /* 2. Disable completion interrupt signal; we don't use.
        **    0 => no interrupt; 1 => interrupt on completion. */
        DPORT_REG_WRITE(RSA_INTERRUPT_REG, 0);

        /* 3. Write (N_result_bits/32 - 1) to the RSA_MODE_REG. */
        DPORT_REG_WRITE(RSA_LENGTH_REG, WordsForOperand - 1);

        /* 4. Write M' value into RSA_M_PRIME_REG
         * (now called RSA_M_DASH_REG) */
        DPORT_REG_WRITE(RSA_M_DASH_REG, mph->mp);

        /* 5. Load X, Y, M, r' operands. */
        esp_mpint_to_memblock(RSA_MEM_X_BLOCK_BASE,
                              X,
                              mph->Xs,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Y_BLOCK_BASE,
                              Y,
                              mph->Ys,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_M_BLOCK_BASE,
                              M,
                              mph->Ms,
                              mph->hwWords_sz);
        esp_mpint_to_memblock(RSA_MEM_Z_BLOCK_BASE,
                              &(mph->r_inv),
                              mph->Rs,
                              mph->hwWords_sz);

        /* 6. Start operation and wait until it completes. */
        process_start(RSA_MODEXP_START_REG);
        ret = wait_until_done(RSA_QUERY_INTERRUPT_REG);
    }

    if (MP_OKAY == ret) {
        /* 7. read the result form MEM_Z              */
        esp_memblock_to_mpint(RSA_MEM_Z_BLOCK_BASE, Z, BITS_TO_WORDS(mph->Ms));
    }

    /* 8. clear and release HW                    */
    if (exptmod_lock_called) {
        ret = esp_mp_hw_unlock();
    }
    else {
        ESP_LOGV(TAG, "Lock not called");
    }

    /* end if CONFIG_IDF_TARGET_ESP32S3 */
#else
    /* unknown or unsupported targets fall back to SW */
    ret = MP_HW_FALLBACK;
#endif

#ifdef DEBUG_WOLFSSL
    if (esp_mp_exptmod_depth_counter != 1) {
        ESP_LOGE(TAG, "esp_mp_exptmod exit Depth Counter Error!");
    }
    esp_mp_exptmod_depth_counter--;
#endif

    /* never modify the result if we are falling back as the result
     * may be the same as one of the operands! */
    if (ret == MP_OKAY) {
        esp_clean_result(Z, 0);
    }
#ifdef WOLFSSL_HW_METRICS
    esp_mp_max_used = (Z->used > esp_mp_max_used) ? Z->used : esp_mp_max_used;
#endif
    ESP_LOGV(TAG, "Return esp_mp_exptmod %d", ret);

    return ret;
} /* esp_mp_exptmod */
#endif /* Use HW expmod: ! NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */

#endif /* WOLFSSL_ESP32_CRYPT_RSA_PRI) &&
        * !NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */

#endif /* !NO_RSA || HAVE_ECC */

/* Some optional metrics when using RSA HW Acceleration */
#if defined(WOLFSSL_ESP32_CRYPT_RSA_PRI) && defined(WOLFSSL_HW_METRICS)
int esp_hw_show_mp_metrics(void)
{
    int ret;
#if !defined(NO_ESP32_CRYPT)  &&  defined(HW_MATH_ENABLED)
    ret = MP_OKAY;

#if defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL)
    ESP_LOGI(TAG, "esp_mp_mul HW disabled with "
                  "NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL");
#else
    /* Metrics: esp_mp_mul() */
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE); /* mul follows */
    ESP_LOGI(TAG, "esp_mp_mul HW acceleration enabled.");
    ESP_LOGI(TAG, "Number of calls to esp_mp_mul: %lu",
                   esp_mp_mul_usage_ct);
    ESP_LOGI(TAG, "Number of calls to esp_mp_mul with tiny operands: %lu",
                   esp_mp_mul_tiny_ct);
    ESP_LOGI(TAG, "Number of calls to esp_mp_mul HW operand exceeded: %lu",
                   esp_mp_mul_max_exceeded_ct);
    if (esp_mp_mul_error_ct == 0) {
        ESP_LOGI(TAG, "Success: no esp_mp_mul() errors.");
    }
    else {
        ESP_LOGW(TAG, "Number of esp_mp_mul failures: %lu",
                       esp_mp_mul_error_ct);
        ret = MP_VAL;
    }
#endif

#if defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD)
    ESP_LOGI(TAG, "esp_mp_mulmod HW disabled with "
                  "NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD");
#else
    /* Metrics: esp_mp_mulmod() */
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE); /* mulmod follows */

    ESP_LOGI(TAG, "esp_mp_mulmod HW acceleration enabled.");
    /* Metrics: esp_mp_mulmod() */
    ESP_LOGI(TAG, "Number of calls to esp_mp_mulmod: %lu",
                   esp_mp_mulmod_usage_ct);
    ESP_LOGI(TAG, "Number of calls to esp_mp_mulmod HW operand exceeded: %lu",
                   esp_mp_mulmod_max_exceeded_ct);
    ESP_LOGI(TAG, "Number of fallback to SW mp_mulmod: %lu",
                   esp_mp_mulmod_fallback_ct);

    if (esp_mp_mulmod_error_ct == 0) {
        ESP_LOGI(TAG, "Success: no esp_mp_mulmod errors.");
    }
    else {
        ESP_LOGW(TAG, "Number of esp_mp_mulmod failures: %lu",
                       esp_mp_mulmod_error_ct);
        ret = MP_VAL;
    }

    if (esp_mp_mulmod_even_mod_ct == 0) {
        ESP_LOGI(TAG, "Success: no esp_mp_mulmod even mod.");
    }
    else {
        ESP_LOGW(TAG, "Number of esp_mp_mulmod even mod: %lu",
                       esp_mp_mulmod_even_mod_ct);
    }

    if (esp_mp_mulmod_error_ct == 0) {
        ESP_LOGI(TAG, "Success: no esp_mp_mulmod small x or y.");
    }
    else {
        ESP_LOGW(TAG, "Number of esp_mp_mulmod small x: %lu",
                       esp_mp_mulmod_small_x_ct);
        ESP_LOGW(TAG, "Number of esp_mp_mulmod small y: %lu",
                       esp_mp_mulmod_small_y_ct);
    }
#endif /* MULMOD disabled: !NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD */

#if defined(NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD)
    ESP_LOGI(TAG, "esp_mp_exptmod HW disabled with "
                  "NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD");
#else
    /* Metrics: sp_mp_exptmod() */
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_BLANKLINE_MESSAGE); /* exptmod follows */

    ESP_LOGI(TAG, "Number of calls to esp_mp_exptmod: %lu",
                   esp_mp_exptmod_usage_ct);
    ESP_LOGI(TAG, "Number of calls to esp_mp_exptmod HW operand exceeded: %lu",
                   esp_mp_exptmod_max_exceeded_ct);
    ESP_LOGI(TAG, "Number of fallback to SW mp_exptmod: %lu",
                   esp_mp_exptmod_fallback_ct);
    if (esp_mp_exptmod_error_ct == 0) {
        ESP_LOGI(TAG, "Success: no esp_mp_exptmod errors.");
    }
    else {
        ESP_LOGW(TAG, "Number of esp_mp_exptmod errors: %lu",
                       esp_mp_exptmod_error_ct);
        ret = MP_VAL;
    }
#endif /* EXPTMOD not disabled !NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD */

    ESP_LOGI(TAG, "Max N->used: esp_mp_max_used = %lu", esp_mp_max_used);
    ESP_LOGI(TAG, "Max hw wait timeout: esp_mp_max_wait_timeout = %lu",
                   esp_mp_max_wait_timeout);
    ESP_LOGI(TAG, "Max calc timeout: esp_mp_max_timeout = 0x%08lx",
                   esp_mp_max_timeout);

#else
    /* no HW math, no HW math metrics */
    ret = ESP_OK;
#endif /* HW_MATH_ENABLED */


    return ret;
}
#endif /* WOLFSSL_HW_METRICS */

#endif /* WOLFSSL_ESPIDF */
