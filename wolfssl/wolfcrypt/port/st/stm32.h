/* stm32.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef _WOLFPORT_STM32_H_
#define _WOLFPORT_STM32_H_

/* Generic STM32 Hashing and Crypto Functions */
/* Supports CubeMX HAL or Standard Peripheral Library */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h> /* for MATH_INT_T */

#ifdef STM32_HASH

#define WOLFSSL_NO_HASH_RAW

#ifdef HASH_DIGEST
    /* The HASH_DIGEST register indicates SHA224/SHA256 support */
    #define STM32_HASH_SHA2
    #if defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32MP13)
        #define HASH_CR_SIZE    103
        #define HASH_MAX_DIGEST 64 /* Up to SHA512 */
    #else
        #define HASH_CR_SIZE    54
        #define HASH_MAX_DIGEST 32
    #endif
    #if defined(WOLFSSL_STM32MP13)
        #define STM32_HASH_SHA512
        #define STM32_HASH_SHA512_224
        #define STM32_HASH_SHA512_256
        #define STM32_HASH_SHA384
        #define STM32_HASH_SHA3
    #endif
#else
    #define HASH_CR_SIZE    50
    #define HASH_MAX_DIGEST 20
#endif

/* Handle hash differences between CubeMX and StdPeriLib */
#if !defined(HASH_ALGOMODE_HASH) && defined(HASH_AlgoMode_HASH)
    #define HASH_ALGOMODE_HASH HASH_AlgoMode_HASH
#endif
#if !defined(HASH_DATATYPE_8B)
    #if defined(HASH_DataType_8b)
        #define HASH_DATATYPE_8B HASH_DataType_8b
    #elif defined(HASH_BYTE_SWAP)
        #define HASH_DATATYPE_8B HASH_BYTE_SWAP
    #endif
#endif
#ifndef HASH_STR_NBW
    #define HASH_STR_NBW HASH_STR_NBLW
#endif

#ifndef STM32_HASH_TIMEOUT
    #define STM32_HASH_TIMEOUT 0xFFFF
#endif


/* STM32 register size in bytes */
#define STM32_HASH_REG_SIZE  4
/* Maximum FIFO buffer is 64 bits for SHA256, 128 bits for SHA512 and 144 bits
 * for SHA3 */
#if defined(STM32_HASH_SHA3)
    #define STM32_HASH_FIFO_SIZE 36
#elif defined(STM32_HASH_SHA512) || defined(STM32_HASH_SHA384)
    #define STM32_HASH_FIFO_SIZE 32
#else
    #define STM32_HASH_FIFO_SIZE 16
#endif

/* STM32 Hash Context */
typedef struct {
    /* Context switching registers */
    uint32_t HASH_IMR;
    uint32_t HASH_STR;
    uint32_t HASH_CR;
    uint32_t HASH_CSR[HASH_CR_SIZE];
#ifdef STM32_HASH_SHA3
    uint32_t SHA3CFGR;
#endif

    /* Hash state / buffers */
    word32 buffer[STM32_HASH_FIFO_SIZE+1]; /* partial word buffer */
    word32 buffLen; /* partial word remain */
    word32 loLen;   /* total update bytes
                 (only lsb 6-bits is used for nbr valid bytes in last word) */
    word32 fifoBytes; /* number of currently filled FIFO bytes */
} STM32_HASH_Context;


/* API's */
void wc_Stm32_Hash_Init(STM32_HASH_Context* stmCtx);
int  wc_Stm32_Hash_Update(STM32_HASH_Context* stmCtx, word32 algo,
    const byte* data, word32 len, word32 blockSize);
int  wc_Stm32_Hash_Final(STM32_HASH_Context* stmCtx, word32 algo,
    byte* hash, word32 digestSize);

#endif /* STM32_HASH */


#ifdef STM32_CRYPTO

#if defined(WOLFSSL_STM32MP13)
    #define RNG RNG1
    #define CRYP CRYP1
    #define hcryp hcryp1
    #define FORMAT_BIN RTC_FORMAT_BIN
    #define __HAL_RCC_RNG_CLK_ENABLE __HAL_RCC_RNG1_CLK_ENABLE
    #define __HAL_RCC_HASH_CLK_ENABLE __HAL_RCC_HASH1_CLK_ENABLE
    #define __HAL_RCC_HASH_CLK_DISABLE __HAL_RCC_HASH1_CLK_DISABLE
    /* From stm32_hal_legacy.h, but that header has a bug in it */
    #define HASH_AlgoSelection_MD5       HASH_ALGOSELECTION_MD5
    #define HASH_AlgoSelection_SHA1      HASH_ALGOSELECTION_SHA1
    #define HASH_AlgoSelection_SHA224    HASH_ALGOSELECTION_SHA224
    #define HASH_AlgoSelection_SHA256    HASH_ALGOSELECTION_SHA256

    #define STM32_NOMD5 /* The HASH HAL has no MD5 implementation */
#endif

#ifndef NO_AES
    #if !defined(STM32_CRYPTO_AES_GCM) && (defined(WOLFSSL_STM32F4) || \
            defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32L4) || \
            defined(WOLFSSL_STM32L5) || defined(WOLFSSL_STM32H7) || \
            defined(WOLFSSL_STM32U5) || defined(WOLFSSL_STM32H5) || \
            defined(WOLFSSL_STM32MP13))
        /* Hardware supports AES GCM acceleration */
        #define STM32_CRYPTO_AES_GCM
    #endif

    #if defined(WOLFSSL_STM32WB) || defined(WOLFSSL_STM32WL)
        #define STM32_CRYPTO_AES_ONLY /* crypto engine only supports AES */
        #ifdef WOLFSSL_STM32WB
            #define CRYP AES1
        #else
            #define CRYP AES
        #endif
        #define STM32_HAL_V2
    #endif
    #if defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32L5) || \
        defined(WOLFSSL_STM32U5) || defined(WOLFSSL_STM32H5)
        #if defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32U5)
            #define STM32_CRYPTO_AES_ONLY /* crypto engine only supports AES */
        #endif
        #if defined(WOLFSSL_STM32H5)
            #define __HAL_RCC_CRYP_CLK_DISABLE  __HAL_RCC_AES_CLK_DISABLE
            #define __HAL_RCC_CRYP_CLK_ENABLE   __HAL_RCC_AES_CLK_ENABLE
        #endif
        #define CRYP AES
        #ifndef CRYP_AES_GCM
            #define CRYP_AES_GCM CRYP_AES_GCM_GMAC
        #endif
    #endif

    /* Detect newer CubeMX crypto HAL (HAL_CRYP_Encrypt / HAL_CRYP_Decrypt) */
    #if !defined(STM32_HAL_V2) && defined(CRYP_AES_GCM) && \
        (defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32L5) || \
         defined(WOLFSSL_STM32H7) || defined(WOLFSSL_STM32U5)) || \
         defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32MP13)
        #define STM32_HAL_V2
    #endif

    /* The datatype for STM32 CubeMX HAL Crypt calls */
    #ifdef STM32_HAL_V2
        #define STM_CRYPT_TYPE uint32_t
    #else
        #define STM_CRYPT_TYPE uint8_t
    #endif

    /* CRYPT_AES_GCM starts the IV with 2 */
    #define STM32_GCM_IV_START 2

    struct Aes;
    #ifdef WOLFSSL_STM32_CUBEMX
        int wc_Stm32_Aes_Init(struct Aes* aes, CRYP_HandleTypeDef* hcryp);
        void wc_Stm32_Aes_Cleanup(void);
    #else /* Standard Peripheral Library */
        int wc_Stm32_Aes_Init(struct Aes* aes, CRYP_InitTypeDef* cryptInit,
            CRYP_KeyInitTypeDef* keyInit);
        void wc_Stm32_Aes_Cleanup(void);
    #endif /* WOLFSSL_STM32_CUBEMX */
#endif /* !NO_AES */

#endif /* STM32_CRYPTO */

#if defined(WOLFSSL_STM32_PKA) && defined(HAVE_ECC)
struct ecc_key;
struct WC_RNG;

int stm32_ecc_verify_hash_ex(MATH_INT_T *r, MATH_INT_T *s, const byte* hash,
                    word32 hashlen, int* res, struct ecc_key* key);

int stm32_ecc_sign_hash_ex(const byte* hash, word32 hashlen, struct WC_RNG* rng,
                     struct ecc_key* key, MATH_INT_T *r, MATH_INT_T *s);
#endif /* WOLFSSL_STM32_PKA && HAVE_ECC */


#endif /* _WOLFPORT_STM32_H_ */
