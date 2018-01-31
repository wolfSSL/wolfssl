#ifndef _WOLFPORT_STM32_H_
#define _WOLFPORT_STM32_H_

#ifdef STM32_HASH

/* Generic STM32 Hashing Function */
/* Supports CubeMX HAL or Standard Peripheral Library */

#include <wolfssl/wolfcrypt/types.h>

#ifdef HASH_DIGEST
    /* The HASH_DIGEST register indicates SHA224/SHA256 support */
    #define STM32_HASH_SHA2
    #define HASH_CR_SIZE 54
    #define HASH_MAX_DIGEST 32
#else
    #define HASH_CR_SIZE 50
    #define HASH_MAX_DIGEST 20
#endif

/* Handle hash differences between CubeMX and StdPeriLib */
#if !defined(HASH_ALGOMODE_HASH) && defined(HASH_AlgoMode_HASH)
    #define HASH_ALGOMODE_HASH HASH_AlgoMode_HASH
#endif
#if !defined(HASH_DATATYPE_8B) && defined(HASH_DataType_8b)
    #define HASH_DATATYPE_8B HASH_DataType_8b
#endif

#ifndef STM32_HASH_TIMEOUT
    #define STM32_HASH_TIMEOUT 0xFFFF
#endif


/* STM32 register size in bytes */
#define STM32_HASH_REG_SIZE  4

/* STM32 Hash Context */
typedef struct {
    /* Context switching registers */
    uint32_t HASH_IMR;
    uint32_t HASH_STR;
    uint32_t HASH_CR;
    uint32_t HASH_CSR[HASH_CR_SIZE];

    /* Hash state / buffers */
    word32 buffer[STM32_HASH_REG_SIZE / sizeof(word32)]; /* partial word buffer */
    word32 buffLen; /* partial word remain */
    word32 loLen;   /* total update bytes
                 (only lsb 6-bits is used for nbr valid bytes in last word) */
} STM32_HASH_Context;


#endif /* STM32_HASH */

#endif /* _WOLFPORT_STM32_H_ */
