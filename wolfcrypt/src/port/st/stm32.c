/* stm32.c
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

/* Generic STM32 Hashing Function */
/* Supports CubeMX HAL or Standard Peripheral Library */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/port/st/stm32.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef WOLFSSL_STM32_PKA
#include <stdint.h>

#if defined(WOLFSSL_STM32L5)
#include <stm32l5xx_hal_conf.h>
#include <stm32l5xx_hal_pka.h>
#elif defined(WOLFSSL_STM32U5)
#include <stm32u5xx_hal_conf.h>
#include <stm32u5xx_hal_pka.h>
#elif defined(WOLFSSL_STM32WB)
#include <stm32wbxx_hal_conf.h>
#include <stm32wbxx_hal_pka.h>
#elif defined(WOLFSSL_STM32WL)
#include <stm32wlxx_hal_conf.h>
#include <stm32wlxx_hal_pka.h>
#elif defined(WOLFSSL_STM32MP13)
#include <stm32mp13xx_hal_conf.h>
#include <stm32mp13xx_hal_pka.h>
#else
#error Please add the hal_pk.h include
#endif
extern PKA_HandleTypeDef hpka;

#if !defined(WOLFSSL_STM32_PKA_V2) && defined(PKA_ECC_SCALAR_MUL_IN_B_COEFF)
/* PKA hardware like in U5 added coefB and primeOrder */
#define WOLFSSL_STM32_PKA_V2
#endif

#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>

#ifndef WOLFSSL_HAVE_ECC_KEY_GET_PRIV
    /* FIPS build has replaced ecc.h. */
    #define wc_ecc_key_get_priv(key) (&((key)->k))
    #define WOLFSSL_HAVE_ECC_KEY_GET_PRIV
#endif
#endif /* HAVE_ECC */
#endif /* WOLFSSL_STM32_PKA */


#ifdef STM32_HASH

/* #define DEBUG_STM32_HASH */

/* User can override STM32_HASH_CLOCK_ENABLE and STM32_HASH_CLOCK_DISABLE */
#ifndef STM32_HASH_CLOCK_ENABLE
    static WC_INLINE void wc_Stm32_Hash_Clock_Enable(STM32_HASH_Context* stmCtx)
    {
    #ifdef WOLFSSL_STM32_CUBEMX
        __HAL_RCC_HASH_CLK_ENABLE();
    #else
        RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, ENABLE);
    #endif
        (void)stmCtx;
    }
    #define STM32_HASH_CLOCK_ENABLE(ctx) wc_Stm32_Hash_Clock_Enable(ctx)
#endif

#ifndef STM32_HASH_CLOCK_DISABLE
    static WC_INLINE void wc_Stm32_Hash_Clock_Disable(STM32_HASH_Context* stmCtx)
    {
    #ifdef WOLFSSL_STM32_CUBEMX
        __HAL_RCC_HASH_CLK_DISABLE();
    #else
        RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, DISABLE);
    #endif
        (void)stmCtx;
    }
    #define STM32_HASH_CLOCK_DISABLE(ctx) wc_Stm32_Hash_Clock_Disable(ctx)
#endif


/* STM32 Port Internal Functions */
static void wc_Stm32_Hash_NumValidBits(word32 len)
{
    /* calculate number of valid bits in last word */
    /* NBLW = 0x00 (all 32-bits are valid) */
    word32 nbvalidbytesdata = (len % STM32_HASH_REG_SIZE);
    HASH->STR &= ~HASH_STR_NBW;
    HASH->STR |= (8 * nbvalidbytesdata) & HASH_STR_NBW;

#ifdef DEBUG_STM32_HASH
    printf("STM Valid Last bits (%d)\n", 8 * nbvalidbytesdata);
#endif
}

static void wc_Stm32_Hash_SaveContext(STM32_HASH_Context* ctx)
{
    int i;

    /* save context registers */
    ctx->HASH_IMR = HASH->IMR;
    ctx->HASH_STR = HASH->STR;
    ctx->HASH_CR  = HASH->CR;
#ifdef STM32_HASH_SHA3
    ctx->SHA3CFGR  = HASH->SHA3CFGR;
#endif
    for (i=0; i<HASH_CR_SIZE; i++) {
        ctx->HASH_CSR[i] = HASH->CSR[i];
    }

#ifdef DEBUG_STM32_HASH
    printf("STM Save CR %lx, IMR %lx, STR %lx\n",
        HASH->CR, HASH->IMR, HASH->STR);
#endif
}

static void wc_Stm32_Hash_RestoreContext(STM32_HASH_Context* ctx, int algo)
{
    int i;

    if (ctx->HASH_CR == 0) {
        /* init content */

    #if defined(HASH_IMR_DINIE) && defined(HASH_IMR_DCIE)
        /* enable IRQ's */
        HASH->IMR |= (HASH_IMR_DINIE | HASH_IMR_DCIE);
    #endif

        /* reset the control register */
        HASH->CR &= ~(HASH_CR_ALGO | HASH_CR_MODE | HASH_CR_DATATYPE
        #ifdef HASH_CR_LKEY
            | HASH_CR_LKEY
        #endif
        );

        /* configure algorithm, mode and data type */
        HASH->CR |= (algo | HASH_ALGOMODE_HASH | HASH_DATATYPE_8B);

        /* reset HASH processor */
        HASH->CR |= HASH_CR_INIT;

        /* by default mark all bits valid */
        wc_Stm32_Hash_NumValidBits(0);

#ifdef DEBUG_STM32_HASH
        printf("STM Init algo %x\n", algo);
#endif
    }
    else {
        /* restore context registers */
        HASH->IMR = ctx->HASH_IMR;
        HASH->STR = ctx->HASH_STR;
        HASH->CR = ctx->HASH_CR;
#ifdef STM32_HASH_SHA3
        HASH->SHA3CFGR = ctx->SHA3CFGR;
#endif

        /* Initialize the hash processor */
        HASH->CR |= HASH_CR_INIT;

        /* continue restoring context registers */
        for (i=0; i<HASH_CR_SIZE; i++) {
            HASH->CSR[i] = ctx->HASH_CSR[i];
        }

#ifdef DEBUG_STM32_HASH
        printf("STM Restore CR %lx, IMR %lx, STR %lx\n",
            HASH->CR, HASH->IMR, HASH->STR);
#endif
    }
}

static void wc_Stm32_Hash_GetDigest(byte* hash, int digestSize)
{
    word32 digest[HASH_MAX_DIGEST/sizeof(word32)];
    int i = 0, sz;

    if (digestSize > HASH_MAX_DIGEST)
        digestSize = HASH_MAX_DIGEST;

    sz = digestSize;
    while (sz > 0) {
        /* first 20 bytes come from instance HR */
        if (i < 5) {
            digest[i] = HASH->HR[i];
        }
    #ifdef HASH_DIGEST
        /* reset comes from HASH_DIGEST */
        else {
            digest[i] = HASH_DIGEST->HR[i];
        }
    #endif
        i++;
        sz -= 4;
    }

    ByteReverseWords(digest, digest, digestSize);

    XMEMCPY(hash, digest, digestSize);

#ifdef DEBUG_STM32_HASH
    {
        word32 ii;
        printf("STM Digest %d\n", digestSize);
        for (ii=0; ii<digestSize/sizeof(word32); ii++) {
            printf("\tDIG 0x%04x\n", digest[ii]);
        }
    }
#endif
}

static int wc_Stm32_Hash_WaitDone(STM32_HASH_Context* stmCtx)
{
    int timeout = 0;
    (void)stmCtx;

    /* wait until not busy and hash digest / input block are complete */
    while ((HASH->SR & HASH_SR_BUSY) &&
        #ifdef HASH_IMR_DCIE
            (HASH->SR & HASH_SR_DCIS) == 0 &&
        #endif
        #ifdef HASH_IMR_DINIE
            (HASH->SR & HASH_SR_DINIS) == 0 &&
        #endif
        ++timeout < STM32_HASH_TIMEOUT) {
    };

#ifdef DEBUG_STM32_HASH
    printf("STM Wait done %d, HASH->SR %lx\n", timeout, HASH->SR);
#endif

    /* verify timeout did not occur */
    if (timeout >= STM32_HASH_TIMEOUT) {
        return WC_TIMEOUT_E;
    }
    return 0;
}

static void wc_Stm32_Hash_Data(STM32_HASH_Context* stmCtx, word32 len)
{
    word32 i, blocks;

    if (len > stmCtx->buffLen)
        len = stmCtx->buffLen;

    /* calculate number of 32-bit blocks - round up */
    blocks = ((len + STM32_HASH_REG_SIZE-1) / STM32_HASH_REG_SIZE);
#ifdef DEBUG_STM32_HASH
    printf("STM DIN %d blocks\n", blocks);
#endif
    for (i=0; i<blocks; i++) {
    #ifdef DEBUG_STM32_HASH
        printf("\tDIN 0x%04x\n", stmCtx->buffer[i]);
    #endif
        HASH->DIN = stmCtx->buffer[i];
    }
    stmCtx->loLen += len; /* total */
    stmCtx->buffLen -= len;
    if (stmCtx->buffLen > 0) {
        XMEMMOVE(stmCtx->buffer, (byte*)stmCtx->buffer+len, stmCtx->buffLen);
    }
}


/* STM32 Port Exposed Functions */
void wc_Stm32_Hash_Init(STM32_HASH_Context* stmCtx)
{
    /* clear context */
    /* this also gets called after finish */
    XMEMSET(stmCtx, 0, sizeof(STM32_HASH_Context));
}

int wc_Stm32_Hash_Update(STM32_HASH_Context* stmCtx, word32 algo,
    const byte* data, word32 len, word32 blockSize)
{
    int ret = 0;
    byte* local = (byte*)stmCtx->buffer;
    int wroteToFifo = 0;
    word32 chunkSz;

#ifdef DEBUG_STM32_HASH
    printf("STM Hash Update: algo %x, len %d, buffLen %d, fifoBytes %d\n",
        algo, len, stmCtx->buffLen, stmCtx->fifoBytes);
#endif
    (void)blockSize;

    /* check that internal buffLen is valid */
    if (stmCtx->buffLen > (word32)sizeof(stmCtx->buffer)) {
        return BUFFER_E;
    }

    /* turn on hash clock */
    STM32_HASH_CLOCK_ENABLE(stmCtx);

    /* restore hash context or init as new hash */
    wc_Stm32_Hash_RestoreContext(stmCtx, algo);

    /* write blocks to FIFO */
    while (len) {
        word32 add;

        chunkSz = blockSize;
        /* fill the FIFO plus one additional to flush the first block */
        if (!stmCtx->fifoBytes) {
            chunkSz += STM32_HASH_REG_SIZE;
        }

        add = min(len, chunkSz - stmCtx->buffLen);
        XMEMCPY(&local[stmCtx->buffLen], data, add);

        stmCtx->buffLen += add;
        data            += add;
        len             -= add;

        if (stmCtx->buffLen == chunkSz) {
            wc_Stm32_Hash_Data(stmCtx, stmCtx->buffLen);
            wroteToFifo = 1;
            stmCtx->fifoBytes += chunkSz;
        }
    }

    if (wroteToFifo) {
        /* make sure hash operation is done */
        ret = wc_Stm32_Hash_WaitDone(stmCtx);

        /* save hash state for next operation */
        wc_Stm32_Hash_SaveContext(stmCtx);
    }

    /* turn off hash clock */
    STM32_HASH_CLOCK_DISABLE(stmCtx);

    return ret;
}

int wc_Stm32_Hash_Final(STM32_HASH_Context* stmCtx, word32 algo,
    byte* hash, word32 digestSize)
{
    int ret = 0;

#ifdef DEBUG_STM32_HASH
    printf("STM Hash Final: algo %x, digestSz %d, buffLen %d, fifoBytes %d\n",
        algo, digestSize, stmCtx->buffLen, stmCtx->fifoBytes);
#endif

    /* turn on hash clock */
    STM32_HASH_CLOCK_ENABLE(stmCtx);

    /* restore hash context or init as new hash */
    wc_Stm32_Hash_RestoreContext(stmCtx, algo);

    /* finish reading any trailing bytes into FIFO */
    if (stmCtx->buffLen > 0) {
        /* send remainder of data */
        wc_Stm32_Hash_Data(stmCtx, stmCtx->buffLen);
    }

    /* calculate number of valid bits in last word */
    wc_Stm32_Hash_NumValidBits(stmCtx->loLen + stmCtx->buffLen);

    /* start hash processor */
    HASH->STR |= HASH_STR_DCAL;

    /* wait for hash done */
    ret = wc_Stm32_Hash_WaitDone(stmCtx);
    if (ret == 0) {
        /* read message digest */
        wc_Stm32_Hash_GetDigest(hash, digestSize);
    }

    /* turn off hash clock */
    STM32_HASH_CLOCK_DISABLE(stmCtx);

    return ret;
}

#endif /* STM32_HASH */


#ifdef STM32_CRYPTO

#ifndef NO_AES
#ifdef WOLFSSL_STM32_CUBEMX
int wc_Stm32_Aes_Init(Aes* aes, CRYP_HandleTypeDef* hcryp)
{
    int ret;
    word32 keySize;
#ifdef STM32_HW_CLOCK_AUTO
    /* enable the peripheral clock */
    __HAL_RCC_CRYP_CLK_ENABLE();
#endif

    ret = wc_AesGetKeySize(aes, &keySize);
    if (ret != 0)
        return ret;

    XMEMSET(hcryp, 0, sizeof(CRYP_HandleTypeDef));
    switch (keySize) {
        case 16: /* 128-bit key */
            hcryp->Init.KeySize = CRYP_KEYSIZE_128B;
            break;
    #ifdef CRYP_KEYSIZE_192B
        case 24: /* 192-bit key */
            hcryp->Init.KeySize = CRYP_KEYSIZE_192B;
            break;
    #endif
        case 32: /* 256-bit key */
            hcryp->Init.KeySize = CRYP_KEYSIZE_256B;
            break;
        default:
            break;
    }
    hcryp->Instance = CRYP;
    hcryp->Init.DataType = CRYP_DATATYPE_8B;
    hcryp->Init.pKey = (STM_CRYPT_TYPE*)aes->key;
#ifdef STM32_HAL_V2
    hcryp->Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
    #ifdef WOLFSSL_STM32MP13
        hcryp->Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;
    #elif defined(CRYP_HEADERWIDTHUNIT_BYTE)
        hcryp->Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_BYTE;
    #endif
#endif

    return 0;
}

void wc_Stm32_Aes_Cleanup(void)
{
#ifdef STM32_HW_CLOCK_AUTO
    /* disable the peripheral clock */
    __HAL_RCC_CRYP_CLK_DISABLE();
#endif
}
#else /* Standard Peripheral Library */

int wc_Stm32_Aes_Init(Aes* aes, CRYP_InitTypeDef* cryptInit,
    CRYP_KeyInitTypeDef* keyInit)
{
    int ret;
    word32 keySize;
    word32* aes_key;

    ret = wc_AesGetKeySize(aes, &keySize);
    if (ret != 0)
        return ret;

    aes_key = aes->key;

    /* crypto structure initialization */
    CRYP_KeyStructInit(keyInit);
    CRYP_StructInit(cryptInit);

    /* load key into correct registers */
    switch (keySize) {
        case 16: /* 128-bit key */
            cryptInit->CRYP_KeySize = CRYP_KeySize_128b;
            keyInit->CRYP_Key2Left  = aes_key[0];
            keyInit->CRYP_Key2Right = aes_key[1];
            keyInit->CRYP_Key3Left  = aes_key[2];
            keyInit->CRYP_Key3Right = aes_key[3];
            break;

        case 24: /* 192-bit key */
            cryptInit->CRYP_KeySize = CRYP_KeySize_192b;
            keyInit->CRYP_Key1Left  = aes_key[0];
            keyInit->CRYP_Key1Right = aes_key[1];
            keyInit->CRYP_Key2Left  = aes_key[2];
            keyInit->CRYP_Key2Right = aes_key[3];
            keyInit->CRYP_Key3Left  = aes_key[4];
            keyInit->CRYP_Key3Right = aes_key[5];
            break;

        case 32: /* 256-bit key */
            cryptInit->CRYP_KeySize = CRYP_KeySize_256b;
            keyInit->CRYP_Key0Left  = aes_key[0];
            keyInit->CRYP_Key0Right = aes_key[1];
            keyInit->CRYP_Key1Left  = aes_key[2];
            keyInit->CRYP_Key1Right = aes_key[3];
            keyInit->CRYP_Key2Left  = aes_key[4];
            keyInit->CRYP_Key2Right = aes_key[5];
            keyInit->CRYP_Key3Left  = aes_key[6];
            keyInit->CRYP_Key3Right = aes_key[7];
            break;

        default:
            break;
    }
    cryptInit->CRYP_DataType = CRYP_DataType_8b;

    return 0;
}

void wc_Stm32_Aes_Cleanup(void)
{
}
#endif /* WOLFSSL_STM32_CUBEMX */
#endif /* !NO_AES */
#endif /* STM32_CRYPTO */

#ifdef WOLFSSL_STM32_PKA

/* Reverse array in memory (in place) */
#ifdef HAVE_ECC

/* convert from mp_int to STM32 PKA HAL integer, as array of bytes of size sz.
 * if mp_int has less bytes than sz, add zero bytes at most significant byte
 * positions.
 * This is when for example modulus is 32 bytes (P-256 curve)
 * and mp_int has only 31 bytes, we add leading zeros
 * so that result array has 32 bytes, same as modulus (sz).
 */
static int stm32_get_from_mp_int(uint8_t *dst, const mp_int *a, int sz)
{
    int res, szbin, offset;

    if (dst == NULL || a == NULL || sz < 0)
        return BAD_FUNC_ARG;

    /* check how many bytes are in the mp_int */
    szbin = mp_unsigned_bin_size(a);
    if (szbin < 0 || szbin > sz)
        return BUFFER_E;

    /* compute offset from dst */
    offset = sz - szbin;
    if (offset < 0)
        offset = 0;
    if (offset > sz)
        offset = sz;

    /* add leading zeroes */
    if (offset)
        XMEMSET(dst, 0, offset);

    /* convert mp_int to array of bytes */
    res = mp_to_unsigned_bin((mp_int*)a, dst + offset);
    return res;
}

static int stm32_getabs_from_mp_int(uint8_t *dst, const mp_int *a, int sz,
    uint32_t* abs_sign)
{
    int res;
    mp_int x;

    if (dst == NULL || a == NULL || sz < 0 || abs_sign == NULL)
        return BAD_FUNC_ARG;

    res = mp_init(&x);
    if (res == MP_OKAY) {
        /* make abs(x) and capture sign */
    #if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH) || \
        ((defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
            defined(WOLFSSL_SP_INT_NEGATIVE))
        *abs_sign = x.sign;
    #else
        *abs_sign = 1; /* default to negative */
    #endif
        res = mp_abs((mp_int*)a, &x);
        if (res == MP_OKAY)
            res = stm32_get_from_mp_int(dst, &x, sz);
        mp_clear(&x);
    }
    return res;
}

/* convert hex string to unsigned char */
static int stm32_getabs_from_hexstr(const char* hex, uint8_t* dst, int sz,
    uint32_t *abs_sign)
{
    int res;
    mp_int x;

    if (hex == NULL || dst == NULL || sz < 0)
        return BAD_FUNC_ARG;

    res = mp_init(&x);
    if (res == MP_OKAY) {
        res = mp_read_radix(&x, hex, MP_RADIX_HEX);
        /* optionally make abs(x) and capture sign */
        if (res == MP_OKAY && abs_sign != NULL) {
        #if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH) || \
            ((defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
                defined(WOLFSSL_SP_INT_NEGATIVE))
            *abs_sign = x.sign;
        #else
            *abs_sign = 1; /* default to negative */
        #endif
            res = mp_abs(&x, &x);
        }
        if (res == MP_OKAY)
            res = stm32_get_from_mp_int(dst, &x, sz);
        mp_clear(&x);
    }
    return res;
}
static int stm32_get_from_hexstr(const char* hex, uint8_t* dst, int sz)
{
    return stm32_getabs_from_hexstr(hex, dst, sz, NULL);
}

/* STM32 PKA supports up to 640-bit numbers */
#define STM32_MAX_ECC_SIZE (80)

#ifdef WOLFSSL_STM32_PKA_V2
/* find curve based on prime/modulus and return order/coefB */
static int stm32_get_curve_params(mp_int* modulus,
    uint8_t* order, uint8_t* coefB)
{
    int res, i, found = 0;
    mp_int modulusChk;
    res = mp_init(&modulusChk);
    if (res != MP_OKAY)
        return res;
    for (i = 0; ecc_sets[i].size != 0 && ecc_sets[i].name != NULL; i++) {
        const ecc_set_type* curve = &ecc_sets[i];
        /* match based on curve prime */
        if ((res = mp_read_radix(&modulusChk, curve->prime, MP_RADIX_HEX)) ==
                MP_OKAY && (mp_cmp(modulus, &modulusChk) == MP_EQ))
        {
            found = 1;
            if (order) {
                res = stm32_get_from_hexstr(curve->order, order, curve->size);
            }
            if (coefB) {
                res = stm32_get_from_hexstr(curve->Bf, coefB, curve->size);
            }
            break;
        }
    }
    mp_clear(&modulusChk);
    if (!found && res == MP_OKAY) {
        res = MP_RANGE;
    }
    return res;
}
#endif /* WOLFSSL_STM32_PKA_V2 */


/**
   Perform a point multiplication  (timing resistant)
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   order    curve order
   rng      Random Generator struct (not used)
   map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/

int wc_ecc_mulmod_ex2(const mp_int* k, ecc_point *G, ecc_point *R, mp_int* a,
                      mp_int* modulus, mp_int* o, WC_RNG* rng, int map,
                      void* heap)
{
    PKA_ECCMulInTypeDef pka_mul;
    PKA_ECCMulOutTypeDef pka_mul_res;
    int szModulus;
    int szkbin;
    int status;
    int res;
    uint8_t Gxbin[STM32_MAX_ECC_SIZE];
    uint8_t Gybin[STM32_MAX_ECC_SIZE];
    uint8_t kbin[STM32_MAX_ECC_SIZE];
    uint8_t PtXbin[STM32_MAX_ECC_SIZE];
    uint8_t PtYbin[STM32_MAX_ECC_SIZE];
    uint8_t prime[STM32_MAX_ECC_SIZE];
    uint8_t coefA[STM32_MAX_ECC_SIZE];
#ifdef WOLFSSL_STM32_PKA_V2
    uint8_t coefB[STM32_MAX_ECC_SIZE];
    uint8_t order[STM32_MAX_ECC_SIZE];
#endif
    uint32_t coefA_sign = 1;

    (void)rng;

    XMEMSET(&pka_mul, 0x00, sizeof(PKA_ECCMulInTypeDef));
    XMEMSET(&pka_mul_res, 0x00, sizeof(PKA_ECCMulOutTypeDef));
    pka_mul_res.ptX = PtXbin;
    pka_mul_res.ptY = PtYbin;

    if (k == NULL || G == NULL || R == NULL || modulus == NULL) {
        return ECC_BAD_ARG_E;
    }

    szModulus = mp_unsigned_bin_size(modulus);
    szkbin = mp_unsigned_bin_size(k);

    res = stm32_get_from_mp_int(kbin, k, szkbin);
    if (res == MP_OKAY)
        res = stm32_get_from_mp_int(Gxbin, G->x, szModulus);
    if (res == MP_OKAY)
        res = stm32_get_from_mp_int(Gybin, G->y, szModulus);
    if (res == MP_OKAY)
        res = stm32_get_from_mp_int(prime, modulus, szModulus);
    if (res == MP_OKAY)
        res = stm32_getabs_from_mp_int(coefA, a, szModulus, &coefA_sign);
#ifdef WOLFSSL_STM32_PKA_V2
    XMEMSET(order, 0, sizeof(order));
    XMEMSET(coefB, 0, sizeof(coefB));
    if (res == MP_OKAY) {
        if (o != NULL) {
            /* use provided order and get coefB */
            res = stm32_get_from_mp_int(order, o, szModulus);
            if (res == MP_OKAY) {
                res = stm32_get_curve_params(modulus, NULL, coefB);
            }
        }
        else {
            /* get order and coefB for matching prime */
            res = stm32_get_curve_params(modulus, order, coefB);
        }
    }
#endif
    if (res != MP_OKAY)
        return res;

    pka_mul.modulusSize = szModulus;
    pka_mul.coefSign = coefA_sign;
    pka_mul.coefA = coefA;
    pka_mul.modulus = prime;
    pka_mul.pointX = Gxbin;
    pka_mul.pointY = Gybin;
    pka_mul.scalarMulSize = szkbin;
    pka_mul.scalarMul = kbin;
#ifdef WOLFSSL_STM32_PKA_V2
    pka_mul.coefB = coefB;
    pka_mul.primeOrder = order;
#endif

    status = HAL_PKA_ECCMul(&hpka, &pka_mul, HAL_MAX_DELAY);
    if (status != HAL_OK) {
        HAL_PKA_RAMReset(&hpka);
        return WC_HW_E;
    }
    pka_mul_res.ptX = Gxbin;
    pka_mul_res.ptY = Gybin;
    HAL_PKA_ECCMul_GetResult(&hpka, &pka_mul_res);
    res = mp_read_unsigned_bin(R->x, Gxbin, szModulus);
    if (res == MP_OKAY) {
        res = mp_read_unsigned_bin(R->y, Gybin, szModulus);

#if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH) || \
    ((defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
        defined(WOLFSSL_SP_INT_NEGATIVE))
        /* if k is negative, we compute the multiplication with abs(-k)
         * with result (x, y) and modify the result to (x, -y)
         */
        R->y->sign = k->sign;
#endif
    }
    if (res == MP_OKAY)
        res = mp_set(R->z, 1);
    HAL_PKA_RAMReset(&hpka);

    (void)heap;

    return res;
}

int wc_ecc_mulmod_ex(const mp_int *k, ecc_point *G, ecc_point *R, mp_int* a,
    mp_int *modulus, int map, void* heap)
{
    return wc_ecc_mulmod_ex2(k, G, R, a, modulus, NULL, NULL, map, heap);
}

int ecc_map_ex(ecc_point* P, mp_int* modulus, mp_digit mp, int ct)
{
    /* this is handled in hardware, so no projective mapping needed */
    (void)P;
    (void)modulus;
    (void)mp;
    (void)ct;
    return MP_OKAY;
}

int stm32_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                    word32 hashlen, int* res, ecc_key* key)
{
    PKA_ECDSAVerifInTypeDef pka_ecc;
    int size;
    int szrbin;
    int status;
    uint8_t Rbin[STM32_MAX_ECC_SIZE];
    uint8_t Sbin[STM32_MAX_ECC_SIZE];
    uint8_t Qxbin[STM32_MAX_ECC_SIZE];
    uint8_t Qybin[STM32_MAX_ECC_SIZE];
    uint8_t Hashbin[STM32_MAX_ECC_SIZE];
    uint8_t privKeybin[STM32_MAX_ECC_SIZE];
    uint8_t prime[STM32_MAX_ECC_SIZE];
    uint8_t coefA[STM32_MAX_ECC_SIZE];
    uint8_t gen_x[STM32_MAX_ECC_SIZE];
    uint8_t gen_y[STM32_MAX_ECC_SIZE];
    uint8_t order[STM32_MAX_ECC_SIZE];
    uint32_t coefA_sign = 1;

    XMEMSET(&pka_ecc, 0x00, sizeof(PKA_ECDSAVerifInTypeDef));

    if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL ||
            key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }
    *res = 0;

    szrbin = mp_unsigned_bin_size(r);
    size = wc_ecc_size(key);

    status = stm32_get_from_mp_int(Rbin, r, szrbin);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Sbin, s, szrbin);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Qxbin, key->pubkey.x, size);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Qybin, key->pubkey.y, size);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(privKeybin, wc_ecc_key_get_priv(key),
            size);
    if (status != MP_OKAY)
        return status;


    /* find parameters for the selected curve */
    status = stm32_get_from_hexstr(key->dp->prime, prime, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->order, order, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gx, gen_x, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gy, gen_y, size);
    if (status == MP_OKAY)
        status = stm32_getabs_from_hexstr(key->dp->Af, coefA, size, &coefA_sign);
    if (status != MP_OKAY)
        return status;

    pka_ecc.primeOrderSize =  size;
    pka_ecc.modulusSize =     size;
    pka_ecc.coefSign =        coefA_sign;
    pka_ecc.coef =            coefA;
    pka_ecc.modulus =         prime;
    pka_ecc.basePointX =      gen_x;
    pka_ecc.basePointY =      gen_y;
    pka_ecc.primeOrder =      order;
    pka_ecc.pPubKeyCurvePtX = Qxbin;
    pka_ecc.pPubKeyCurvePtY = Qybin;
    pka_ecc.RSign =           Rbin;
    pka_ecc.SSign =           Sbin;

    XMEMSET(Hashbin, 0, STM32_MAX_ECC_SIZE);
    if (hashlen > STM32_MAX_ECC_SIZE) {
        return ECC_BAD_ARG_E;
    }
    else if (hashlen > size) {
        /* in the case that hashlen is larger than key size place hash at
         * beginning of buffer */
        XMEMCPY(Hashbin, hash, size);
    }
    else {
        /* in all other cases where hashlen is equal to or less than the key
         * size pad the Hashbin buffer with leading zero's */
        XMEMCPY(Hashbin + (size - hashlen), hash, hashlen);
    }
    pka_ecc.hash =            Hashbin;

    status = HAL_PKA_ECDSAVerif(&hpka, &pka_ecc, HAL_MAX_DELAY);
    if (status != HAL_OK) {
        HAL_PKA_RAMReset(&hpka);
        return WC_HW_E;
    }
    *res = HAL_PKA_ECDSAVerif_IsValidSignature(&hpka);
    HAL_PKA_RAMReset(&hpka);
    return status;
}

int stm32_ecc_sign_hash_ex(const byte* hash, word32 hashlen, WC_RNG* rng,
                     ecc_key* key, mp_int *r, mp_int *s)
{
    PKA_ECDSASignInTypeDef pka_ecc;
    PKA_ECDSASignOutTypeDef pka_ecc_out;
    int size;
    int status;
    mp_int gen_k;
    mp_int order_mp;
    uint8_t Keybin[STM32_MAX_ECC_SIZE];
    uint8_t Intbin[STM32_MAX_ECC_SIZE];
    uint8_t Rbin[STM32_MAX_ECC_SIZE];
    uint8_t Sbin[STM32_MAX_ECC_SIZE];
    uint8_t Hashbin[STM32_MAX_ECC_SIZE];
    uint8_t prime[STM32_MAX_ECC_SIZE];
    uint8_t coefA[STM32_MAX_ECC_SIZE];
#ifdef WOLFSSL_STM32_PKA_V2
    uint8_t coefB[STM32_MAX_ECC_SIZE];
#endif
    uint8_t gen_x[STM32_MAX_ECC_SIZE];
    uint8_t gen_y[STM32_MAX_ECC_SIZE];
    uint8_t order[STM32_MAX_ECC_SIZE];
    uint32_t coefA_sign = 1;

    XMEMSET(&pka_ecc, 0x00, sizeof(PKA_ECDSASignInTypeDef));
    XMEMSET(&pka_ecc_out, 0x00, sizeof(PKA_ECDSASignOutTypeDef));

    if (r == NULL || s == NULL || hash == NULL || key == NULL ||
            key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }

    size = wc_ecc_size(key);

    /* find parameters for the selected curve */
    status = stm32_get_from_hexstr(key->dp->prime, prime, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->order, order, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gx, gen_x, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gy, gen_y, size);
    if (status == MP_OKAY)
        status = stm32_getabs_from_hexstr(key->dp->Af, coefA, size, &coefA_sign);
#ifdef WOLFSSL_STM32_PKA_V2
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Bf, coefB, size);
#endif
    if (status != MP_OKAY)
        return status;

    /* generate random part of "k" */
    mp_init(&gen_k);
    mp_init(&order_mp);
    status = mp_read_unsigned_bin(&order_mp, order, size);
    if (status == MP_OKAY)
        status = wc_ecc_gen_k(rng, size, &gen_k, &order_mp);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Intbin, &gen_k, size);
    mp_clear(&gen_k);
    mp_clear(&order_mp);
    if (status != MP_OKAY)
        return status;

    /* get private part of "k" */
    status = stm32_get_from_mp_int(Keybin, wc_ecc_key_get_priv(key), size);
    if (status != MP_OKAY)
        return status;

    pka_ecc.primeOrderSize =  size;
    pka_ecc.modulusSize =     size;
    pka_ecc.coefSign =        coefA_sign;
    pka_ecc.coef =            coefA;
#ifdef WOLFSSL_STM32_PKA_V2
    pka_ecc.coefB =           coefB;
#endif
    pka_ecc.modulus =         prime;
    pka_ecc.basePointX =      gen_x;
    pka_ecc.basePointY =      gen_y;
    pka_ecc.primeOrder =      order;

    XMEMSET(Hashbin, 0, STM32_MAX_ECC_SIZE);
    if (hashlen > STM32_MAX_ECC_SIZE) {
        return ECC_BAD_ARG_E;
    }
    else if (hashlen > size) {
        /* in the case that hashlen is larger than key size place hash at
         * beginning of buffer */
        XMEMCPY(Hashbin, hash, size);
    }
    else {
        /* in all other cases where hashlen is equal to or less than the key
         * size pad the Hashbin buffer with leading zero's */
        XMEMCPY(Hashbin + (size - hashlen), hash, hashlen);
    }
    pka_ecc.hash =            Hashbin;
    pka_ecc.integer =         Intbin;
    pka_ecc.privateKey =      Keybin;

    /* Assign R, S static buffers */
    pka_ecc_out.RSign = Rbin;
    pka_ecc_out.SSign = Sbin;

    status = HAL_PKA_ECDSASign(&hpka, &pka_ecc, HAL_MAX_DELAY);
    if (status != HAL_OK) {
        HAL_PKA_RAMReset(&hpka);
        return WC_HW_E;
    }
    HAL_PKA_ECDSASign_GetResult(&hpka, &pka_ecc_out, NULL);
    status = mp_read_unsigned_bin(r, pka_ecc_out.RSign, size);
    if (status == MP_OKAY)
        status = mp_read_unsigned_bin(s, pka_ecc_out.SSign, size);
    HAL_PKA_RAMReset(&hpka);
    return status;
}

#endif /* HAVE_ECC */
#endif /* WOLFSSL_STM32_PKA */
