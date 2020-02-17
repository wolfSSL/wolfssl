/* test.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

/* wolfSSL and wolfCrypt */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas_sce_ra6m3g.h>
/* Renesas RA SCE */
#include "common/hw_sce_common.h"
#include "hw_sce_private.h"
#include "hw_sce_trng_private.h"
#include "hw_sce_hash_private.h"
#include "hw_sce_aes_private.h"

int wc_Renesas_SCE_init(void) {
    fsp_err_t ret;

    HW_SCE_PowerOn();
    HW_SCE_SoftReset();

    ret = HW_SCE_Initialization1();
    if (FSP_SUCCESS == ret) {
        ret = HW_SCE_Initialization2();
    }

    if (FSP_SUCCESS == ret) {
        ret = HW_SCE_secureBoot();
        HW_SCE_EndianSetLittle();
    }

    return (int)ret;
}

/* TRNG */
int wc_Renesas_GenerateSeed(OS_Seed* os, byte* output, word32 sz) {
    int ret = FSP_SUCCESS;
    uint32_t tmpOut[4] = {0};

    if (!(os && output && sz > 0))
        ret = BAD_FUNC_ARG;

    /* Fill output with multiples of 128-bit random numbers */
    while (sz >= sizeof(tmpOut) && ret == FSP_SUCCESS) {
        ret = HW_SCE_RNG_Read((uint32_t*) output);
        output += sizeof(tmpOut);
        sz -= sizeof(tmpOut);
    }

    /* Truncate random number when sz is less than 128-bits */
    if (sz > 0 && ret == FSP_SUCCESS) {
        ret = HW_SCE_RNG_Read(tmpOut);
        XMEMCPY(output, tmpOut, sz);
    }

    if (ret == FSP_SUCCESS)
        ret = 0;

    return ret;
}

/* SHA-256 */
int wc_Renesas_Sha256Transform(wc_Sha256* sha256, const byte* data) {
    int ret = WOLFSSL_SUCCESS;
    (void) data;

    if (sha256 == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret != BAD_FUNC_ARG) {
        ret = wolfSSL_CryptHwMutexLock();
        HW_SCE_EndianSetBig();
    }

    if (ret == 0) {
        ret = HW_SCE_SHA256_UpdateHash((const uint32_t*) sha256->buffer,
                            (uint32_t) WC_SHA256_BLOCK_SIZE  / sizeof(word32),
                            (uint32_t*) sha256->digest);
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG)
        ret = WC_HW_E;

    return ret;
}

/* AES */
int wc_Renesas_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 keySize = 0;
    uint32_t num_words = 0;
    int ret = 0;

    /* Only accept input with size that is a multiple AES_BLOCK_SIZE */
    if (sz % AES_BLOCK_SIZE != 0) {
        ret = BAD_FUNC_ARG;
    }

    if (aes == NULL || out == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret != BAD_FUNC_ARG) {
        wc_AesGetKeySize(aes, &keySize);
    }

    if (ret != BAD_FUNC_ARG && wolfSSL_CryptHwMutexLock() == 0 && sz)
    {
        /* Format AES Key for Little Endian HW */
        if (keySize == 16 || keySize == 32) {
            HW_SCE_EndianSetLittle();
        }

        num_words = (sz / sizeof(word32));

        switch (keySize) {
        case 16:
            ret =  HW_SCE_AES_128CbcEncrypt((const uint32_t *) aes->key,
                                            (const uint32_t *) aes->reg,
                                            (const uint32_t)   num_words,
                                            (const uint32_t *) in,
                                            (uint32_t *) out,
                                            (uint32_t *) aes->reg);
            break;
        case 32:
            ret =  HW_SCE_AES_256CbcEncrypt((const uint32_t *) aes->key,
                                            (const uint32_t *) aes->reg,
                                            (const uint32_t)   num_words,
                                            (const uint32_t *) in,
                                            (uint32_t *) out,
                                            (uint32_t *) aes->reg);
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
        }
    }
    wolfSSL_CryptHwMutexUnLock();

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG)
        ret = WC_HW_E;

    return ret;
}

int wc_Renesas_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 keySize = 0;
    uint32_t num_words = 0;
    int ret = 0;

    /* Only accept input with size that is a multiple AES_BLOCK_SIZE */
    if (sz % AES_BLOCK_SIZE != 0) {
        ret = BAD_FUNC_ARG;
    }

    if (aes == NULL || out == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret != BAD_FUNC_ARG) {
        wc_AesGetKeySize(aes, &keySize);
    }

    if (ret != BAD_FUNC_ARG && wolfSSL_CryptHwMutexLock() == 0 && sz)
    {
        /* Format AES Key for Little Endian HW */
        if (keySize == 16 || keySize == 32) {
            HW_SCE_EndianSetLittle();
        }

        num_words = (sz / sizeof(word32));

        switch (keySize) {
        case 16:
            ret =  HW_SCE_AES_128CbcDecrypt((const uint32_t *) aes->key,
                                            (const uint32_t *) aes->reg,
                                            (const uint32_t)   num_words,
                                            (const uint32_t *) in,
                                            (uint32_t *) out,
                                            (uint32_t *) aes->reg);
            break;
        case 32:
            ret =  HW_SCE_AES_256CbcDecrypt((const uint32_t *) aes->key,
                                            (const uint32_t *) aes->reg,
                                            (const uint32_t)   num_words,
                                            (const uint32_t *) in,
                                            (uint32_t *) out,
                                            (uint32_t *) aes->reg);
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
        }
    }
    wolfSSL_CryptHwMutexUnLock();

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG)
        ret = WC_HW_E;

    return ret;
}

int wc_Renesas_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 keySize = 0;
    uint32_t num_words = 0;
    int ret = 0;

    /* Only accept input with size that is a multiple AES_BLOCK_SIZE */
    if (sz % AES_BLOCK_SIZE != 0) {
        ret = BAD_FUNC_ARG;
    }

    if (aes == NULL || out == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret != BAD_FUNC_ARG) {
        wc_AesGetKeySize(aes, &keySize);
    }

    if (ret != BAD_FUNC_ARG && wolfSSL_CryptHwMutexLock() == 0 && sz)
    {
        /* Format AES Key for Little Endian HW */
        if (keySize == 16 || keySize == 32) {
            HW_SCE_EndianSetLittle();
        }

        num_words = (sz / sizeof(word32));

        switch (keySize) {
        case 16:
            ret = HW_SCE_AES_128EcbEncrypt((const uint32_t*)  aes->key,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*) out);
            break;
        case 32:
            ret = HW_SCE_AES_256EcbEncrypt((const uint32_t*)  aes->key,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*) out);
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
        }
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG)
        ret = WC_HW_E;

    return ret;
}

int wc_Renesas_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 keySize = 0;
    uint32_t num_words = 0;
    int ret = 0;

    /* Only accept input with size that is a multiple AES_BLOCK_SIZE */
    if (sz % AES_BLOCK_SIZE != 0) {
        ret = BAD_FUNC_ARG;
    }

    if (aes == NULL || out == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret != BAD_FUNC_ARG) {
        wc_AesGetKeySize(aes, &keySize);
    }

    if (ret != BAD_FUNC_ARG && wolfSSL_CryptHwMutexLock() == 0 && sz)
    {
        /* Format AES Key for Little Endian HW */
        if (keySize == 16 || keySize == 32) {
            HW_SCE_EndianSetLittle();
        }

        num_words = (sz / sizeof(word32));

        switch (keySize) {
        case 16:
            ret = HW_SCE_AES_128EcbDecrypt((const uint32_t*)  aes->key,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*) out);
            break;
        case 32:
            ret = HW_SCE_AES_256EcbDecrypt((const uint32_t*)  aes->key,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*) out);
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
        }
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG)
        ret = WC_HW_E;

    return ret;
}

int wc_Renesas_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
    const byte aes_blk_words = AES_BLOCK_SIZE / sizeof(word32);
    word32 keySize = 0;
    int ret = WOLFSSL_SUCCESS;
    const byte* tmp;
    uint32_t* outTmp;
    byte inTmp[16] = {0};

    if (aes == NULL || out == NULL || in == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Format AES Key for Little Endian HW */
    HW_SCE_EndianSetLittle();
    wc_AesGetKeySize(aes, &keySize);
    if (!(keySize == 16 || keySize == 32)) {
        ret = BAD_FUNC_ARG;
    }

    /* Use remaining AES stream from previous non-AES_BLOCK_SIZE operation */
    tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;
    while (aes->left && sz && ret != BAD_FUNC_ARG) {
       *(out++) = *(in++) ^ *(tmp++);
       aes->left--;
       sz--;
    }

    while (sz) {
        tmp = in;
        outTmp = (word32*) out;

        if (sz < AES_BLOCK_SIZE) {
            /* Copy remaining bytes into AES_BLOCK_SIZE buffer */
            XMEMCPY(inTmp, in, sz);
            tmp = inTmp;
            /* Set output to aes->tmp for future stream re-use */
            outTmp = aes->tmp;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret != 0) {
            break;
        }

        if (keySize == 16) {
            ret = HW_SCE_AES_128CtrEncrypt((const uint32_t*) aes->key,
                                           (const uint32_t*) aes->reg,
                                           (const uint32_t)  aes_blk_words,
                                           (const uint32_t*) tmp,
                                           (uint32_t*) outTmp,
                                           (uint32_t*) aes->reg);
        } else if (keySize == 32) {
            ret = HW_SCE_AES_256CtrEncrypt((const uint32_t*) aes->key,
                                           (const uint32_t*) aes->reg,
                                           (const uint32_t)  aes_blk_words,
                                           (const uint32_t*) tmp,
                                           (uint32_t*) outTmp,
                                           (uint32_t*) aes->reg);
        } else {
            ret = BAD_FUNC_ARG;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret != FSP_SUCCESS)
            break;

        if (sz < AES_BLOCK_SIZE) {
            /* Finished remaining bytes.
             * Bookkeeping for future stream re-use.
             */
            XMEMCPY(out, aes->tmp, sz);
            aes->left = AES_BLOCK_SIZE - sz;
            break;
        } else {
            out += AES_BLOCK_SIZE;
            in  += AES_BLOCK_SIZE;
            sz  -= AES_BLOCK_SIZE;
            aes->left = 0;
        }
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG)
        ret = WC_HW_E;

    return ret;
}
