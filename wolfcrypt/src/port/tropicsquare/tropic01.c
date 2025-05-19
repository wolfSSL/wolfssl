/* tropic01.c
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
 *
*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>

#include <wolfssl/wolfcrypt/port/tropicsquare/tropic01.h>

/*
 * TROPIC01 hardware RNG implementation
 */
static int Tropic01_GetRandom(byte* out, word32 sz, Tropic01CryptoDevCtx* ctx)
{
    int ret = 0;
    // Default factory pairing keys
    byte pkey_index_0 =  PAIRING_KEY_SLOT_INDEX_0;
    // Engineering samples 01 keys:
    byte sh0priv[] = {0xd0,0x99,0x92,0xb1,0xf1,0x7a,0xbc,0x4d,0xb9,0x37,0x17,0x68,0xa2,0x7d,0xa0,0x5b,0x18,0xfa,0xb8,0x56,0x13,0xa7,0x84,0x2c,0xa6,0x4c,0x79,0x10,0xf2,0x2e,0x71,0x6b};
    byte sh0pub[]  = {0xe7,0xf7,0x35,0xba,0x19,0xa3,0x3f,0xd6,0x73,0x23,0xab,0x37,0x26,0x2d,0xe5,0x36,0x08,0xca,0x57,0x85,0x76,0x53,0x43,0x52,0xe1,0x8f,0x64,0xe6,0x13,0xd3,0x8d,0x54};
    lt_handle_t h;
    lt_ret_t rett;
    WOLFSSL_MSG_EX("TROPIC01: GetRandom: Requesting %u bytes", sz);
    
    if (out == NULL || ctx == NULL || !ctx->initialized || sz == 0)
        return BAD_FUNC_ARG;
    
    /* Call TROPIC01 TRNG API to get random data */
    
    
    rett = lt_init(&h);
    if(rett != LT_OK) {
        //printf("Error lt_init(): %s", lt_ret_verbose(ret));
        return rett;
    }
    ret = verify_chip_and_start_secure_session(&h, sh0priv, sh0pub, pkey_index_0);
    if(ret != LT_OK) {
        //printf("Error sec channel: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return ret;
    }
    ret = lt_random_get(&h, out, sz);
    if(ret != LT_OK) {
        //printf("Error l3 cmd: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return ret;
    }
    ret = lt_deinit(&h);
    if(ret != LT_OK) {
        //printf("Error lt_deinit(): %s", lt_ret_verbose(ret));
        return ret;
    }
    WOLFSSL_MSG_EX("TROPIC01: GetRandom: Completed with ret=%d", ret);
    return ret;
}

/*
 * Retrive the AES key from the secure memory of TROPIC01 
 */

static int Tropic01_GetKey(Aes* aes, int keySlot, word32 keySz, Tropic01CryptoDevCtx* ctx)
{
    int ret;
    // Default factory pairing keys
    byte pkey_index_0 =  PAIRING_KEY_SLOT_INDEX_0;
    // Engineering samples 01 keys:
    byte sh0priv[] = {0xd0,0x99,0x92,0xb1,0xf1,0x7a,0xbc,0x4d,0xb9,0x37,0x17,0x68,0xa2,0x7d,0xa0,0x5b,0x18,0xfa,0xb8,0x56,0x13,0xa7,0x84,0x2c,0xa6,0x4c,0x79,0x10,0xf2,0x2e,0x71,0x6b};
    byte sh0pub[]  = {0xe7,0xf7,0x35,0xba,0x19,0xa3,0x3f,0xd6,0x73,0x23,0xab,0x37,0x26,0x2d,0xe5,0x36,0x08,0xca,0x57,0x85,0x76,0x53,0x43,0x52,0xe1,0x8f,0x64,0xe6,0x13,0xd3,0x8d,0x54};
    lt_handle_t h;
    lt_ret_t rett;
    WOLFSSL_MSG_EX("TROPIC01: GetKey: Retrieving key from slot %d", keySlot);
    
    if (aes == NULL || ctx == NULL || !ctx->initialized || keySlot < 0 || keySlot >= 511)
        return BAD_FUNC_ARG;
    
    /* Check key size */
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Unsupported key size %u", keySz);
        return BAD_FUNC_ARG;
    }
    
    /* Retrieve key from TROPIC01 */
    rett = lt_init(&h);
    if(rett != LT_OK) {
        //printf("Error lt_init(): %s", lt_ret_verbose(ret));
        return rett;
    }
    ret = verify_chip_and_start_secure_session(&h, sh0priv, sh0pub, pkey_index_0);
    if(ret != LT_OK) {
        //printf("Error sec channel: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return ret;
    }
    ret = lt_r_mem_data_read(&h, keySlot, (byte*)aes->key, keySz);
    if(ret != LT_OK) {
        //printf("Error l3 cmd: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return 1;
    }
    ret = lt_deinit(&h);
    if(ret != LT_OK) {
        //printf("Error lt_deinit(): %s", lt_ret_verbose(ret));
        return ret;
    }
    
    if (ret != 0) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to retrieve key, ret=%d", ret);
        return ret;
    }
    
    WOLFSSL_MSG_EX("TROPIC01: GetKey: Key retrieved successfully");
    return 0;
}

/**
 * Find an available key slot in the TROPIC01
 */
static int Tropic01_FindFreeKeySlot(Tropic01CryptoDevCtx* ctx)
{
    int i;
    
    WOLFSSL_MSG("TROPIC01: FindFreeKeySlot: Searching for available slot");
    
    for (i = 0; i < 8; i++) {
        if (ctx->keySlotUsage[i] == 0) {
            ctx->keySlotUsage[i] = 1;
            WOLFSSL_MSG_EX("TROPIC01: FindFreeKeySlot: Found slot %d", i);
            return i;
        }
    }
    
    WOLFSSL_MSG("TROPIC01: FindFreeKeySlot: No free slots available");
    return -1;
}

/**
 * Store AES key in TROPIC01 secure memory
 */
static int Tropic01_StoreKey(Aes* aes, const byte* key, word32 keySz, Tropic01CryptoDevCtx* ctx)
{
    int ret;
    int keySlot;
    Tropic01KeyRef* keyRef;
    
    WOLFSSL_MSG_EX("TROPIC01: StoreKey: Storing key of size %u bytes", keySz);
    
    if (aes == NULL || key == NULL || ctx == NULL || !ctx->initialized)
        return BAD_FUNC_ARG;
    
    /* Check key size */
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        WOLFSSL_MSG_EX("TROPIC01: StoreKey: Unsupported key size %u", keySz);
        return BAD_FUNC_ARG;
    }
    
    /* Find available key slot */
    keySlot = Tropic01_FindFreeKeySlot(ctx);
    if (keySlot < 0) {
        WOLFSSL_MSG("TROPIC01: StoreKey: No free key slots available");
        return MEMORY_E;
    }
    
    /* Allocate key reference */
    keyRef = (Tropic01KeyRef*)XMALLOC(sizeof(Tropic01KeyRef), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyRef == NULL) {
        ctx->keySlotUsage[keySlot] = 0;
        return MEMORY_E;
    }
    
    /* Store key in TROPIC01 */
    /* Example TROPIC01_StoreKey call */
    ret = 0; /* Replace with actual implementation */
    
    if (ret != 0) {
        WOLFSSL_MSG_EX("TROPIC01: StoreKey: Failed to store key in slot %d, ret=%d", keySlot, ret);
        XFREE(keyRef, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx->keySlotUsage[keySlot] = 0;
        return ret;
    }
    
    /* Initialize key reference */
    keyRef->keySlot = keySlot;
    keyRef->keySize = keySz;
    keyRef->keyType = 0;
    keyRef->isValid = 1;
    
    /* Store reference in AES structure */
    //aes->devKey = keySlot;
    //aes->devCtx = keyRef;
    
    WOLFSSL_MSG_EX("TROPIC01: StoreKey: Key stored successfully in slot %d", keySlot);
    return 0;
}

/**
 * Crypto Callback function for TROPIC01
 */
int Tropic01_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;
    Tropic01CryptoDevCtx* tropicCtx = (Tropic01CryptoDevCtx*)ctx;

    
    if (info == NULL || tropicCtx == NULL || !tropicCtx->initialized || devId == -2)
        return BAD_FUNC_ARG;

    switch (info->algo_type) {
        case WC_ALGO_TYPE_RNG:
            WOLFSSL_MSG_EX("TROPIC01: CryptoCB: RNG generation request (%u bytes)", info->rng.sz);
            ret = Tropic01_GetRandom(info->rng.out, info->rng.sz, tropicCtx);
            break;
        case WC_ALGO_TYPE_SEED:
            WOLFSSL_MSG_EX("TROPIC01: CryptoCB: SEED generation request (%u bytes)", info->seed.sz);
            ret = Tropic01_GetRandom(info->seed.seed, info->seed.sz, tropicCtx);
            break;    
        case WC_ALGO_TYPE_CIPHER:
            WOLFSSL_MSG_EX("TROPIC01: CryptoCB: AES request (%u bytes)", info->aes_setkey.keySz);
            ret = Tropic01_StoreKey(NULL, NULL, 32, tropicCtx);
            //ret = Tropic01_GetKey(NULL, NULL, TROPIC01_AES_MAX_KEY_SIZE, tropicCtx);
#if !defined(NO_AES) || !defined(NO_DES3)
    #ifdef HAVE_AESGCM
            if (info->cipher.type == WC_CIPHER_AES_GCM) {
                if (info->cipher.enc) {
                    /* set devId to invalid, so software is used */
                    info->cipher.aesgcm_enc.aes->devId = INVALID_DEVID;
                    ret = Tropic01_GetKey(info->cipher.aesgcm_enc.aes, TROPIC01_AES_KEY_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE, tropicCtx);
                    if (ret != 0) {
                        WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-GCM encryption, ret=%d", ret);
                        return ret;
                    }
                    ret = wc_AesGcmEncrypt(
                        info->cipher.aesgcm_enc.aes,
                        info->cipher.aesgcm_enc.out,
                        info->cipher.aesgcm_enc.in,
                        info->cipher.aesgcm_enc.sz,
                        info->cipher.aesgcm_enc.iv,
                        info->cipher.aesgcm_enc.ivSz,
                        info->cipher.aesgcm_enc.authTag,
                        info->cipher.aesgcm_enc.authTagSz,
                        info->cipher.aesgcm_enc.authIn,
                        info->cipher.aesgcm_enc.authInSz);

                    /* reset devId */
                    info->cipher.aesgcm_enc.aes->devId = devId;
                }
                else {
                    /* set devId to invalid, so software is used */
                    info->cipher.aesgcm_dec.aes->devId = INVALID_DEVID;
                    ret = Tropic01_GetKey(info->cipher.aesgcm_dec.aes, TROPIC01_AES_KEY_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE, tropicCtx);
                    if (ret != 0) {
                        WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-GCM decryption, ret=%d", ret);
                        return ret;
                    }
                    ret = wc_AesGcmDecrypt(
                        info->cipher.aesgcm_dec.aes,
                        info->cipher.aesgcm_dec.out,
                        info->cipher.aesgcm_dec.in,
                        info->cipher.aesgcm_dec.sz,
                        info->cipher.aesgcm_dec.iv,
                        info->cipher.aesgcm_dec.ivSz,
                        info->cipher.aesgcm_dec.authTag,
                        info->cipher.aesgcm_dec.authTagSz,
                        info->cipher.aesgcm_dec.authIn,
                        info->cipher.aesgcm_dec.authInSz);

                    /* reset devId */
                    info->cipher.aesgcm_dec.aes->devId = devId;
                }
            }
#endif /* HAVE_AESGCM */
    #ifdef HAVE_AES_CBC
        if (info->cipher.type == WC_CIPHER_AES_CBC) {
            if (info->cipher.enc) {
                /* set devId to invalid, so software is used */
                info->cipher.aescbc.aes->devId = INVALID_DEVID;
                ret = Tropic01_GetKey(info->cipher.aescbc.aes, TROPIC01_AES_KEY_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE, tropicCtx);
                if (ret != 0) {
                    WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-CBC encryption, ret=%d", ret);
                    return ret;
                }
                ret = wc_AesCbcEncrypt(
                    info->cipher.aescbc.aes,
                    info->cipher.aescbc.out,
                    info->cipher.aescbc.in,
                    info->cipher.aescbc.sz);

                /* reset devId */
                info->cipher.aescbc.aes->devId = devId;
            }
            else {
                /* set devId to invalid, so software is used */
                info->cipher.aescbc.aes->devId = INVALID_DEVID;
                ret = Tropic01_GetKey(info->cipher.aescbc.aes, TROPIC01_AES_KEY_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE, tropicCtx);
                if (ret != 0) {
                    WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-CBC decryption, ret=%d", ret);
                    return ret;
                }      
                ret = wc_AesCbcDecrypt(
                    info->cipher.aescbc.aes,
                    info->cipher.aescbc.out,
                    info->cipher.aescbc.in,
                    info->cipher.aescbc.sz);

                /* reset devId */
                info->cipher.aescbc.aes->devId = devId;
            }
        }
    #endif /* HAVE_AES_CBC */
#endif /* !NO_AES || !NO_DES3 */        
            break;
            
        default:
            WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Unsupported algorithm type %d", info->algo_type);
            break;
    }

    return ret;
}

int Tropic01_Init(Tropic01CryptoDevCtx* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->initialized = 1;
    XMEMSET(ctx->keySlotUsage, 0, sizeof(ctx->keySlotUsage));
    
    return 0;
}
