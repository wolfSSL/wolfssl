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

static Tropic01CryptoDevCtx g_ctx = {0};
static lt_handle_t g_h;

// Default factory pairing keys
byte pkey_index_0 =  PAIRING_KEY_SLOT_INDEX_0;
    // Engineering samples 01 keys:
byte sh0priv[] = {0xd0,0x99,0x92,0xb1,0xf1,0x7a,0xbc,0x4d,0xb9,0x37,0x17,0x68,0xa2,0x7d,0xa0,0x5b,0x18,0xfa,0xb8,0x56,0x13,0xa7,0x84,0x2c,0xa6,0x4c,0x79,0x10,0xf2,0x2e,0x71,0x6b};
byte sh0pub[]  = {0xe7,0xf7,0x35,0xba,0x19,0xa3,0x3f,0xd6,0x73,0x23,0xab,0x37,0x26,0x2d,0xe5,0x36,0x08,0xca,0x57,0x85,0x76,0x53,0x43,0x52,0xe1,0x8f,0x64,0xe6,0x13,0xd3,0x8d,0x54};
/*
 * TROPIC01 hardware RNG implementation
 */
static int Tropic01_GetRandom(byte* out, word32 sz)
{
    int ret = 0;
    
    
    WOLFSSL_MSG_EX("TROPIC01: GetRandom: Requesting %u bytes", sz);
    
    if (out == NULL || sz == 0)
        return BAD_FUNC_ARG;
    
    
    /* Call TROPIC01 TRNG API to get random data */
    
    
    ret = lt_random_get(&g_h, out, sz);
    if(ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to retrieve key, ret=%d", ret);
        Tropic01_Deinit();
        return WC_HW_E;
    }
    
    WOLFSSL_MSG_EX("TROPIC01: GetRandom: Completed with ret=%d", ret);
    /*
    for (word32 i = 0; i < sz; i++) {
        WOLFSSL_MSG_EX("TROPIC01: GetRandom: out[%d] = 0x%02x", i, out[i]);
    }
    */
    return 0;
}

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_MAKE_KEY)

static int Tropic01_GenerateKeyED25519(byte* pubkey, int keySlot, word32 sz)
{
    lt_ret_t ret = 0;
    
    WOLFSSL_MSG_EX("TROPIC01: GenerateKeyED25519: Requesting %u bytes", sz);
    
    if (pubkey == NULL || sz != 32)
        return BAD_FUNC_ARG;
    
    ret = lt_ecc_key_erase(&g_h, keySlot);
    if(ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to erase key, ret=%d", ret);
        Tropic01_Deinit();
        return WC_HW_E;
    }
    
    ret = lt_ecc_key_generate(&g_h, keySlot, CURVE_ED25519);
    if(ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to generate key, ret=%d", ret);
        Tropic01_Deinit();
        return WC_HW_E;
    }
    lt_ecc_curve_type_t curve = CURVE_ED25519;
    ecc_key_origin_t origin = CURVE_GENERATED;
    ret = lt_ecc_key_read(&g_h, keySlot, pubkey, sz, &curve, &origin);
    if(ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to read pub key, ret=%d", ret);
        Tropic01_Deinit();
        return WC_HW_E;
    }
    
    WOLFSSL_MSG_EX("TROPIC01: GenerateKeyED25519: Completed with ret=%d", ret);
    
    return 0;
}
#endif

/*
 * Retrive the AES key from the secure R memory of TROPIC01 
 */

static int Tropic01_GetKeyAES(Aes* aes, int keySlot, word32 keySz)
{

    lt_ret_t rett;
    WOLFSSL_MSG_EX("TROPIC01: Get AES Key: Retrieving key from slot %d", keySlot);
    
    if (aes == NULL || keySlot < 0 || keySlot >= 511)
        return BAD_FUNC_ARG;
  
    
    /* Check key size */
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        WOLFSSL_MSG_EX("TROPIC01: Get AES Key: Unsupported key size %u", keySz);
        return BAD_FUNC_ARG;
    }
    
    /* Retrieve key from TROPIC01 */
    
    rett = lt_r_mem_data_read(&g_h, keySlot, (byte*)aes->key, keySz);
    if(rett != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: Get AES Key: Failed to retrieve key, ret=%d", rett);
        Tropic01_Deinit();
        return WC_HW_E;
    }
    
    
    WOLFSSL_MSG_EX("TROPIC01: Get AES Key: Key retrieved successfully");
    return 0;
}

static int Tropic01_GetKeyECC(byte* ecckey, int keySlot, word32 keySz)
{

    lt_ret_t rett;
    WOLFSSL_MSG_EX("TROPIC01: Get ECC Key: Retrieving key from slot %d", keySlot);
    
    if (ecckey == NULL || keySlot < 0 || keySlot >= 511)
        return BAD_FUNC_ARG;
  
    
    /* Check key size */
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        WOLFSSL_MSG_EX("TROPIC01: Get ECC Key: Unsupported key size %u", keySz);
        return BAD_FUNC_ARG;
    }
    
    /* Retrieve key from TROPIC01 */
    
    rett = lt_r_mem_data_read(&g_h, keySlot, (byte*)ecckey, keySz);
    if(rett != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: Get ECC Key: Failed to retrieve key, ret=%d", rett);
        Tropic01_Deinit();
        return WC_HW_E;
    }
    
    
    WOLFSSL_MSG_EX("TROPIC01: Get ECC Key: Key retrieved successfully");
    return 0;
}

/**
 * Crypto Callback function for TROPIC01
 */
int Tropic01_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    
    if (info == NULL)
        return BAD_FUNC_ARG;
    (void)ctx;
   // (void)devId;

    if (g_ctx.initialized == 0) {
        WOLFSSL_MSG("TROPIC01: CryptoCB: Device not initialized");
        return CRYPTOCB_UNAVAILABLE;
    }
    switch (info->algo_type) {
        case WC_ALGO_TYPE_RNG:
            WOLFSSL_MSG_EX("TROPIC01: CryptoCB: RNG generation request (%u bytes)", info->rng.sz);
            ret = Tropic01_GetRandom(info->rng.out, info->rng.sz);
            break;
        case WC_ALGO_TYPE_SEED:
            WOLFSSL_MSG_EX("TROPIC01: CryptoCB: SEED generation request (%u bytes)", info->seed.sz);
            ret = Tropic01_GetRandom(info->seed.seed, info->seed.sz);
            break;    
        case WC_ALGO_TYPE_PK:
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_MAKE_KEY)
        if (info->pk.type == WC_PK_TYPE_ED25519_KEYGEN) {
            WOLFSSL_MSG("TROPIC01: CryptoCB: ED25519 key generation request");
            ret = Tropic01_GenerateKeyED25519(info->pk.ed25519kg.key->p, TROPIC01_ED25519_ECC_SLOT_DEFAULT, info->pk.ed25519kg.size);            
           
        }
        #ifdef HAVE_ED25519_SIGN
        else if (info->pk.type == WC_PK_TYPE_ED25519_SIGN) {

            WOLFSSL_MSG("TROPIC01: CryptoCB: ED25519 signing request");
            // retrieve private key from TROPIC01 secure R memory
            ret = Tropic01_GetKeyECC(info->pk.ed25519sign.key->k, TROPIC01_ED25519_PRIV_RMEM_SLOT_DEFAULT, TROPIC01_ED25519_PRIV_KEY_SIZE);
            if (ret != 0) {
                WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get ECC key for ED25519 sign, ret=%d", ret);
                return ret;
            }
            /* set devId to invalid, so software is used */
            info->pk.ed25519sign.key->devId = INVALID_DEVID;
            info->pk.ed25519sign.key->pubKeySet = 1;

            ret = wc_ed25519_sign_msg_ex(
                info->pk.ed25519sign.in, info->pk.ed25519sign.inLen,
                info->pk.ed25519sign.out, info->pk.ed25519sign.outLen,
                info->pk.ed25519sign.key, info->pk.ed25519sign.type,
                info->pk.ed25519sign.context, info->pk.ed25519sign.contextLen);

            /* reset devId */
            info->pk.ed25519sign.key->devId = devId;
        }
        #endif
        #ifdef HAVE_ED25519_VERIFY
        else if (info->pk.type == WC_PK_TYPE_ED25519_VERIFY) {
            WOLFSSL_MSG("TROPIC01: CryptoCB: ED25519 verification request");
            // retrieve public key from TROPIC01 secure R memory
            ret = Tropic01_GetKeyECC(info->pk.ed25519sign.key->p, TROPIC01_ED25519_PUB_RMEM_SLOT_DEFAULT, TROPIC01_ED25519_PUB_KEY_SIZE);
            if (ret != 0) {
                WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get ECC key for ED25519 verification, ret=%d", ret);
                return ret;
            }

            /* set devId to invalid, so software is used */
            info->pk.ed25519verify.key->devId = INVALID_DEVID;

            ret = wc_ed25519_verify_msg_ex(
                info->pk.ed25519verify.sig, info->pk.ed25519verify.sigLen,
                info->pk.ed25519verify.msg, info->pk.ed25519verify.msgLen,
                info->pk.ed25519verify.res, info->pk.ed25519verify.key,
                info->pk.ed25519verify.type, NULL, 0);

            /* reset devId */
            info->pk.ed25519verify.key->devId = devId;
        }
        #endif // HAVE_ ED25519_VERIFY
#endif /* HAVE_ED25519 */
            break;
        case WC_ALGO_TYPE_CIPHER:
            WOLFSSL_MSG("TROPIC01: CryptoCB: AES request ");
            //ret = Tropic01_StoreKey(NULL, NULL, 32);
            //ret = Tropic01_GetKey(NULL, NULL, TROPIC01_AES_MAX_KEY_SIZE, tropicCtx);
#if !defined(NO_AES) || !defined(NO_DES3)
    #ifdef HAVE_AESGCM
            if (info->cipher.type == WC_CIPHER_AES_GCM) {
                if (info->cipher.enc) {
                    
                    ret = Tropic01_GetKeyAES(info->cipher.aesgcm_enc.aes, TROPIC01_AES_RMEM_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE);
                    if (ret != 0) {
                        WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-GCM encryption, ret=%d", ret);
                        return ret;
                    }
                    /* set devId to invalid, so software is used */
                    info->cipher.aesgcm_enc.aes->devId = INVALID_DEVID;
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
                    
                    ret = Tropic01_GetKeyAES(info->cipher.aesgcm_dec.aes, TROPIC01_AES_RMEM_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE);
                    if (ret != 0) {
                        WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-GCM decryption, ret=%d", ret);
                        return ret;
                    }
                    /* set devId to invalid, so software is used */
                    info->cipher.aesgcm_dec.aes->devId = INVALID_DEVID;
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
                
                ret = Tropic01_GetKeyAES(info->cipher.aescbc.aes, TROPIC01_AES_RMEM_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE);
                if (ret != 0) {
                    WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-CBC encryption, ret=%d", ret);
                    return ret;
                }
                /* set devId to invalid, so software is used */
                info->cipher.aescbc.aes->devId = INVALID_DEVID;
                ret = wc_AesCbcEncrypt(
                    info->cipher.aescbc.aes,
                    info->cipher.aescbc.out,
                    info->cipher.aescbc.in,
                    info->cipher.aescbc.sz);

                /* reset devId */
                info->cipher.aescbc.aes->devId = devId;
            }
            else {
                
                ret = Tropic01_GetKeyAES(info->cipher.aescbc.aes, TROPIC01_AES_RMEM_SLOT_DEFAULT, TROPIC01_AES_MAX_KEY_SIZE);
                if (ret != 0) {
                    WOLFSSL_MSG_EX("TROPIC01: CryptoCB: Failed to get key for AES-CBC decryption, ret=%d", ret);
                    return ret;
                }
                /* set devId to invalid, so software is used */
                info->cipher.aescbc.aes->devId = INVALID_DEVID;      
                ret = wc_AesCbcDecrypt(
                    info->cipher.aescbc.aes,
                    info->cipher.aescbc.out,
                    info->cipher.aescbc.in,
                    info->cipher.aescbc.sz);

                /* reset devId */
                info->cipher.aescbc.aes->devId = devId;
            }
            for (int i = 0; i < info->cipher.aescbc.aes->keylen; i++) {
                WOLFSSL_MSG_EX("TROPIC01: CryptoCB: aes->key[%d] = 0x%02x", i, info->cipher.aescbc.aes->key[i]);
            }    
            for (word32 i = 0; i < info->cipher.aescbc.sz; i++) {
                WOLFSSL_MSG_EX("TROPIC01: CryptoCB: out[%d] = 0x%02x", i, info->cipher.aescbc.out[i]);
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

int Tropic01_Init()
{
    lt_ret_t ret;

    g_ctx.initialized = 0;
    ret = lt_init(&g_h);
    if(ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: lt_init failed with a code %d", ret);
        return WC_HW_E;
    }
    ret = verify_chip_and_start_secure_session(&g_h, sh0priv, sh0pub, pkey_index_0);
    if(ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: secure session failed with a code %d", ret);
        lt_deinit(&g_h);
        return WC_HW_E;
    }
    g_ctx.initialized = 1;
    WOLFSSL_MSG("TROPIC01: Crypto device initialized successfully");
    
    return 0;
}

int Tropic01_Deinit()
{
    lt_ret_t ret;

    if (g_ctx.initialized) {
        ret = lt_deinit(&g_h);
        if(ret != LT_OK) {
            WOLFSSL_MSG_EX("TROPIC01: lt_deinit failed with a code %d", ret);
            return WC_HW_E;
        }
        g_ctx.initialized = 0;
        WOLFSSL_MSG("TROPIC01: Crypto device deinitialized successfully");
    }

    return 0;
}
