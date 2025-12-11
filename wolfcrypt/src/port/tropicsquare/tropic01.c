/* tropic01.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_TROPIC01

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>

#include <wolfssl/wolfcrypt/port/tropicsquare/tropic01.h>

static Tropic01CryptoDevCtx g_ctx = {0};
static lt_handle_t g_h;

/* Pairing keys for TROPIC01 (use Tropic01_SetPairingKeys() to set them)*/
static byte pk_index =  PAIRING_KEY_SLOT_INDEX_0;
static byte sh0priv[32] = {0};
static byte sh0pub[32]  = {0};

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
    if (ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to retrieve key, ret=%d", ret);
        return WC_HW_E;
    }

    WOLFSSL_MSG_EX("TROPIC01: GetRandom: Completed with ret=%d", ret);
    return 0;
}

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_MAKE_KEY)
/*
 * TROPIC01 ECC keys generation implementation
 */
static int Tropic01_GenerateKeyED25519(byte* pubkey, int keySlot, word32 sz)
{
    lt_ret_t ret = 0;

    WOLFSSL_MSG_EX("TROPIC01: GenerateKeyED25519: Requesting %u bytes", sz);

    if (pubkey == NULL || sz != 32)
        return BAD_FUNC_ARG;

    ret = lt_ecc_key_erase(&g_h, keySlot);
    if (ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to erase key, ret=%d", ret);
        return WC_HW_E;
    }

    ret = lt_ecc_key_generate(&g_h, keySlot, CURVE_ED25519);
    if (ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to generate key, ret=%d", ret);
        return WC_HW_E;
    }
    lt_ecc_curve_type_t curve = CURVE_ED25519;
    ecc_key_origin_t origin = CURVE_GENERATED;
    ret = lt_ecc_key_read(&g_h, keySlot, pubkey, sz, &curve, &origin);
    if (ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: GetKey: Failed to read pub key, ret=%d", ret);
        return WC_HW_E;
    }

    WOLFSSL_MSG_EX("TROPIC01: GenerateKeyED25519: Completed with ret=%d", ret);

    return 0;
}
#endif

/*
 * Retrieve the AES key from the secure R memory of TROPIC01
 */

static int Tropic01_GetKeyAES(byte* aesKey, int keySlot, word32 keySz)
{

    lt_ret_t rett;
    WOLFSSL_MSG_EX(
        "TROPIC01: Get AES Key: Retrieving key from slot %d",
        keySlot
    );

    if (aesKey == NULL || keySlot < 0 || keySlot >= 511)
        return BAD_FUNC_ARG;


    /* Check key size */
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        WOLFSSL_MSG_EX(
            "TROPIC01: Get AES Key: Unsupported key size %u",
            keySz
        );
        return BAD_FUNC_ARG;
    }

    /* Retrieve key from TROPIC01 */

    rett = lt_r_mem_data_read(&g_h, keySlot, aesKey, keySz);
    if (rett != LT_OK) {
        WOLFSSL_MSG_EX(
            "TROPIC01: Get AES Key: Failed to retrieve key, ret=%d",
            rett
        );
        return WC_HW_E;
    }


    WOLFSSL_MSG_EX("TROPIC01: Get AES Key: Key retrieved successfully");
    return 0;
}

/*
 * Retrieve the ECC key from the secure R memory of TROPIC01
 */
static int Tropic01_GetKeyECC(byte* ecckey, int keySlot, word32 keySz)
{

    lt_ret_t rett;
    WOLFSSL_MSG_EX(
        "TROPIC01: Get ECC Key: Retrieving key from slot %d",
        keySlot
    );

    if (ecckey == NULL || keySlot < 0 || keySlot >= 511)
        return BAD_FUNC_ARG;


    /* Check key size */
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        WOLFSSL_MSG_EX(
            "TROPIC01: Get ECC Key: Unsupported key size %u",
            keySz
        );
        return BAD_FUNC_ARG;
    }

    /* Retrieve key from TROPIC01 */

    rett = lt_r_mem_data_read(&g_h, keySlot, (byte*)ecckey, keySz);
    if (rett != LT_OK) {
        WOLFSSL_MSG_EX(
            "TROPIC01: Get ECC Key: Failed to retrieve key, ret=%d",
            rett
        );
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
    byte lt_key[TROPIC01_AES_MAX_KEY_SIZE] = {0};
    byte lt_iv[TROPIC01_AES_MAX_KEY_SIZE] = {0};

    if (info == NULL)
        return BAD_FUNC_ARG;
    (void)ctx;

    if (g_ctx.initialized == 0) {
        WOLFSSL_MSG("TROPIC01: CryptoCB: Device not initialized");
        return CRYPTOCB_UNAVAILABLE;
    }
    switch (info->algo_type) {
        case WC_ALGO_TYPE_RNG:
            WOLFSSL_MSG_EX(
                "TROPIC01: CryptoCB: RNG generation request (%u bytes)",
                info->rng.sz
            );
            ret = Tropic01_GetRandom(info->rng.out, info->rng.sz);
            break;
        case WC_ALGO_TYPE_SEED:
            WOLFSSL_MSG_EX(
                "TROPIC01: CryptoCB: SEED generation request (%u bytes)",
                info->seed.sz
            );
            ret = Tropic01_GetRandom(info->seed.seed, info->seed.sz);
            break;
        case WC_ALGO_TYPE_PK:
#ifdef HAVE_ED25519
    #ifdef HAVE_ED25519_MAKE_KEY
        if (info->pk.type == WC_PK_TYPE_ED25519_KEYGEN) {
            WOLFSSL_MSG("TROPIC01: CryptoCB: ED25519 key generation request");
            ret = Tropic01_GenerateKeyED25519(
                info->pk.ed25519kg.key->p,
                TROPIC01_ED25519_ECC_SLOT_DEFAULT,
                info->pk.ed25519kg.size);
        }
    #endif /* HAVE_ED25519_MAKE_KEY */
    #ifdef HAVE_ED25519_SIGN
        if (info->pk.type == WC_PK_TYPE_ED25519_SIGN) {

            WOLFSSL_MSG("TROPIC01: CryptoCB: ED25519 signing request");
            /* retrieve private key from TROPIC01 secure R memory */
            ret = Tropic01_GetKeyECC(
                info->pk.ed25519sign.key->k,
                TROPIC01_ED25519_PRIV_RMEM_SLOT_DEFAULT,
                TROPIC01_ED25519_PRIV_KEY_SIZE);
            if (ret != 0) {
                WOLFSSL_MSG_EX(
                    "TROPIC01: CryptoCB: Failed to get ED25519 PRIVkey,ret=%d",
                     ret);
                return ret;
            }
            ret = Tropic01_GetKeyECC(
                info->pk.ed25519sign.key->p,
                TROPIC01_ED25519_PUB_RMEM_SLOT_DEFAULT,
                TROPIC01_ED25519_PUB_KEY_SIZE);
            if (ret != 0) {
                WOLFSSL_MSG_EX(
                    "TROPIC01: CryptoCB: Failed to get ED25519 PUBkey,ret=%d",
                     ret);
                return ret;
            }
            /* set devId to invalid, so software is used */
            info->pk.ed25519sign.key->devId = INVALID_DEVID;
            info->pk.ed25519sign.key->privKeySet = 1;
            info->pk.ed25519sign.key->pubKeySet = 1;
            ret = wc_ed25519_sign_msg(
                info->pk.ed25519sign.in, info->pk.ed25519sign.inLen,
                info->pk.ed25519sign.out, info->pk.ed25519sign.outLen,
                info->pk.ed25519sign.key);

            /* reset devId */
            info->pk.ed25519sign.key->devId = devId;
        }
    #endif /* HAVE_ED25519_SIGN */
    #ifdef HAVE_ED25519_VERIFY
        if (info->pk.type == WC_PK_TYPE_ED25519_VERIFY) {
            WOLFSSL_MSG("TROPIC01: CryptoCB: ED25519 verification request");
            /* retrieve public key from TROPIC01 secure R memory */
            ret = Tropic01_GetKeyECC(
                info->pk.ed25519verify.key->p,
                TROPIC01_ED25519_PUB_RMEM_SLOT_DEFAULT,
                TROPIC01_ED25519_PUB_KEY_SIZE);
            if (ret != 0) {
                WOLFSSL_MSG_EX(
                    "TROPIC01: CryptoCB: Failed to get ED25519 key, ret=%d",
                    ret);
                return ret;
            }

            /* set devId to invalid, so software is used */
            info->pk.ed25519verify.key->devId = INVALID_DEVID;
            info->pk.ed25519verify.key->pubKeySet = 1;
            ret = wc_ed25519_verify_msg(
                info->pk.ed25519verify.sig, info->pk.ed25519verify.sigLen,
                info->pk.ed25519verify.msg, info->pk.ed25519verify.msgLen,
                info->pk.ed25519verify.res, info->pk.ed25519verify.key);

            /* reset devId */
            info->pk.ed25519verify.key->devId = devId;
        }
    #endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519 */
            break;
        case WC_ALGO_TYPE_CIPHER:
            WOLFSSL_MSG("TROPIC01: CryptoCB: AES request ");

#if !defined(NO_AES)
    #ifdef HAVE_AESGCM
            if (info->cipher.type == WC_CIPHER_AES_GCM) {
                ret = Tropic01_GetKeyAES(
                        lt_key,
                        TROPIC01_AES_KEY_RMEM_SLOT,
                        TROPIC01_AES_MAX_KEY_SIZE);
                if (ret != 0) {
                    WOLFSSL_MSG_EX(
                            "TROPIC01: CryptoCB: Failed to get AES key,ret=%d",
                             ret);
                    return ret;
                }
                ret = Tropic01_GetKeyAES(
                        lt_iv,
                        TROPIC01_AES_IV_RMEM_SLOT,
                        TROPIC01_AES_MAX_KEY_SIZE);
                if (ret != 0) {
                    WOLFSSL_MSG_EX(
                            "TROPIC01: CryptoCB: Failed to get AES IV, ret=%d",
                             ret);
                    return ret;
                }
                if (info->cipher.enc) {
                    ret = wc_AesSetKey(info->cipher.aesgcm_enc.aes, lt_key,
                                WC_AES_BLOCK_SIZE, lt_iv, AES_ENCRYPTION);
                     if (ret != 0) {
                        WOLFSSL_MSG_EX(
                            "TROPIC01: CryptoCB: Failed to set AES key, ret=%d",
                            ret);
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

                    ret = wc_AesSetKey(info->cipher.aesgcm_dec.aes, lt_key,
                                WC_AES_BLOCK_SIZE, lt_iv, AES_DECRYPTION);
                    if (ret != 0) {
                        WOLFSSL_MSG_EX(
                            "TROPIC01: CryptoCB: Failed to set AES key, ret=%d",
                            ret);
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
            ret = Tropic01_GetKeyAES(
                        lt_key,
                        TROPIC01_AES_KEY_RMEM_SLOT,
                        TROPIC01_AES_MAX_KEY_SIZE);
            if (ret != 0) {
                WOLFSSL_MSG_EX(
                    "TROPIC01: CryptoCB: Failed to get AES key,ret=%d", ret);
                return ret;
            }
            ret = Tropic01_GetKeyAES(
                        lt_iv,
                        TROPIC01_AES_IV_RMEM_SLOT,
                        TROPIC01_AES_MAX_KEY_SIZE);
            if (ret != 0) {
                WOLFSSL_MSG_EX(
                    "TROPIC01: CryptoCB: Failed to get AES IV, ret=%d", ret);
                    return ret;
                }
            if (info->cipher.enc) {
                ret = wc_AesSetKey(info->cipher.aescbc.aes, lt_key,
                                WC_AES_BLOCK_SIZE, lt_iv, AES_ENCRYPTION);
                if (ret != 0) {
                    WOLFSSL_MSG_EX(
                        "TROPIC01: CryptoCB: Failed to set AES key, ret=%d",
                        ret);
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

                ret = wc_AesSetKey(info->cipher.aescbc.aes, lt_key,
                                WC_AES_BLOCK_SIZE, lt_iv, AES_DECRYPTION);
                if (ret != 0) {
                    WOLFSSL_MSG_EX(
                        "TROPIC01: CryptoCB: Failed to set AES key, ret=%d",
                        ret);
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
        }
    #endif /* HAVE_AES_CBC */
#endif /* !NO_AES */
            break;

        default:

            break;
    }

    return ret;
}
/* Set TROPIC01 pairing keys */
int Tropic01_SetPairingKeys(int kIndex, const byte* kPub, const byte* kPriv)
{
    int i;

    if (kPub == NULL || kPriv == NULL || kIndex < 0 || kIndex > 3) {
        WOLFSSL_MSG_EX("TROPIC01: SetPairingKeys: Invalid arguments");
        return BAD_FUNC_ARG;
    }

    WOLFSSL_MSG_EX(
        "TROPIC01: SetPairingKeys: Setting pairing key in slot %d",
        kIndex);

    for (i = 0; i < TROPIC01_PAIRING_KEY_SIZE; i++) {

        sh0priv[i] = kPriv[i];
        sh0pub[i] = kPub[i];
    }

    WOLFSSL_MSG("TROPIC01: SetPairingKeys: Pairing key set successfully");
    WOLFSSL_MSG_EX(
        "TROPIC01: sh0priv: %02X %02X %02X %02X ...",
        kPriv[0], kPriv[1], kPriv[2], kPriv[3]);
    WOLFSSL_MSG_EX(
        "TROPIC01: sh0pub: %02X %02X %02X %02X ...",
        kPub[0], kPub[1], kPub[2], kPub[3]);
    return 0;
}

int Tropic01_Init(void)
{
    lt_ret_t ret;

    g_ctx.initialized = 0;
    ret = lt_init(&g_h);
    if (ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: lt_init failed with a code %d", ret);
        return WC_HW_E;
    }
    ret = verify_chip_and_start_secure_session(&g_h, sh0priv, sh0pub, pk_index);
    if (ret != LT_OK) {
        WOLFSSL_MSG_EX("TROPIC01: secure session failed with a code %d", ret);
        lt_deinit(&g_h);
        return WC_HW_E;
    }
    g_ctx.initialized = 1;
    WOLFSSL_MSG("TROPIC01: Crypto device initialized successfully");

    return 0;
}

int Tropic01_Deinit(void)
{
    lt_ret_t ret;

    if (g_ctx.initialized) {
        ret = lt_deinit(&g_h);
        if (ret != LT_OK) {
            WOLFSSL_MSG_EX("TROPIC01: lt_deinit failed with a code %d", ret);
            return WC_HW_E;
        }
        g_ctx.initialized = 0;
        WOLFSSL_MSG("TROPIC01: Crypto device deinitialized successfully");
    }

    return 0;
}

#endif /* WOLFSSL_TROPIC01 */
