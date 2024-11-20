/* renesas_sce_rsa.c
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

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(NO_RSA) && \
     defined(WOLFSSL_RENESAS_TSIP_CRYPTONLY)

#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h>

#ifdef WOLFSSL_RENESAS_TSIP_CRYPTONLY
/* Make RSA key for TSIP and set it to callback ctx
 * Assumes to be called by Crypt Callback
 *
 * size   desired key length, in bits. supports 1024 or 2048 bits
 * ctx    Callback context including pointer to hold generated key
 * return TSIP_SUCCESS(0) on Success, otherwise negative value
 */
int wc_tsip_MakeRsaKey(int size, void* ctx)
{
    e_tsip_err_t     ret;
    TsipUserCtx     *info = (TsipUserCtx*)ctx;

    tsip_rsa1024_key_pair_index_t *tsip_pair1024_key = NULL;
    tsip_rsa2048_key_pair_index_t *tsip_pair2048_key = NULL;

    /* sanity check */
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (size != 1024 && size != 2048) {
        WOLFSSL_MSG("Failed to generate key pair by TSIP");
        return CRYPTOCB_UNAVAILABLE;
    }

    if ((ret = tsip_hw_lock()) == 0) {
        if (size == 1024) {
            tsip_pair1024_key =
            (tsip_rsa1024_key_pair_index_t*)XMALLOC(
                sizeof(tsip_rsa1024_key_pair_index_t), NULL,
                                                DYNAMIC_TYPE_RSA_BUFFER);
            if (tsip_pair1024_key == NULL)
                return MEMORY_E;

            ret = R_TSIP_GenerateRsa1024RandomKeyIndex(tsip_pair1024_key);
        }
        else if (size == 2048) {
            tsip_pair2048_key =
            (tsip_rsa2048_key_pair_index_t*)XMALLOC(
                sizeof(tsip_rsa2048_key_pair_index_t), NULL,
                                                DYNAMIC_TYPE_RSA_BUFFER);
            if (tsip_pair2048_key == NULL)
                return MEMORY_E;

            ret = R_TSIP_GenerateRsa2048RandomKeyIndex(tsip_pair2048_key);
        }

        if (ret == TSIP_SUCCESS) {
            if (size == 1024) {
                XFREE(info->rsa1024pri_keyIdx, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                XFREE(info->rsa1024pub_keyIdx, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                info->rsa1024pri_keyIdx =
                (tsip_rsa1024_private_key_index_t*)XMALLOC(
                    sizeof(tsip_rsa1024_private_key_index_t), NULL,
                                                DYNAMIC_TYPE_RSA_BUFFER);

                if (info->rsa1024pri_keyIdx == NULL) {
                    XFREE(tsip_pair1024_key, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }

                info->rsa1024pub_keyIdx =
                (tsip_rsa1024_public_key_index_t*)XMALLOC(
                    sizeof(tsip_rsa1024_public_key_index_t), NULL,
                                                DYNAMIC_TYPE_RSA_BUFFER);

                if (info->rsa1024pub_keyIdx == NULL) {
                    XFREE(tsip_pair1024_key, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                    XFREE(info->rsa1024pri_keyIdx, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }
                /* copy generated key pair and free malloced key */
                XMEMCPY(info->rsa1024pri_keyIdx,
                                    &tsip_pair1024_key->private,
                                    sizeof(tsip_rsa1024_private_key_index_t));
                XMEMCPY(info->rsa1024pub_keyIdx,
                                    &tsip_pair1024_key->public,
                                    sizeof(tsip_rsa1024_public_key_index_t));
                XFREE(tsip_pair1024_key, NULL, DYNAMIC_TYPE_RSA_BUFFER);

                info->keyflgs_crypt.bits.rsapri1024_key_set = 1;
                info->keyflgs_crypt.bits.rsapub1024_key_set = 1;
                info->wrappedKeyType = TSIP_KEY_TYPE_RSA1024;
            }
            else if (size == 2048) {
                XFREE(info->rsa2048pri_keyIdx, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                XFREE(info->rsa2048pub_keyIdx, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                info->rsa2048pri_keyIdx =
                (tsip_rsa2048_private_key_index_t*)XMALLOC(
                    sizeof(tsip_rsa2048_private_key_index_t), NULL,
                                    DYNAMIC_TYPE_RSA_BUFFER);

                if (info->rsa2048pri_keyIdx == NULL) {
                    XFREE(tsip_pair2048_key, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }

                info->rsa2048pub_keyIdx =
                (tsip_rsa2048_public_key_index_t*)XMALLOC(
                    sizeof(tsip_rsa2048_public_key_index_t), NULL,
                                    DYNAMIC_TYPE_RSA_BUFFER);

                if (info->rsa2048pub_keyIdx == NULL) {
                    XFREE(tsip_pair2048_key, NULL, DYNAMIC_TYPE_RSA_BUFFER);
                    XFREE(info->rsa2048pri_keyIdx, NULL,
                                    DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }

                /* copy generated key pair and free malloced key */
                XMEMCPY(info->rsa2048pri_keyIdx,
                            &tsip_pair2048_key->private,
                            sizeof(tsip_rsa2048_private_key_index_t));
                XMEMCPY(info->rsa2048pub_keyIdx,
                            &tsip_pair2048_key->public,
                            sizeof(tsip_rsa2048_public_key_index_t));
                XFREE(tsip_pair2048_key, NULL, DYNAMIC_TYPE_RSA_BUFFER);

                info->keyflgs_crypt.bits.rsapri2048_key_set = 1;
                info->keyflgs_crypt.bits.rsapub2048_key_set = 1;
                info->wrappedKeyType = TSIP_KEY_TYPE_RSA2048;
            }
        }

        tsip_hw_unlock();
    }


    return 0;
}
/* Generate TSIP key index if needed
 *
 * tuc    struct pointer of TsipUserCtx
 * return FSP_SUCCESS(0) on Success, otherwise CRYPTOCB_UNAVAILABLE
 */
static int tsip_RsakeyImport(TsipUserCtx* tuc)
{
    int ret = 0;

    switch (tuc->wrappedKeyType) {
        case TSIP_KEY_TYPE_RSA1024:
            if (tuc->keyflgs_crypt.bits.rsapub1024_key_set != 1) {
                ret = tsip_ImportPublicKey(tuc, tuc->wrappedKeyType);

                WOLFSSL_MSG("tsip rsa private key 1024 not set");
                if (ret != 0)
                    ret = CRYPTOCB_UNAVAILABLE;

            }
            break;
        case TSIP_KEY_TYPE_RSA2048:
            if (tuc->keyflgs_crypt.bits.rsapub2048_key_set != 1) {
                ret = tsip_ImportPublicKey(tuc, tuc->wrappedKeyType);

                WOLFSSL_MSG("tsip rsa private key 2048 not set");
                if (ret != 0)
                    ret = CRYPTOCB_UNAVAILABLE;
            }
            break;
        default:
            WOLFSSL_MSG("wrapped private key is not supported");
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}

/* Perform rsa encryption/decryption by TSIP
 * Assumes to be called by Crypt Callback
 *
 * info struct pointer of wc_CryptoInfo including necessary info
 * tuc  struct pointer of TsipUserCtx including TSIP key info
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
int wc_tsip_RsaFunction(wc_CryptoInfo* info, TsipUserCtx* tuc)
{
    int ret;
    int keySize;
    int type;
    tsip_rsa_byte_data_t plain, cipher;


    if (info == NULL || tuc == NULL) {
        return BAD_FUNC_ARG;
    }

    if (tsip_RsakeyImport(tuc) == 0) {
        type = info->pk.rsa.type;
        keySize = (int)tuc->wrappedKeyType;

        if ((ret = tsip_hw_lock()) == 0) {
            if (type == RSA_PUBLIC_ENCRYPT || type == RSA_PUBLIC_DECRYPT) {
                plain.pdata = (uint8_t*)info->pk.rsa.in;
                plain.data_length = info->pk.rsa.inLen;
                cipher.pdata = (uint8_t*)info->pk.rsa.out;
                cipher.data_length = *(info->pk.rsa.outLen);

                if (keySize == TSIP_KEY_TYPE_RSA1024) {
                    ret = R_TSIP_RsaesPkcs1024Encrypt(&plain, &cipher,
                            tuc->rsa1024pub_keyIdx);
                }
                else if (keySize == TSIP_KEY_TYPE_RSA2048) {
                    ret = R_TSIP_RsaesPkcs2048Encrypt(&plain, &cipher,
                            tuc->rsa2048pub_keyIdx);
                }
                else {
                    WOLFSSL_MSG("keySize is invalid, neither 128 or 256 bytes, "
                                                          "1024 or 2048 bits.");
                    return BAD_FUNC_ARG;
                }
                if (ret == 0) {
                    *(info->pk.rsa.outLen) = cipher.data_length;
                }
            }
            else if (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT)
            {
                plain.pdata = (uint8_t*)info->pk.rsa.out;
                plain.data_length = *(info->pk.rsa.outLen);
                cipher.pdata = (uint8_t*)info->pk.rsa.in;
                cipher.data_length = info->pk.rsa.inLen;

                if (keySize == TSIP_KEY_TYPE_RSA1024) {
                    ret = R_TSIP_RsaesPkcs1024Decrypt(&cipher, &plain,
                            tuc->rsa1024pri_keyIdx);
                }
                else if (keySize == TSIP_KEY_TYPE_RSA2048) {
                    ret = R_TSIP_RsaesPkcs2048Decrypt(&cipher, &plain,
                            tuc->rsa2048pri_keyIdx);
                }
                else {
                    WOLFSSL_MSG("keySize is invalid, neither 128 or 256 bytes, "
                                                          "1024 or 2048 bits.");
                    return BAD_FUNC_ARG;
                }
                if (ret == 0) {
                    *(info->pk.rsa.outLen) = plain.data_length;
                }
            }
            tsip_hw_unlock();
        }
    }
    return ret;
}
/* Perform Rsa verify by TSIP
 * Assumes to be called by Crypt Callback
 *
 * info struct pointer of wc_CryptoInfo including necessary info
 * tuc  struct pointer of TsipUserCtx including TSIP key info
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */

int wc_tsip_RsaVerifyPkcs(wc_CryptoInfo* info, TsipUserCtx* tuc)
{
    int ret = 0;
    e_tsip_err_t    err = TSIP_SUCCESS;
    tsip_rsa_byte_data_t hashData, sigData;
    uint8_t  tsip_hash_type;

    /* sanity check */
    if (info == NULL || tuc == NULL){
        return BAD_FUNC_ARG;
    }

    if (ret == 0) {
       if (tuc->sign_hash_type == md5_mac)
           tsip_hash_type = R_TSIP_RSA_HASH_MD5;
       else if (tuc->sign_hash_type == sha_mac)
           tsip_hash_type = R_TSIP_RSA_HASH_SHA1;
       else if (tuc->sign_hash_type == sha256_mac)
           tsip_hash_type = R_TSIP_RSA_HASH_SHA256;
       else
           ret = CRYPTOCB_UNAVAILABLE;
    }

    if (tsip_RsakeyImport(tuc) == 0) {
        hashData.pdata = (uint8_t*)info->pk.rsa.out;
        hashData.data_length = *(info->pk.rsa.outLen);
        hashData.data_type =
            tuc->keyflgs_crypt.bits.message_type;/* message 0, hash 1 */

        sigData.pdata = (uint8_t*)info->pk.rsa.in;
        sigData.data_length = info->pk.rsa.inLen;

        if ((ret = tsip_hw_lock()) == 0) {
            switch (tuc->wrappedKeyType) {
                case TSIP_KEY_TYPE_RSA1024:
                    err = R_TSIP_RsassaPkcs1024SignatureVerification(&sigData,
                            &hashData,
                            (tsip_rsa1024_public_key_index_t *)
                            tuc->rsa1024pub_keyIdx,
                            tsip_hash_type);
                    if (err == TSIP_ERR_AUTHENTICATION) {
                        ret = SIG_VERIFY_E;
                    }
                    else if (err == TSIP_SUCCESS) {
                        ret = 0;
                    }
                    else {
                        ret = WC_HW_E;
                    }
                    break;
                case TSIP_KEY_TYPE_RSA2048:
                    err = R_TSIP_RsassaPkcs2048SignatureVerification(&sigData,
                            &hashData,
                            (tsip_rsa2048_public_key_index_t *)
                            tuc->rsa2048pub_keyIdx,
                            tsip_hash_type);
                    if (err == TSIP_ERR_AUTHENTICATION) {
                            ret = SIG_VERIFY_E;
                    }
                    else if (err == TSIP_SUCCESS) {
                        ret = 0;
                    }
                    else {
                        ret = WC_HW_E;
                    }
                    break;
            }
            tsip_hw_unlock();
        }
    }

    return ret;
}
#endif /* WOLFSSL_RENESAS_TSIP_CRYPTONLY */
#endif /* WOLFSSL_RENESAS_TSIP_TLS || \
          WOLFSSL_RENESAS_TSIP_CRYPTONLY */
