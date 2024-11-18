/* renesas-fsp-crypt.h
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
#ifndef __RENESAS_FSP_CRYPT_H__
#define __RENESAS_FSP_CRYPT_H__

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>


#if defined(WOLFSSL_RENESAS_SCEPROTECT)

    #include "r_sce.h"

    #define FSPSM_W_KEYVAR          renesas_sce_wrappedkey
    #define FSPSM_tls_flg_ST        sce_keyflgs_tls
    #define FSPSM_key_flg_ST        sce_keyflgs_crypt
    #define FSPSM_tag_ST            tagUser_SCEPKCbInfo
    #define FSPSM_ST                User_SCEPKCbInfo
    #define FSPSM_ST_PKC            SCE_PKCbInfo

    /* map SCE API to macro */
    #define FSPSM_INSTANCE          sce_instance_ctrl_t
    #define gFSPSM_ctrl             sce_ctrl
    #define FSPSM_CONFIG            sce_cfg_t
    #define gFSPSM_cfg              sce_cfg
    #define H_INSTANCE              _handle
    #define FSPSM_OPEN              R_SCE_Open
    #define FSPSM_CLOSE             R_SCE_Close

    /* rand generation func */
    #define R_RANDOM_GEN(b)         R_SCE_RandomNumberGenerate(b)

    #define FSPSM_ROOTCA_RSA2048    \
                        R_SCE_TLS_RootCertificateRSA2048PublicKeyInstall
    #define FSPSM_TLS_SVRKEYExVfy   R_SCE_TLS_ServerKeyExchangeVerify
    #define FSPSM_TLS_ECCS256R1_KPG \
                    R_SCE_TLS_ECC_secp256r1_EphemeralWrappedKeyPairGenerate
    #define FSPSM_TLS_PREMASTERGEN \
                    R_SCE_TLS_PreMasterSecretGenerateForECC_secp256r1
    /* hmac */
    #define FSPSM_S256HMAC_GInt   R_SCE_SHA256HMAC_GenerateInit
    #define FSPSM_S256HMAC_GUp    R_SCE_SHA256HMAC_GenerateUpdate
    #define FSPSM_S256HMAC_GFnl   R_SCE_SHA256HMAC_GenerateFinal
    #define FSPSM_S256HMAC_VInt   R_SCE_SHA256HMAC_VerifyInit
    #define FSPSM_S256HMAC_VUp    R_SCE_SHA256HMAC_VerifyUpdate
    #define FSPSM_S256HMAC_VFnl   R_SCE_SHA256HMAC_VerifyFinal
    #define FSPSM_HMAC_HANDLE     sce_hmac_sha_handle_t
    #define FSPSM_HMAC_WKEY       sce_hmac_sha_wrapped_key_t

    /* TLS */
    #define FSPSM_SESSIONKEY_GEN_FUNC R_SCE_TLS_SessionKeyGenerate
    #define FSPSM_MASTERSECRET_GEN_FUNC R_SCE_TLS_MasterSecretGenerate
    #define FSPSM_PREGEN_FUNC       R_SCE_TLS_PreMasterSecretGenerateForRSA2048
    #define FSPSM_PREGENENC_FUNC    R_SCE_TLS_PreMasterSecretEncryptWithRSA2048

    /* certificate */
    #define FSPSM_TLSCERT_VRY       R_SCE_TLS_CertificateVerify
    #define FSPSM_TLSROOTCERT_VRY   R_SCE_TLS_RootCertificateVerify
    #define FSPSM_CACERT_PUB_WKEY   \
                            sce_tls_ca_certification_public_wrapped_key_t

    /* verify data */
    #define FSPSM_VERIFY_DATA_FUNC  R_SCE_TLS_VerifyDataGenerate

    /* aes */
    #define FSPSM_AES_WKEY          sce_aes_wrapped_key_t
    #define FSPSM_AES_PWKEY         sce_aes_wrapped_key_t*
    #define FSPSM_AESGCM_HANDLE     sce_gcm_handle_t
    #define FSPSM_AES_HANDLE        sce_aes_handle_t
    /* aes 128 cbc */
    #define FSPSM_AES128CBCEnc_Init    R_SCE_AES128CBC_EncryptInit
    #define FSPSM_AES128CBCEnc_Up      R_SCE_AES128CBC_EncryptUpdate
    #define FSPSM_AES128CBCEnc_Final   R_SCE_AES128CBC_EncryptFinal
    #define FSPSM_AES128CBCDec_Init    R_SCE_AES128CBC_DecryptInit
    #define FSPSM_AES128CBCDec_Up      R_SCE_AES128CBC_DecryptUpdate
    #define FSPSM_AES128CBCDec_Final   R_SCE_AES128CBC_DecryptFinal

    /* aes 256 cbc */
    #define FSPSM_AES256CBCEnc_Init    R_SCE_AES256CBC_EncryptInit
    #define FSPSM_AES256CBCEnc_Up      R_SCE_AES256CBC_EncryptUpdate
    #define FSPSM_AES256CBCEnc_Final   R_SCE_AES256CBC_EncryptFinal
    #define FSPSM_AES256CBCDec_Init    R_SCE_AES256CBC_DecryptInit
    #define FSPSM_AES256CBCDec_Up      R_SCE_AES256CBC_DecryptUpdate
    #define FSPSM_AES256CBCDec_Final   R_SCE_AES256CBC_DecryptFinal

    /* aes128 gcm */
    #define FSPSM_AES128GCMEnc_Init    R_SCE_AES128GCM_EncryptInit
    #define FSPSM_AES128GCMEnc_Up      R_SCE_AES128GCM_EncryptUpdate
    #define FSPSM_AES128GCMEnc_Final   R_SCE_AES128GCM_EncryptFinal
    #define FSPSM_AES128GCMDec_Init    R_SCE_AES128GCM_DecryptInit
    #define FSPSM_AES128GCMDec_Up      R_SCE_AES128GCM_DecryptUpdate
    #define FSPSM_AES128GCMDec_Final   R_SCE_AES128GCM_DecryptFinal

    /* aes256 gcm */
    #define FSPSM_AES256GCMEnc_Init    R_SCE_AES256GCM_EncryptInit
    #define FSPSM_AES256GCMEnc_Up      R_SCE_AES256GCM_EncryptUpdate
    #define FSPSM_AES256GCMEnc_Final   R_SCE_AES256GCM_EncryptFinal
    #define FSPSM_AES256GCMDec_Init    R_SCE_AES256GCM_DecryptInit
    #define FSPSM_AES256GCMDec_Up      R_SCE_AES256GCM_DecryptUpdate
    #define FSPSM_AES256GCMDec_Final   R_SCE_AES256GCM_DecryptFinal

    /* rsa */
    /* rsa data */
    #define FSPSM_RSA_DATA          sce_rsa_byte_data_t
    /* rsa 1024 key */
    #define FSPSM_RSA1024_WPA_KEY   sce_rsa1024_wrapped_pair_key_t
    #define FSPSM_RSA1024_WPB_KEY   sce_rsa1024_public_wrapped_key_t
    #define FSPSM_RSA1024_WPI_KEY   sce_rsa1024_private_wrapped_key_t
    /* rsa 2048 key */
    #define FSPSM_RSA2048_WPA_KEY   sce_rsa2048_wrapped_pair_key_t
    #define FSPSM_RSA2048_WPB_KEY   sce_rsa2048_public_wrapped_key_t
    #define FSPSM_RSA2048_WPI_KEY   sce_rsa2048_private_wrapped_key_t

    /* rsa key gen */
    #define FSPSM_RSA1024_KEYPA_GEN(x,y) R_SCE_RSA1024_WrappedKeyPairGenerate\
                                    (x)
    #define FSPSM_RSA2048_KEYPA_GEN(x,y) R_SCE_RSA2048_WrappedKeyPairGenerate\
                                    (x)

    /* rsa function */
    #define FSPSM_RSA1024_PKCSENC_FUNC(p,c,k) R_SCE_RSAES_PKCS1024_Encrypt\
                                                            (p,c,k)
    #define FSPSM_RSA2048_PKCSENC_FUNC(p,c,k) R_SCE_RSAES_PKCS2048_Encrypt\
                                                            (p,c,k)
    #define FSPSM_RSA1024_PKCSDEC_FUNC(p,c,k,l) R_SCE_RSAES_PKCS1024_Decrypt\
                                                            (p,c,k)
    #define FSPSM_RSA2048_PKCSDEC_FUNC(p,c,k,l) R_SCE_RSAES_PKCS2048_Decrypt\
                                                            (p,c,k)
    #define FSPSM_RSA1024_SIGN_FUNC(m,s,k,t) \
                        R_SCE_RSASSA_PKCS1024_SignatureGenerate(m,s,k,t)
    #define FSPSM_RSA2048_SIGN_FUNC(m,s,k,t)  \
                        R_SCE_RSASSA_PKCS2048_SignatureGenerate(m,s,k,t)
    #define FSPSM_RSA1024_VRY_FUNC(m,s,k,t) \
                        R_SCE_RSASSA_PKCS1024_SignatureVerify(m,s,k,t)
    #define FSPSM_RSA2048_VRY_FUNC(m,s,k,t) \
                        R_SCE_RSASSA_PKCS2048_SignatureVerify(m,s,k,t)
    /* sha */
    #define FSPSM_SHA_HANDLE    sce_sha_md5_handle_t
    #define FSPSM_SHA256_Init   R_SCE_SHA256_Init
    #define FSPSM_SHA256_Up     R_SCE_SHA256_Update
    #define FSPSM_SHA256_Final  R_SCE_SHA256_Final

    /* user API */
    #define FSPSM_INFORM_FUNC       wc_sce_inform_user_keys
    #define FSPSM_CALLBACK_FUNC     wc_sce_set_callbacks
    #define FSPSM_CALLBACK_CTX_FUNC wc_sce_set_callback_ctx
    #define FSPSM_INFORM_CERT_SIGN  wc_sce_inform_cert_sign

#elif defined(WOLFSSL_RENESAS_RSIP)

    #include "r_rsip.h"

    /* structure, type so on */
    #define FSPSM_W_KEYVAR          renesas_rsip_wrappedkey
    #define FSPSM_tls_flg_ST        rsip_keyflgs_tls
    #define FSPSM_key_flg_ST        rsip_keyflgs_crypt
    #define FSPSM_tag_ST            tagUser_RSIPPKCbInfo
    #define FSPSM_ST                User_RSIPPKCbInfo
    #define FSPSM_ST_PKC            RSIP_PKCbInfo
    #define FSPSM_KEY_TYPE          rsip_key_type_t

    #define FSPSM_INSTANCE          rsip_instance_ctrl_t
    #define gFSPSM_ctrl             rsip_ctrl
    #define FSPSM_CONFIG            rsip_cfg_t
    #define gFSPSM_cfg              rsip_cfg
    #define H_INSTANCE              gFSPSM_ctrl
    #define FSPSM_OPEN              R_RSIP_Open
    #define FSPSM_CLOSE             R_RSIP_Close

    /* rnd generation func */
    #define R_RANDOM_GEN(b)         R_RSIP_RandomNumberGenerate(&gFSPSM_ctrl,b)
    /* sha 1*/
    #define FSPSM_SHA_HANDLE        rsip_sha_handle_t
    #define FSPSM_SHA1_Init         _R_RSIP_SHA1_GenerateInit
    #define FSPSM_SHA1_Up           _R_RSIP_SHA_GenerateUpdate
    #define FSPSM_SHA1_Final        _R_RSIP_SHA_GenerateFinal

    /* sha 224 */
    #define FSPSM_SHA224_Init       _R_RSIP_SHA224_GenerateInit
    #define FSPSM_SHA224_Up         _R_RSIP_SHA_GenerateUpdate
    #define FSPSM_SHA224_Final      _R_RSIP_SHA_GenerateFinal

    /* sha 256 */
    #define FSPSM_SHA256_Init       _R_RSIP_SHA256_GenerateInit
    #define FSPSM_SHA256_Up         _R_RSIP_SHA_GenerateUpdate
    #define FSPSM_SHA256_Final      _R_RSIP_SHA_GenerateFinal

    /* sha 384 */
    #define FSPSM_SHA384_Init       _R_RSIP_SHA384_GenerateInit
    #define FSPSM_SHA384_Up         _R_RSIP_SHA_GenerateUpdate
    #define FSPSM_SHA384_Final      _R_RSIP_SHA_GenerateFinal

    /* sha 512 */
    #define FSPSM_SHA512_Init       _R_RSIP_SHA512_GenerateInit
    #define FSPSM_SHA512_Up         _R_RSIP_SHA_GenerateUpdate
    #define FSPSM_SHA512_Final      _R_RSIP_SHA_GenerateFinal

    /* sha 512 224*/
    #define FSPSM_SHA512_224_Init   _R_RSIP_SHA512_224_GenerateInit
    #define FSPSM_SHA512_224_Up     _R_RSIP_SHA_GenerateUpdate
    #define FSPSM_SHA512_224_Final  _R_RSIP_SHA_GenerateFinal

     /* sha 512 256 */
    #define FSPSM_SHA512_256_Init   _R_RSIP_SHA512_256_GenerateInit
    #define FSPSM_SHA512_256_Up     _R_RSIP_SHA_GenerateUpdate
    #define FSPSM_SHA512_256_Final  _R_RSIP_SHA_GenerateFinal
    /* aes */
    #define FSPSM_AES_WKEY          rsip_wrapped_key_t
    #define FSPSM_AES_PWKEY         rsip_wrapped_key_t*
    #define FSPSM_AESGCM_HANDLE     rsip_instance_ctrl_t*
    #define FSPSM_AES_HANDLE        rsip_instance_ctrl_t*
    #define FSPSM_AES_KEYGEN_FUNC   _R_RSIP_KeyGenerate

    /* aes 128 cbc */
    /* mode : RSIP_AES_MODE_CBC */
    #define FSPSM_AES128CBCEnc_Init    _R_RSIP_AESCBC_Cipher_EncryptInit
    #define FSPSM_AES128CBCEnc_Up      _R_RSIP_AESCBC_Cipher_EncryptUpdate
    #define FSPSM_AES128CBCEnc_Final   _R_RSIP_AESCBC_Cipher_EncryptFinal
    #define FSPSM_AES128CBCDec_Init    _R_RSIP_AESCBC_Cipher_DecryptInit
    #define FSPSM_AES128CBCDec_Up      _R_RSIP_AESCBC_Cipher_DecryptUpdate
    #define FSPSM_AES128CBCDec_Final   _R_RSIP_AESCBC_Cipher_DecryptFinal

    /* aes 256 cbc */
    /* mode : RSIP_AES_MODE_CBC */
    #define FSPSM_AES256CBCEnc_Init    _R_RSIP_AESCBC_Cipher_EncryptInit
    #define FSPSM_AES256CBCEnc_Up      _R_RSIP_AESCBC_Cipher_EncryptUpdate
    #define FSPSM_AES256CBCEnc_Final   _R_RSIP_AESCBC_Cipher_EncryptFinal
    #define FSPSM_AES256CBCDec_Init    _R_RSIP_AESCBC_Cipher_DecryptInit
    #define FSPSM_AES256CBCDec_Up      _R_RSIP_AESCBC_Cipher_DecryptUpdate
    #define FSPSM_AES256CBCDec_Final   _R_RSIP_AESCBC_Cipher_DecryptFinal

    /* aes128 gcm */
    #define FSPSM_AES128GCMEnc_Init    _R_RSIP_AES_GCM_EncryptInit
    #define FSPSM_AES128GCMEnc_Up      _R_RSIP_AES_GCM_EncryptUpdate
    #define FSPSM_AES128GCMEnc_Final   _R_RSIP_AES_GCM_EncryptFinal
    #define FSPSM_AES128GCMDec_Init    _R_RSIP_AES_GCM_DecryptInit
    #define FSPSM_AES128GCMDec_Up      _R_RSIP_AES_GCM_DecryptUpdate
    #define FSPSM_AES128GCMDec_Final   _R_RSIP_AES_GCM_DecryptFinal

    /* aes256 gcm */
    #define FSPSM_AES256GCMEnc_Init    _R_RSIP_AES_GCM_EncryptInit
    #define FSPSM_AES256GCMEnc_Up      _R_RSIP_AES_GCM_EncryptUpdate
    #define FSPSM_AES256GCMEnc_Final   _R_RSIP_AES_GCM_EncryptFinal
    #define FSPSM_AES256GCMDec_Init    _R_RSIP_AES_GCM_DecryptInit
    #define FSPSM_AES256GCMDec_Up      _R_RSIP_AES_GCM_DecryptUpdate
    #define FSPSM_AES256GCMDec_Final   _R_RSIP_AES_GCM_DecryptFinal

    /* rsa */
    /* rsa data */
    typedef struct {
        uint8_t *pdata;
        uint32_t data_length;
        uint32_t data_type;/* no use for RSIP */
        uint32_t hash_type;/* for rsip, hash type */
    } tmpRSIP_RSA_DATA;

    #define FSPSM_RSA_DATA          tmpRSIP_RSA_DATA

    /* rsa 1024 key */
    #define FSPSM_RSA1024_WPA_KEY   rsip_wrapped_key_t
    #define FSPSM_RSA1024_WPB_KEY   rsip_wrapped_key_t
    #define FSPSM_RSA1024_WPI_KEY   rsip_wrapped_key_t
    /* rsa 2048 key */
    #define FSPSM_RSA2048_WPA_KEY   rsip_wrapped_key_t
    #define FSPSM_RSA2048_WPB_KEY   rsip_wrapped_key_t
    #define FSPSM_RSA2048_WPI_KEY   rsip_wrapped_key_t

    /* rsa key gen */
    #define FSPSM_RSA1024_KEYPA_GEN(x,y) R_RSIP_KeyPairGenerate\
                                    (&gFSPSM_ctrl, RSIP_KEY_PAIR_TYPE_RSA_1024,\
                                    x,y)
    #define FSPSM_RSA2048_KEYPA_GEN(x,y) R_RSIP_KeyPairGenerate\
                                    (&gFSPSM_ctrl, RSIP_KEY_PAIR_TYPE_RSA_2048,\
                                    x,y)

    /* rsa function */
    /* encrypt */
    #define FSPSM_RSA1024_PKCSENC_FUNC(p,c,k) R_RSIP_RSAES_PKCS1_V1_5_Encrypt\
        (&gFSPSM_ctrl, k, (uint8_t const *const)(p)->pdata, \
        (uint32_t const)(p)->data_length, \
        (uint8_t *const)(c)->pdata);

    #define FSPSM_RSA2048_PKCSENC_FUNC(p,c,k) FSPSM_RSA1024_PKCSENC_FUNC(p,c,k)
    /* decrypt */
    #define FSPSM_RSA1024_PKCSDEC_FUNC(c,p,k,l) R_RSIP_RSAES_PKCS1_V1_5_Decrypt\
        (&gFSPSM_ctrl, k, (uint8_t const *const)(c)->pdata, \
        (uint8_t *const)(p)->pdata,\
        (uint32_t *const)l, \
        (uint32_t const)(p)->data_length);
    #define FSPSM_RSA2048_PKCSDEC_FUNC(c,p,k,l) \
                                            FSPSM_RSA1024_PKCSDEC_FUNC(c,p,k,l)

    /* sign */
    #define FSPSM_RSA1024_SIGN_FUNC(m,s,k,t) R_RSIP_RSASSA_PKCS1_V1_5_Sign\
        (&gFSPSM_ctrl, k, (m)->hash_type, (uint8_t const *const)(m)->pdata,\
        (uint8_t *const)(s)->pdata)
    #define FSPSM_RSA2048_SIGN_FUNC(m,s,k,t)  FSPSM_RSA1024_SIGN_FUNC(m,s,k,t)

    /* verify */
    #define FSPSM_RSA1024_VRY_FUNC(s,m,k,t)  R_RSIP_RSASSA_PKCS1_V1_5_Verify\
        (&gFSPSM_ctrl, k, (m)->hash_type, (uint8_t const *const)(m)->pdata,\
        (uint8_t *const)(s)->pdata)
    #define FSPSM_RSA2048_VRY_FUNC(s,m,k,t)  FSPSM_RSA1024_VRY_FUNC(s,m,k,t)

#endif

#endif /* __RENESAS_FSP_CRYPT_H__ */
