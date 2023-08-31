/* renesas-fsp-crypt.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
    #define FSPSM_key_flg_ST        sce_keyflgs_cryt
    #define FSPSM_tag_ST            tagUser_SCEPKCbInfo
    #define FSPSM_ST                User_SCEPKCbInfo
    #define FSPSM_ST_PKC            SCE_PKCbInfo

    /* map SCE API to macro */
    #define FSPSM_INSTANCE          sce_instance_ctrl_t
    #define gFSPSM_ctrl             sce_ctrl
    #define FSPSM_CONFIG            sce_cfg_t
    #define gFSPSM_cfg              sce_cfg
    #define FSPSM_OPEN              R_SCE_Open
    #define FSPSM_CLOSE             R_SCE_Close

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
    #define FSPSM_RSA1024_KEYPA_GEN R_SCE_RSA1024_WrappedKeyPairGenerate
    #define FSPSM_RSA2048_KEYPA_GEN R_SCE_RSA2048_WrappedKeyPairGenerate

    /* rsa function */
    #define FSPSM_RSA1024_PKCSENC_FUNC R_SCE_RSAES_PKCS1024_Encrypt
    #define FSPSM_RSA2048_PKCSENC_FUNC R_SCE_RSAES_PKCS2048_Encrypt
    #define FSPSM_RSA1024_PKCSDEC_FUNC R_SCE_RSAES_PKCS1024_Decrypt
    #define FSPSM_RSA2048_PKCSDEC_FUNC R_SCE_RSAES_PKCS2048_Decrypt
    #define FSPSM_RSA1024_SIGN_FUNC R_SCE_RSASSA_PKCS1024_SignatureGenerate
    #define FSPSM_RSA2048_SIGN_FUNC R_SCE_RSASSA_PKCS2048_SignatureGenerate
    #define FSPSM_RSA1024_VRY_FUNC R_SCE_RSASSA_PKCS1024_SignatureVerify
    #define FSPSM_RSA2048_VRY_FUNC R_SCE_RSASSA_PKCS2048_SignatureVerify
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

#endif

#endif /* __RENESAS_FSP_CRYPT_H__ */
