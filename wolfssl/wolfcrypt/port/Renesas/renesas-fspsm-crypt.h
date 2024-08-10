/* renesas-fspsm-crypt.h
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
#ifndef __RENESAS_FSPSM_CRYPT_H__
#define __RENESAS_FSPSM_CRYPT_H__


#include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WOLFSSL_FSPSM_ILLEGAL_CIPHERSUITE     -1
#define MAX_FSPSM_CBINDEX 5

typedef void* FSPSM_W_KEYVAR;

/* flsgas related to TLS */
struct FSPSM_tls_flg_ST {
    uint8_t pk_key_set:1;
    uint8_t session_key_set:1;
};

/* flags Crypt Only */
struct FSPSM_key_flg_ST {
    uint8_t aes256_installedkey_set:1;
    uint8_t aes128_installedkey_set:1;
    uint8_t rsapri2048_installedkey_set:1;
    uint8_t rsapub2048_installedkey_set:1;
    uint8_t rsapri1024_installedkey_set:1;
    uint8_t rsapub1024_installedkey_set:1;
    uint8_t message_type:1;/*message 0, hashed 1*/
};

typedef struct FSPSM_tag_ST {
    /* unique number for each session */
    int devId;
   #if defined(WOLFSSL_RENESAS_FSPSM_TLS) && \
        !defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)
    /* out from R_SCE_TLS_ServerKeyExchangeVerify */
    uint32_t
        encrypted_ephemeral_ecdh_public_key[FSPSM_TLS_ENCRYPTED_ECCPUBKEY_SZ];
    /* out from R_SCE_TLS_ECC_secp256r1_EphemeralWrappedKeyPairGenerate */
    sce_tls_p256_ecc_wrapped_key_t ecc_p256_wrapped_key;
    uint8_t ecc_ecdh_public_key[HW_SCE_ECC_PUBLIC_KEY_BYTE_SIZE];

    uint32_t    masterSecret[FSPSM_TLS_MASTERSECRET_SIZE/4];
    uint8_t     clientRandom[FSPSM_TLS_CLIENTRANDOM_SZ];
    uint8_t     serverRandom[FSPSM_TLS_SERVERRANDOM_SZ];
    uint8_t     cipher;

   #endif

    /* installed key handling */
    /* aes */
    FSPSM_W_KEYVAR   wrapped_key_aes256;
    FSPSM_W_KEYVAR   wrapped_key_aes128;

   #if defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)
    /* rsa */
    FSPSM_W_KEYVAR   wrapped_key_rsapri2048;
    FSPSM_W_KEYVAR   wrapped_key_rsapub2048;
    FSPSM_W_KEYVAR   wrapped_key_rsapri1024;
    FSPSM_W_KEYVAR   wrapped_key_rsapub1024;
   #endif

   #if defined(WOLFSSL_RENESAS_RSIP)
    uint8_t hash_type;
   #endif
    /* key status flags */
    /* flag whether encrypted ec key is set */
    union {
        uint8_t chr;
        struct FSPSM_tls_flg_ST bits;
    } keyflgs_tls;
    /* key status flags */
    /* flags shows status if wrapped keys are installed */
    union {
        uint8_t chr;
        struct FSPSM_key_flg_ST bits;
    } keyflgs_crypt;
} FSPSM_ST;

typedef struct tagPKCbInfo {
    FSPSM_ST    *user_PKCbInfo[MAX_FSPSM_CBINDEX];
    uint32_t    num_session;
} FSPSM_ST_PKC;

#ifdef WOLFSSL_RENESAS_FSPSM_TLS
typedef struct
{
    uint8_t                          *encrypted_provisioning_key;
    uint8_t                          *iv;
    uint8_t                          *encrypted_user_tls_key;
    uint32_t                         encrypted_user_tls_key_type;
    FSPSM_CACERT_PUB_WKEY            user_rsa2048_tls_wrappedkey;
} fspsm_key_data;
#endif

struct WOLFSSL;
struct WOLFSSL_CTX;
struct ecc_key;

WOLFSSL_LOCAL int     wc_fspsm_Open();
WOLFSSL_LOCAL void    wc_fspsm_Close();
WOLFSSL_LOCAL int     wc_fspsm_hw_lock();
WOLFSSL_LOCAL void    wc_fspsm_hw_unlock( void );
WOLFSSL_LOCAL int     wc_fspsm_usable(const struct WOLFSSL *ssl,
                                    uint8_t session_key_generated);

typedef struct {
    FSPSM_AES_PWKEY   wrapped_key;
    word32           keySize;
#ifdef WOLFSSL_RENESAS_FSPSM_TLS
    byte             setup;
#endif
} FSPSM_AES_CTX;

struct Aes;
WOLFSSL_LOCAL void wc_fspsm_Aesfree(struct Aes* aes);
WOLFSSL_LOCAL int wc_fspsm_AesCbcEncrypt(struct Aes* aes, byte* out,
                        const byte* in, word32 sz);
WOLFSSL_LOCAL int wc_fspsm_AesCbcDecrypt(struct Aes* aes, byte* out,
                        const byte* in, word32 sz);

WOLFSSL_LOCAL int  wc_fspsm_AesGcmEncrypt(struct Aes* aes, byte* out,
                          const byte* in, word32 sz,
                          byte* iv, word32 ivSz,
                          byte* authTag, word32 authTagSz,
                          const byte* authIn, word32 authInSz,
                          void* ctx);

WOLFSSL_LOCAL int  wc_fspsm_AesGcmDecrypt(struct Aes* aes, byte* out,
                          const byte* in, word32 sz,
                          const byte* iv, word32 ivSz,
                          const byte* authTag, word32 authTagSz,
                          const byte* authIn, word32 authInSz,
                          void* ctx);

#if (!defined(NO_SHA) || !defined(NO_SHA256) || defined(WOLFSSL_SH224) || \
    defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)) && \
    !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)

typedef enum {
#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    FSPSM_SHA256 = 1,
#elif defined(WOLFSSL_RENESAS_RSIP)
    FSPSM_SHA1 = RSIP_HASH_TYPE_SHA1,
    FSPSM_SHA224 = RSIP_HASH_TYPE_SHA224,
    FSPSM_SHA256 = RSIP_HASH_TYPE_SHA256,
    FSPSM_SHA384 = RSIP_HASH_TYPE_SHA384,
    FSPSM_SHA512 = RSIP_HASH_TYPE_SHA512,
    FSPSM_SHA512_224 = RSIP_HASH_TYPE_SHA512_224,
    FSPSM_SHA512_256 = RSIP_HASH_TYPE_SHA512_256,
#endif
} FSPSM_SHA_TYPE;

typedef struct {
    void*  heap;
    word32 sha_type;
#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    word32 used;
    word32 len;
    byte*  msg;
#endif
#if defined(WOLFSSL_RENESAS_RSIP)
    FSPSM_SHA_HANDLE handle;
#endif
#if defined(WOLF_CRYPTO_CB)
    word32 flags;
    int devId;
#endif
} wolfssl_FSPSM_Hash;

/* RAW hash function APIs are not implemented with SCE */
#undef  WOLFSSL_NO_HASH_RAW
#define WOLFSSL_NO_HASH_RAW

#if !defined(NO_SHA) && defined(WOLFSSL_RENESAS_RSIP)
    typedef wolfssl_FSPSM_Hash wc_Sha;
#endif

#if defined(WOLFSSL_SHA224) && defined(WOLFSSL_RENESAS_RSIP)
    typedef wolfssl_FSPSM_Hash wc_Sha224;
    #define WC_SHA224_TYPE_DEFINED
#endif

#if !defined(NO_SHA256) && \
    (defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_RSIP))
    typedef wolfssl_FSPSM_Hash wc_Sha256;
#endif

#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_RENESAS_RSIP)
    typedef wolfssl_FSPSM_Hash wc_Sha384;
    #define WC_SHA384_TYPE_DEFINED
#endif

#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_RENESAS_RSIP)
    typedef wolfssl_FSPSM_Hash wc_Sha512;
    typedef wolfssl_FSPSM_Hash wc_Sha512_224;
    typedef wolfssl_FSPSM_Hash wc_Sha512_256;
    #define WC_SHA512_TYPE_DEFINED
#endif

#endif /* NO_SHA */

#if defined(WOLFSSL_RENESAS_FSPSM_TLS) && \
        !defined(WOLFSSL_RENESAS_FSPSM_CRYPT_ONLY)

WOLFSSL_LOCAL int     wc_fspsm_tls_RootCertVerify(
            const   uint8_t* cert,         uint32_t cert_len,
            uint32_t  key_n_start,        uint32_t key_n_len,
            uint32_t  key_e_start,        uint32_t key_e_len,
            uint32_t  cm_row);

WOLFSSL_LOCAL int     wc_sce_tls_CertVerify(
            const   uint8_t* cert,         uint32_t certSz,
            const   uint8_t* signature,    uint32_t sigSz,
            uint32_t  key_n_start,        uint32_t key_n_len,
            uint32_t  key_e_start,        uint32_t key_e_len,
            uint8_t*   sce_encRsaKeyIdx);


WOLFSSL_LOCAL int     wc_fspsm_generatePremasterSecret(
            uint8_t*   premaster,
            uint32_t  preSz);

WOLFSSL_LOCAL int     wc_fspsm_generateEncryptPreMasterSecret(
            struct WOLFSSL* ssl,
            uint8_t*           out,
            uint32_t*         outSz);

WOLFSSL_LOCAL int     wc_fspsm_Sha256GenerateHmac(
            const struct WOLFSSL *ssl,
            const uint8_t* myInner,
            uint32_t      innerSz,
            const uint8_t* in,
            uint32_t      sz,
            uint8_t*       digest);

WOLFSSL_LOCAL int wc_fspsm_Sha256VerifyHmac(
        const struct WOLFSSL *ssl,
        const uint8_t* message,
        uint32_t      messageSz,
        uint32_t      macSz,
        uint32_t      content);

WOLFSSL_LOCAL int wc_fspsm_storeKeyCtx(
        struct WOLFSSL* ssl,
        FSPSM_ST* info);

WOLFSSL_LOCAL int wc_fspsm_generateVerifyData(
        const uint8_t*  ms, /* master secret */
        const uint8_t*  side,
        const uint8_t*  handshake_hash,
        uint8_t*        hashes /* out */);

WOLFSSL_LOCAL int wc_fspsm_generateSessionKey(
        struct WOLFSSL*   ssl,
        FSPSM_ST* cbInfo,
        int               devId);

WOLFSSL_LOCAL int wc_fspsm_generateMasterSecret(
        uint8_t        cipherSuiteFirst,
        uint8_t        cipherSuite,
        const uint8_t *pr, /* pre-master    */
        const uint8_t *cr, /* client random */
        const uint8_t *sr, /* server random */
        uint8_t *ms);

WOLFSSL_LOCAL int wc_fspsm_RsaVerifyTLS(struct WOLFSSL* ssl, byte* sig,
                        uint32_t sigSz, uint8_t** out,
                        const byte* key, uint32_t keySz, void* ctx);
WOLFSSL_LOCAL int wc_fspsm_EccVerifyTLS(struct WOLFSSL* ssl,
                        const uint8_t* sig, uint32_t sigSz,
                        const uint8_t* hash, uint32_t hashSz,
                        const uint8_t* key, uint32_t keySz,
                        int* result, void* ctx);
WOLFSSL_LOCAL int wc_fspsm_tls_CertVerify(
        const uint8_t* cert,       uint32_t certSz,
        const uint8_t* signature,  uint32_t sigSz,
        uint32_t      key_n_start,uint32_t key_n_len,
        uint32_t      key_e_start,uint32_t key_e_len,
        uint8_t*      fspsm_encPublickey);

/* Callback for EccShareSecret */
WOLFSSL_LOCAL int fspsm_EccSharedSecret(struct WOLFSSL* ssl,
            struct ecc_key* otherKey,
            uint8_t* pubKeyDer, unsigned int* pubKeySz,
            uint8_t* out, unsigned int* outlen, int side, void* ctx);

/* user API */
WOLFSSL_API void FSPSM_INFORM_FUNC(
    uint8_t*     encrypted_provisioning_key,
    uint8_t*     iv,
    uint8_t*     encrypted_user_tls_key,
    uint32_t    encrypted_user_tls_key_type);

WOLFSSL_API void FSPSM_CALLBACK_FUNC(struct WOLFSSL_CTX* ctx);
WOLFSSL_API int  FSPSM_CALLBACK_CTX_FUNC(struct WOLFSSL* ssl, void* user_ctx);
WOLFSSL_API void FSPSM_INFORM_CERT_SIGN(const uint8_t *sign);


#endif  /* WOLFSSL_RENESAS_FSPSM_TLS &&
         * !WOLFSSL_RENESAS_FSPSM_CRYPT_ONLY */

typedef struct FSPSM_RSA_CTX {
    FSPSM_RSA1024_WPI_KEY *wrapped_pri1024_key;
    FSPSM_RSA1024_WPB_KEY *wrapped_pub1024_key;
    FSPSM_RSA2048_WPI_KEY *wrapped_pri2048_key;
    FSPSM_RSA2048_WPB_KEY *wrapped_pub2048_key;
    word32 keySz;
} FSPSM_RSA_CTX;

/* rsa */
struct RsaKey;
struct WC_RNG;
WOLFSSL_LOCAL void wc_fspsm_RsaKeyFree(struct RsaKey *key);
WOLFSSL_LOCAL int  wc_fspsm_RsaFunction(const byte* in, word32 inLen, byte* out,
  word32 *outLen, int type, struct RsaKey* key, struct WC_RNG* rng);
WOLFSSL_LOCAL int  wc_fspsm_MakeRsaKey(struct RsaKey* key, int size, void* ctx);
WOLFSSL_LOCAL int  wc_fspsm_RsaSign(const byte* in, word32 inLen, byte* out,
                    word32* outLen, struct RsaKey* key, void* ctx);
WOLFSSL_LOCAL int  wc_fspsm_RsaVerify(const byte* in, word32 inLen, byte* out,
                    word32* outLen,struct RsaKey* key, void* ctx);
WOLFSSL_LOCAL int  wc_fspsm_GenerateRandBlock(byte* output, word32 size);
#endif  /* __RENESAS_FSPSM_CRYPT_H__ */
