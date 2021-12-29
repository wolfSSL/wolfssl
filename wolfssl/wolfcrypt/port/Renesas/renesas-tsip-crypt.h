/* renesas-tsip-crypt.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
#ifndef __RENESAS_TSIP_CRYPT_H__
#define __RENESAS_TSIP_CRYPT_H__

#if !defined(WOLFCRYPT_ONLY)

#if defined(WOLFSSL_RENESAS_TSIP_IAREWRX)
    #include "r_bsp/mcu/all/r_rx_compiler.h"
    #include "r_bsp/platform.h"
#else
    #include "platform.h"
#endif

#include "r_tsip_rx_if.h"
#include <wolfssl/wolfcrypt/logging.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TSIP_SESSIONKEY_NONCE_SIZE      8

#define tsip_Sha256HmacVerify tsip_ShaXHmacVerify /* for backward compat */
#define sce_tsip_checkCA tsip_checkCA

typedef enum {
    WOLFSSL_TSIP_NOERROR = 0,
    WOLFSSL_TSIP_ILLEGAL_CIPHERSUITE = 0xffffffff,
}wolfssl_tsip_error_number;

typedef enum {
    tsip_Key_SESSION = 1,
    tsip_Key_AES128  = 2,
    tsip_Key_AES256  = 3,
    tsip_Key_RSA1024 = 4,
    tsip_Key_RSA2048 = 5,
    tsip_Key_tls_Rsa2048 = 6,
    tsip_Key_unknown = -1,
} wolfssl_TSIP_KEY_IV;

enum {
    l_TLS_RSA_WITH_AES_128_CBC_SHA            = 0x2F,
    l_TLS_RSA_WITH_AES_128_CBC_SHA256         = 0x3c,
    l_TLS_RSA_WITH_AES_256_CBC_SHA            = 0x35,
    l_TLS_RSA_WITH_AES_256_CBC_SHA256         = 0x3d,
    l_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0x23,
    l_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   = 0x27,
    l_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0x2b,
    l_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   = 0x2f,    
};

enum {
    ENCRYPTED_ECDHE_PUBKEY_SZ = 96,
    ECCP256_PUBKEY_SZ = 64,
    TSIP_TLS_CLIENTRANDOM_SZ = 32,
    TSIP_TLS_SERVERRANDOM_SZ = 32,
};

#if (!defined(NO_SHA) || !defined(NO_SHA256)) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)

typedef enum {
    TSIP_SHA1 = 0,
    TSIP_SHA256 = 1,
} TSIP_SHA_TYPE;

typedef struct {
    byte*  msg;
    void*  heap;
    word32 used;
    word32 len;
    word32 sha_type;
#if defined(WOLF_CRYPTO_CB)
    word32 flags;
    int devId;
#endif    
} wolfssl_TSIP_Hash;

/* RAW hash function APIs are not implemented with TSIP */
#define WOLFSSL_NO_HASH_RAW

typedef wolfssl_TSIP_Hash wc_Sha;

#if !defined(NO_SHA256)
    typedef wolfssl_TSIP_Hash wc_Sha256;
#endif

#endif /* NO_SHA */

#if defined(WOLFSSL_RENESAS_TSIP_TLS_AES_CRYPT)
    typedef struct {
        tsip_aes_key_index_t tsip_keyIdx;
        word32               keySize;
        byte                 setup;
    } TSIP_AES_CTX;
#endif 



/*
 * structure for ECDH key exchange
 */
typedef struct TsipUserCtx {
    
    uint32_t user_key_id;

#if (WOLFSSL_RENESAS_TSIP_VER >=109)     
    /* out from R_SCE_TLS_ServerKeyExchangeVerify */
    uint32_t encrypted_ephemeral_ecdh_public_key[ENCRYPTED_ECDHE_PUBKEY_SZ];
    
    /* ephemeral ECDH pubkey index 
     * got from R_TSIP_GenerateTlsP256EccKeyIndex.
     * Input to R_TSIP_TlsGeneratePreMasterSecretWithEccP256Key. 
     */
    tsip_tls_p256_ecc_key_index_t ecc_p256_wrapped_key;

    /* ephemeral ECDH pub-key Qx(256bit)||Qy(256bit) 
     * got from  R_TSIP_GenerateTlsP256EccKeyIndex.
     * Should be sent to peer(server) in Client Key Exchange msg. 
     */
    uint8_t ecc_ecdh_public_key[ECCP256_PUBKEY_SZ];
#endif /* WOLFSSL_RENESAS_TSIP_VER >=109 */

    /* info to generate session key */
    uint32_t    tsip_masterSecret[TSIP_TLS_MASTERSECRET_SIZE/4];
    uint8_t     tsip_clientRandom[TSIP_TLS_CLIENTRANDOM_SZ];
    uint8_t     tsip_serverRandom[TSIP_TLS_SERVERRANDOM_SZ];

    /* TSIP defined cipher suite number */
    uint32_t    tsip_cipher;    
    
    /* flags */
    uint8_t pk_key_set:1;
    uint8_t session_key_set:1;


} TsipUserCtx;

typedef TsipUserCtx user_PKCbInfo;

typedef struct
{
    TsipUserCtx* userCtx; 
} TsipPKCbInfo;


#if (WOLFSSL_RENESAS_TSIP_VER >=109)

typedef struct
{
    uint8_t *  encrypted_provisioning_key;
    uint8_t *  iv;
    uint8_t *  encrypted_user_tls_key;
    uint32_t   encrypted_user_tls_key_type;
    tsip_tls_ca_certification_public_key_index_t  user_rsa2048_tls_pubindex;
} tsip_key_data;

#else
typedef struct
{
    uint8_t*  encrypted_session_key;
    uint8_t*  iv;
    uint8_t*  encrypted_user_tls_key;
    tsip_tls_ca_certification_public_key_index_t  user_rsa2048_tls_pubindex;
} tsip_key_data;

#endif

struct Aes;
struct WOLFSSL;
/*----------------------------------------------------*/
/*   APIs                                             */
/*----------------------------------------------------*/

WOLFSSL_API void tsip_inform_cert_sign(const byte *sign);

WOLFSSL_API void tsip_set_callbacks(struct WOLFSSL_CTX* ctx);

WOLFSSL_API int  tsip_set_callback_ctx(struct WOLFSSL* ssl, void* user_ctx);



#if (WOLFSSL_RENESAS_TSIP_VER >=109)

#define wc_tsip_inform_user_keys_ex tsip_inform_user_keys_ex
WOLFSSL_API void tsip_inform_user_keys_ex(
    byte*       provisioning_key,   /* key got from DLM server */
    byte*       iv,                 /* iv used for public key  */
    byte*       encrypted_public_key,/*RSA2048 or ECDSAp256 public key*/
    word32      public_key_type);   /* 0: RSA-2048 2:ECDSA P-256 */    

#else

WOLFSSL_API void tsip_inform_user_keys(
    byte*       encrypted_session_key, 
    byte*       iv,
    byte*       encrypted_user_tls_key);

#endif


/*----------------------------------------------------*/
/*   internal use functions                           */
/*----------------------------------------------------*/


#if (WOLFSSL_RENESAS_TSIP_VER >=109)

WOLFSSL_LOCAL int wc_tsip_generateMasterSecretEx(
        byte        cipherSuiteFirst,
        byte        cipherSuite,
        const byte* pr,                 /* pre-master    */
        const byte* cr,                 /* client random */
        const byte* sr,                 /* server random */
        byte*       ms);

#else

WOLFSSL_LOCAL int wc_tsip_generateMasterSecret(
        const byte *pre,
        const byte *cr,
        const byte *sr,
        byte *ms);

#endif


WOLFSSL_LOCAL int wc_tsip_storeKeyCtx(
        struct WOLFSSL *ssl,
        TsipUserCtx *userCtx);

WOLFSSL_LOCAL int wc_tsip_generateEncryptPreMasterSecret(
        struct WOLFSSL*  ssl,
        byte*       out,
        word32*     outSz);

WOLFSSL_LOCAL int wc_tsip_EccSharedSecret(
        struct WOLFSSL* ssl,
        struct ecc_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx);

WOLFSSL_LOCAL int wc_tsip_RsaVerify(
        struct WOLFSSL* ssl,
        byte* sig,
        word32 sigSz,
        byte** out,
        const byte* key,
        word32 keySz,
        void* ctx);

WOLFSSL_LOCAL int wc_tsip_EccVerify(
        struct WOLFSSL*  ssl, 
        const byte* sig,    word32  sigSz,
        const byte* hash,   word32  hashSz,
        const byte* key,    word32  keySz,
        int*  result, void*   ctx);

WOLFSSL_LOCAL int wc_tsip_generateVerifyData(
        const uint8_t*  masterSecret,
        const uint8_t*  side,
        const uint8_t*  handshake_hash,
        uint8_t*        hashes);

WOLFSSL_LOCAL int wc_tsip_AesCbcEncrypt(
        struct Aes* aes,
        byte*       out,
        const byte* in,
        word32      sz);

WOLFSSL_LOCAL int wc_tsip_AesCbcDecrypt(
        struct Aes* aes,
        byte*       out,
        const byte* in,
        word32      sz);
 
WOLFSSL_LOCAL int wc_tsip_AesGcmEncrypt(
        struct Aes* aes, byte* out,
        const byte* in, word32 sz,
              byte* iv, word32 ivSz,
              byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz,
        void* ctx);
            
WOLFSSL_LOCAL int wc_tsip_AesGcmDecrypt(
        struct Aes* aes, byte* out,
        const byte* in, word32 sz,
        const byte* iv, word32 ivSz,
        const byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz,
        void* ctx);

WOLFSSL_LOCAL int wc_tsip_ShaXHmacVerify(
        const struct WOLFSSL *ssl,
        const byte* message, 
        word32      messageSz,
        word32      macSz,
        word32      content);

WOLFSSL_LOCAL int wc_tsip_Sha1HmacGenerate(
        const struct WOLFSSL *ssl,
        const byte* myInner, 
        word32      innerSz,
        const byte* in,
        word32      sz, 
        byte*       digest);

WOLFSSL_LOCAL int wc_tsip_Sha256HmacGenerate(
        const struct WOLFSSL *ssl,
        const byte* myInner,
        word32      innerSz,
        const byte* in,
        word32      sz,
        byte*       digest);

WOLFSSL_LOCAL int  tsip_Open();

WOLFSSL_LOCAL void tsip_Close();

WOLFSSL_LOCAL int  tsip_hw_lock();

WOLFSSL_LOCAL void tsip_hw_unlock( void );

WOLFSSL_LOCAL int  tsip_usable(const struct WOLFSSL *ssl,
                                uint8_t session_key_generated);

WOLFSSL_LOCAL void tsip_inform_sflash_signedcacert(
        const byte* ps_flash, 
        const byte* psigned_ca_cert,
            word32  len);

WOLFSSL_LOCAL byte tsip_rootCAverified();

WOLFSSL_LOCAL byte tsip_checkCA(word32 cmIdx);

WOLFSSL_LOCAL int  wc_tsip_tls_RootCertVerify(
        const   byte* cert,   word32 cert_len,
        word32  key_n_start,  word32 key_n_len,
        word32  key_e_start,  word32 key_e_len,
        word32  cm_row);

WOLFSSL_LOCAL int  wc_tsip_tls_CertVerify(
        const   uint8_t* cert,      uint32_t certSz,
        const   uint8_t* signature, uint32_t sigSz,
        uint32_t  key_n_start,      uint32_t key_n_len,
        uint32_t  key_e_start,      uint32_t key_e_len,
        uint8_t*  tsip_encRsaKeyIdx);

WOLFSSL_LOCAL int  wc_tsip_generatePremasterSecret(
        byte*   premaster,
        word32  preSz);

WOLFSSL_LOCAL int  wc_tsip_generateSessionKey(
        struct WOLFSSL* ssl,
        TsipUserCtx*    ctx,
        int             devId);




#if defined(WOLFSSL_RENESAS_TSIP_CRYPT_DEBUG)
byte *ret2err(word32 ret);

#endif

#ifdef __cplusplus
}
#endif

#endif  /* !WOLFCRYPT_ONLY */
#endif  /* __RENESAS_TSIP_CRYPT_H__ */
