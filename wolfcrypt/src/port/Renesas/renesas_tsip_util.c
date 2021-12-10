/* renesas_tsip_util.c
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
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_RENESAS_TSIP)

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#include <stdio.h>


/* function pointer typedefs for TSIP SHAxx HMAC Verification  */
typedef e_tsip_err_t (*shaHmacInitFn)
        (tsip_hmac_sha_handle_t*, tsip_hmac_sha_key_index_t*);
typedef e_tsip_err_t (*shaHmacUpdateFn)
        (tsip_hmac_sha_handle_t*, uint8_t*, uint32_t);
typedef e_tsip_err_t (*shaHmacFinalFn)
        (tsip_hmac_sha_handle_t*, uint8_t*, uint32_t);

/* ./ca-cert.der.sign,  */
/* expect to have these variables defined at user application */
extern uint32_t     s_flash[];
extern uint32_t     s_inst1[R_TSIP_SINST_WORD_SIZE];
extern uint32_t     s_inst2[R_TSIP_SINST2_WORD_SIZE];


wolfSSL_Mutex       tsip_mutex;
static int          tsip_CryptHwMutexInit_ = 0;
static const byte*  ca_cert_sig;
static tsip_key_data g_user_key_info;


/* tsip only keep one encrypted ca public key */
#if defined(WOLFSSL_RENESAS_TSIP_TLS)
static uint32_t     g_encrypted_publicCA_key[R_TSIP_SINST_WORD_SIZE];

/* index of CM table. must be global since renesas_common access it. */
extern uint32_t     g_CAscm_Idx;

#endif /* WOLFSSL_RENESAS_TSIP_TLS */



static int tsip_CryptHwMutexInit(wolfSSL_Mutex* mutex) 
{
    return wc_InitMutex(mutex);
}

static int tsip_CryptHwMutexLock(wolfSSL_Mutex* mutex) 
{
    return wc_LockMutex(mutex);
}

static int tsip_CryptHwMutexUnLock(wolfSSL_Mutex* mutex)
{
    return wc_UnLockMutex(mutex);
}

#if defined(WOLFSSL_RENESAS_TSIP_TLS) && (WOLFSSL_RENESAS_TSIP_VER >=109)

static uint32_t GetTsipCipherSuite( 
                    uint8_t cipherSuiteFirst,
                    uint8_t cipherSuite)
{
    WOLFSSL_ENTER("GetTsipCipherSuite");
    uint32_t tsipCipher;

    if(cipherSuiteFirst == CIPHER_BYTE )
    {
        switch(cipherSuite){

            case TLS_RSA_WITH_AES_128_CBC_SHA: /*2F*/
                tsipCipher = R_TSIP_TLS_RSA_WITH_AES_128_CBC_SHA; /*0*/
                break;

            case TLS_RSA_WITH_AES_128_CBC_SHA256:
                tsipCipher = R_TSIP_TLS_RSA_WITH_AES_128_CBC_SHA256;
                break;

            case TLS_RSA_WITH_AES_256_CBC_SHA:
                tsipCipher = R_TSIP_TLS_RSA_WITH_AES_256_CBC_SHA;
                break;

            case TLS_RSA_WITH_AES_256_CBC_SHA256:
                tsipCipher = R_TSIP_TLS_RSA_WITH_AES_256_CBC_SHA256;
                break;

            default:
                tsipCipher = (uint32_t)WOLFSSL_TSIP_ILLEGAL_CIPHERSUITE;
                break;
        }
        WOLFSSL_LEAVE("GetTsipCipherSuite", tsipCipher);
        return tsipCipher;
    }
    else if( cipherSuiteFirst == ECC_BYTE )
    {
        tsipCipher = (uint32_t)WOLFSSL_TSIP_ILLEGAL_CIPHERSUITE;
    
        switch(cipherSuite){

            case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
                tsipCipher = R_TSIP_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
                break;

            case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                tsipCipher = R_TSIP_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
                break;

            case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
                tsipCipher = R_TSIP_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
                break;

            case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                tsipCipher = R_TSIP_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
                break;

            default:
                tsipCipher = (uint32_t)WOLFSSL_TSIP_ILLEGAL_CIPHERSUITE;
                break;
        }
    }
    else{
        tsipCipher = (uint32_t)WOLFSSL_TSIP_ILLEGAL_CIPHERSUITE;
    }

    WOLFSSL_LEAVE("GetTsipCipherSuite", tsipCipher);

    return tsipCipher;
}

/*  Attempt to get a public key exchaged with the peer in ECDHE.
 *  the public key is verified by given signature then stored into ctx.
 *  
 *  return WOLFSSL_SUCCESS on success, WOLFSSL_FAILURE on failure.
 */
static int tsip_ServerKeyExVerify(
    word32      type,       /* public key type 0:RSA2048 2:ECDSA P-256 */
    WOLFSSL*    ssl,
    const byte* sig, 
    word32      sigSz,
    void*       ctx)
{
    int     ret = WOLFSSL_FAILURE;
    byte    qx[MAX_ECC_BYTES], qy[MAX_ECC_BYTES];
    byte*   peerkey = NULL;
    word32  qxLen = sizeof(qx), qyLen = sizeof(qy);
    TsipUserCtx*   userCtx;

    WOLFSSL_ENTER("tsip_ServerKeyExVerify");

    /* sanity check */
    if (ssl == NULL || sig == NULL || ctx == NULL)
        return ret;
    
    userCtx = (TsipUserCtx*)ctx;

    /* export public peer public key */
    ret = wc_ecc_export_public_raw(ssl->peerEccKey, qx, &qxLen, qy, &qyLen);

    if (ret != 0){
        WOLFSSL_MSG("failed to export peer ecc key");
        WOLFSSL_LEAVE("tsip_ServerKeyExVerify", ret);
        return ret;
    }
    /* make peer ecc key data for SCE */
    /* 0padding(24bit) || 04(8bit) || Qx(256bit) || Qy(256bit) */
    peerkey = (byte*)XMALLOC((3 + 1 + qxLen + qyLen), NULL,
                                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (peerkey == NULL) {
        WOLFSSL_MSG("failed to malloc ecc key");
        WOLFSSL_LEAVE("tsip_ServerKeyExVerify", ret);
        return WOLFSSL_FAILURE;
    }
    
    XMEMSET(peerkey, 0, (3 + 1 + qxLen + qyLen));
    peerkey[3] = ECC_POINT_UNCOMP;
    XMEMCPY(&peerkey[4], qx, qxLen);
    XMEMCPY(&peerkey[4+qxLen], qy, qyLen);
    
    /* 0 : RSA 2048bit, 1 : Reserved, 2 : ECDSA P-256 */
    if ((ret = tsip_hw_lock()) == 0) {
        ret = R_TSIP_TlsServersEphemeralEcdhPublicKeyRetrieves(
            type,
            (uint8_t*) ssl->arrays->clientRandom,
            (uint8_t*) ssl->arrays->serverRandom,
            (uint8_t*) peerkey,
            (uint8_t*) sig,
            (uint32_t*)ssl->peerSceTsipEncRsaKeyIndex,
            (uint32_t*)userCtx->encrypted_ephemeral_ecdh_public_key);
    
        if (ret !=TSIP_SUCCESS) {
            WOLFSSL_MSG("R_TSIP_TlsServersEphemeralEcdhPublicKeyRetrieves failed");
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }
    
        tsip_hw_unlock();
    }
    else {
        WOLFSSL_MSG("Failed to lock tsip hw");
    }

    XFREE(peerkey, 0, DYNAMIC_TYPE_TMP_BUFFER);

    WOLFSSL_LEAVE("tsip_ServerKeyExVerify", ret);
    return ret;
}
/*
 *  return 0 on success
 */
int wc_tsip_RsaVerify(
        WOLFSSL* ssl,
        byte* sig,      word32 sigSz,
        byte** out,
        const byte* key,
        word32 keySz,
        void* ctx)
{
    int ret;
    
    WOLFSSL_ENTER("tsip_RsaVerify");
    
    if (tsip_usable(ssl, 0))
        ret = tsip_ServerKeyExVerify(0, ssl, sig, sigSz, ctx);
    else
        ret = CRYPTOCB_UNAVAILABLE;

    if (ret == WOLFSSL_SUCCESS)
        ret = 0;

    WOLFSSL_LEAVE("tsip_RsaVerify", ret);
    return ret;
}
/*
 *  return 0 on success
 */
int wc_tsip_EccVerify(
        WOLFSSL*  ssl, 
        const byte* sig,    word32  sigSz,
        const byte* hash,   word32  hashSz,
        const byte* key,    word32  keySz,
              int*  result, void*   ctx)
{
    int         ret = WOLFSSL_FAILURE;
    uint8_t*    sigforSCE;
    uint8_t*    pSig;
    const byte  rs_size = R_TSIP_ECDSA_DATA_BYTE_SIZE/2;
    byte        offset = 0x3;
    
    WOLFSSL_ENTER("wc_tsip_EccVerify");
  
    /* check if TSIP can handle given cipher suite */ 
    if (!tsip_usable(ssl, 0)) {
        WOLFSSL_MSG("Cannot handle cipher suite by TSIP");
        WOLFSSL_LEAVE("wc_tsip_EccVerify", CRYPTOCB_UNAVAILABLE);
        return CRYPTOCB_UNAVAILABLE;
    }

    sigforSCE = (uint8_t*)XMALLOC(R_TSIP_ECDSA_DATA_BYTE_SIZE, NULL, 
                                            DYNAMIC_TYPE_TMP_BUFFER);

    if (sigforSCE == NULL) {
        WOLFSSL_MSG("failed to malloc memory");
        WOLFSSL_LEAVE("wc_tsip_EccVerify", MEMORY_E);
        return MEMORY_E;        
    }

    /* initialization */
    XMEMCPY(sigforSCE, 0, R_TSIP_ECDSA_DATA_BYTE_SIZE);
    
    /* r */
    if (sig[offset] == 0x20) {
        XMEMCPY(sigforSCE, &sig[offset+1], rs_size);
        
        offset = 0x25;
        /* s */
        if (sig[offset] == 0x20) {
          XMEMCPY(&sigforSCE[rs_size], &sig[offset+1], rs_size);
        }
        else {
          XMEMCPY(&sigforSCE[rs_size], &sig[offset+2], rs_size);
        }
    }
    else {
        XMEMCPY(sigforSCE, &sig[offset+2], rs_size);
        
        offset = 0x26;
        /* s */
        if (sig[offset] == rs_size) {
          XMEMCPY(&sigforSCE[rs_size], &sig[offset+1], rs_size);
        }
        else {
          XMEMCPY(&sigforSCE[rs_size], &sig[offset+2], rs_size);
        }
    }
    
    pSig = sigforSCE;
    
    ret = tsip_ServerKeyExVerify(2, ssl, pSig, 64, ctx);
       
    if (ret == WOLFSSL_SUCCESS) {
        *result = 1;
        ret = 0; /* for success */
    }
    else
        *result = 0;
    
    WOLFSSL_LEAVE("wc_tsip_EccVerify", ret);
    return ret;
}

/*
 *  generate premaster secret
 *  1. generate P256 ECC key pair for ECDHE key exchange
 *  2. generate pre-master secret 
 *  output 64 bytes premaster secret to "out" buffer.
 */
int wc_tsip_EccSharedSecret(
    struct WOLFSSL* ssl,
    ecc_key* otherKey,
    unsigned char* pubKeyDer,   unsigned int* pubKeySz,
    unsigned char* out,         unsigned int* outlen,
    int side, void* ctx)
{
    int       ret;
    TsipUserCtx* usrCtx = (TsipUserCtx*)ctx;
    
    (void)ssl;
    (void)otherKey;

    WOLFSSL_ENTER("wc_tsip_EccSharedSecret");
    /* sanity check */
    if (ssl == NULL || pubKeyDer == NULL || pubKeySz == NULL ||
        out == NULL || outlen == NULL || ctx == NULL) {
        WOLFSSL_LEAVE("wc_tsip_EccSharedSecret", WOLFSSL_FAILURE);
        return WOLFSSL_FAILURE;
    }
    if ((ret = tsip_hw_lock()) == 0) {
        /* Generate ECC public key for key exchange */
        ret = R_TSIP_GenerateTlsP256EccKeyIndex(
                    &usrCtx->ecc_p256_wrapped_key,
                    (uint8_t*)&usrCtx->ecc_ecdh_public_key);
        
        if (ret == TSIP_SUCCESS) {
    
            /* copy generated ecdh public key into buffer */
            pubKeyDer[0] = ECC_POINT_UNCOMP;
            *pubKeySz = 1 + sizeof(usrCtx->ecc_ecdh_public_key);
            XMEMCPY(&pubKeyDer[1], &usrCtx->ecc_ecdh_public_key, 
                        sizeof(usrCtx->ecc_ecdh_public_key));
            
            /* Generate Premaster Secret */
            ret = R_TSIP_TlsGeneratePreMasterSecretWithEccP256Key(
                        (uint32_t*)&usrCtx->encrypted_ephemeral_ecdh_public_key,
                        &usrCtx->ecc_p256_wrapped_key,
                        (uint32_t*)out/* pre-master secret 64 bytes */);
        }
        if (ret == TSIP_SUCCESS) {
            *outlen = 64;
            wolfSSL_CTX_SetGenMasterSecretCb(ssl->ctx, 
                                                Renesas_cmn_genMasterSecret);
            wolfSSL_SetGenMasterSecretCtx(ssl, usrCtx);
             
        }

        tsip_hw_unlock();
    }
    else {
        WOLFSSL_MSG("Failed to lock tsip hw");
    }
    WOLFSSL_LEAVE("wc_tsip_EccSharedSecret", ret);
    return ret;
}


WOLFSSL_API void tsip_set_callbacks(struct WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("tsip_set_callbacks");
    wolfSSL_CTX_SetEccVerifyCb(ctx, (CallbackEccVerify)Renesas_cmn_EccVerify);
    wolfSSL_CTX_SetRsaVerifyCb(ctx, (CallbackRsaVerify)Renesas_cmn_RsaVerify);
    wolfSSL_CTX_SetGenPreMasterCb(ctx, Renesas_cmn_generatePremasterSecret);
    wolfSSL_CTX_SetRsaEncCb(ctx, Renesas_cmn_RsaEnc);
    wolfSSL_CTX_SetVerifyMacCb(ctx, (CallbackVerifyMac)Renesas_cmn_VerifyHmac);
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, NULL);
    WOLFSSL_LEAVE("tsip_set_callbacks", 0);
}

WOLFSSL_API int tsip_set_callback_ctx(struct WOLFSSL* ssl, void* user_ctx)
{
    WOLFSSL_ENTER("tsip_set_callback_ctx");

    TsipUserCtx* uCtx = (TsipUserCtx*)user_ctx;
    if (user_ctx == NULL) {
        WOLFSSL_LEAVE("tsip_set_callback_ctx", 0);
        return 0;
    }
    XMEMSET( uCtx, 0, sizeof(TsipUserCtx));
   
    wolfSSL_SetEccVerifyCtx(ssl, user_ctx);
    wolfSSL_SetRsaEncCtx(ssl, user_ctx);
    wolfSSL_SetRsaVerifyCtx(ssl, user_ctx);
    wolfSSL_SetGenPreMasterCtx(ssl, user_ctx);
    wolfSSL_SetEccSharedSecretCtx(ssl, NULL);
    wolfSSL_SetVerifyMacCtx(ssl, user_ctx);
    
    /* set up crypt callback */
    wc_CryptoCb_CryptInitRenesasCmn(ssl, user_ctx);
    WOLFSSL_LEAVE("tsip_set_callback_ctx", 0);
    return 0;
}

#elif defined(WOLFSSL_RENESAS_TSIP_TLS) && (WOLFSSL_RENESAS_TSIP_VER >=106) 

/* convert def to tsip define */
static byte _tls2tsipdef(byte cipher)
{
    byte def = R_TSIP_TLS_RSA_WITH_AES_128_CBC_SHA;
    switch(cipher){
        case l_TLS_RSA_WITH_AES_128_CBC_SHA:
            break;
        case l_TLS_RSA_WITH_AES_128_CBC_SHA256:
            def = R_TSIP_TLS_RSA_WITH_AES_128_CBC_SHA256;
            break;
        case l_TLS_RSA_WITH_AES_256_CBC_SHA:
            def = R_TSIP_TLS_RSA_WITH_AES_256_CBC_SHA;
            break;
        case l_TLS_RSA_WITH_AES_256_CBC_SHA256:
            def = R_TSIP_TLS_RSA_WITH_AES_256_CBC_SHA256;
            break;
        default:break;
    }
    return def;
}
#endif
/*
* lock hw engine.
* this should be called before using engine.
*/
WOLFSSL_LOCAL int tsip_hw_lock()
{
    int ret = 0;

    if (tsip_CryptHwMutexInit_ == 0) {
      
        ret = tsip_CryptHwMutexInit(&tsip_mutex);
      
        if (ret == 0) {
            tsip_CryptHwMutexInit_ = 1;
        }
        else {
            WOLFSSL_MSG(" mutex initialization failed.");
            return -1;
        }
    }
    if (tsip_CryptHwMutexLock(&tsip_mutex) != 0) {
        /* this should not happens */
        return -1;
    }
 
    return ret;
}

/*
* release hw engine
*/
WOLFSSL_LOCAL void tsip_hw_unlock( void )
{
    tsip_CryptHwMutexUnLock(&tsip_mutex);
}

/* check if tsip tls functions can be used for the cipher      */
/* return  :1 when tsip can be used , 0 not be used.           */
int tsip_usable(const struct WOLFSSL *ssl, uint8_t session_key_generated)
{
    byte cipher0 = ssl->options.cipherSuite0;
    byte cipher  = ssl->options.cipherSuite;
    byte side    = ssl->options.side;
    int  ret     = WOLFSSL_SUCCESS;
    const Ciphers *enc;
    const Ciphers *dec;

    WOLFSSL_ENTER("tsip_usable"); 
    
    /* sanity check */
    if (ssl == NULL) {
        WOLFSSL_MSG( "ssl is NULL");
        ret = BAD_FUNC_ARG;
    }
    
    /* when rsa key index == NULL, tsip isn't used for cert verification. */
    /* in the case, we cannot use TSIP.                                   */
    if (ret == WOLFSSL_SUCCESS) {
        if (!ssl->peerSceTsipEncRsaKeyIndex) {
            WOLFSSL_MSG( "ssl->peerSceTsipEncRsaKeyIndex is NULL");
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (session_key_generated) {
            enc = &ssl->encrypt;
            dec = &ssl->decrypt;
            if (enc == NULL || dec == NULL) {
                /* something wrong */
                ret = WOLFSSL_FAILURE;
            }
            if (enc->aes == NULL || dec->aes == NULL) {
                ret = WOLFSSL_FAILURE;
            }
            if (enc->aes->ctx.setup == 0) {
                /* session key for SCE is not created */
                ret = WOLFSSL_FAILURE;
            }
        }
    }

    /* when enabled Extended Master Secret, we cannot use TSIP.           */
    
    if (ret == WOLFSSL_SUCCESS) {
        if (ssl->options.haveEMS) {
            WOLFSSL_MSG( "ssl->options.haveEMS");
            ret = WOLFSSL_FAILURE;
        }
    }
    /* TSIP works only for TLS client */
    if (ret == WOLFSSL_SUCCESS) {
        if (side != WOLFSSL_CLIENT_END) {
            WOLFSSL_MSG( "Not client side");
            ret = WOLFSSL_FAILURE;
        }
    }
    /* Check if TSIP can handle cipher suite */
    if (ret == WOLFSSL_SUCCESS) {
        if (
            cipher0 == CIPHER_BYTE &&
            (cipher == l_TLS_RSA_WITH_AES_128_CBC_SHA ||
            cipher == l_TLS_RSA_WITH_AES_128_CBC_SHA256 ||
            cipher == l_TLS_RSA_WITH_AES_256_CBC_SHA ||
            cipher == l_TLS_RSA_WITH_AES_256_CBC_SHA256)
            # if (WOLFSSL_RENESAS_TSIP_VER >= TSIP109)
            ||
            cipher0 == ECC_BYTE &&
            (cipher == l_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ||
            cipher == l_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
            cipher == l_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
            cipher == l_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)   
            #endif
        ) {
            WOLFSSL_MSG("supported cipher suite"); 
        }
        else {
            WOLFSSL_MSG("unsupported cipher suite");
            ret = WOLFSSL_FAILURE;;
        }
    }

    WOLFSSL_LEAVE("tsip_usable", ret);
    return ret;
}



/* open TSIP driver
 * return 0 on success.
 */
WOLFSSL_LOCAL int tsip_Open()
{
    int ret = TSIP_SUCCESS;

    WOLFSSL_ENTER("tsip_Open"); 

    if ((ret = tsip_hw_lock()) == 0) {
    
#if defined(WOLFSSL_RENESAS_TSIP_TLS) && (WOLFSSL_RENESAS_TSIP_VER>=109)

        ret = R_TSIP_Open(NULL,NULL);
        if ( ret != TSIP_SUCCESS ) {
            WOLFSSL_MSG("RENESAS TSIP Open failed");
        }

        if (ret == TSIP_SUCCESS && g_user_key_info.encrypted_user_tls_key) {

            ret = R_TSIP_GenerateTlsRsaPublicKeyIndex(
                    g_user_key_info.encrypted_provisioning_key,
                    g_user_key_info.iv,
                    g_user_key_info.encrypted_user_tls_key,
                    &g_user_key_info.user_rsa2048_tls_pubindex); /* OUT */

            R_TSIP_Close();       /* close once */

            if (ret != TSIP_SUCCESS){            

                WOLFSSL_MSG("R_TSIP_GenerataeTlsRsa: NG" );

            }
            else {                
                
                /* open again with newly created TLS public key index*/
                ret = R_TSIP_Open(
                        &g_user_key_info.user_rsa2048_tls_pubindex,
                        (tsip_update_key_ring_t*)s_inst2);

                if (ret != TSIP_SUCCESS) {
                    WOLFSSL_MSG("R_TSIP_(Re)Open: NG");
                }
                    /* init vars */
                g_CAscm_Idx = (uint32_t)-1;
            }
        }

#elif defined(WOLFSSL_RENESAS_TSIP_TLS) && (WOLFSSL_RENESAS_TSIP_VER>=106)

        ret = R_TSIP_Open((uint32_t*)s_flash, s_inst1, s_inst2);
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG("RENESAS TSIP Open failed");
        }
        
        /* generate TLS Rsa public key for Certificate verification */
        if (ret == TSIP_SUCCESS && g_user_key_info.encrypted_user_tls_key) {
            ret = R_TSIP_GenerateTlsRsaPublicKeyIndex(
                    g_user_key_info.encrypted_session_key,
                    g_user_key_info.iv,
                    g_user_key_info.encrypted_user_tls_key,
                    &g_user_key_info.user_rsa2048_tls_pubindex);
            
            if (ret != TSIP_SUCCESS) {
                WOLFSSL_MSG("R_TSIP_GenerateTlsRsaPublicKeyIndex failed");
            }
            else {
                /* close once */
                tsip_Close( );
                /* open again with s_inst[] */
                XMEMCPY(s_inst1, 
                    g_user_key_info.user_rsa2048_tls_pubindex.value,
                    sizeof(s_inst1));
                ret = R_TSIP_Open((uint32_t*)s_flash, s_inst1, s_inst2);
                if (ret != TSIP_SUCCESS) {
                    WOLFSSL_MSG("R_TSIP_(Re)Open failed");
                }
                 /* init vars */
                g_CAscm_Idx = (uint32_t)-1;
            }
        }
#else
        ret = R_TSIP_Open((uint32_t*)s_flash, s_inst1, s_inst2);
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG("RENESAS TSIP Open failed");
        }
#endif
        /* unlock hw */
        tsip_hw_unlock();
    }
    else 
        WOLFSSL_MSG("Failed to lock tsip hw ");
    
    WOLFSSL_LEAVE( "tsip_Open", ret);
    return ret;
}

/* close TSIP driver */
WOLFSSL_LOCAL void tsip_Close()
{
    WOLFSSL_ENTER("tsip_Close");
    int ret;
    
    if ((ret = tsip_hw_lock()) == 0) {
        /* close TSIP */
        ret = R_TSIP_Close();
#if defined(WOLFSSL_RENESAS_TSIP_TLS)
        g_CAscm_Idx = (uint32_t)-1;
#endif
        /* unlock hw */
        tsip_hw_unlock();
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG("RENESAS TSIP Close failed");
        }
    } 
    else
        WOLFSSL_MSG("Failed to unlock tsip hw ");
    WOLFSSL_LEAVE("tsip_Close", 0);
}

/* Support functions for TSIP TLS Capability */
#if defined(WOLFSSL_RENESAS_TSIP_TLS)

/* to inform ca certificate sign */
/* signature format expects RSA 2048 PSS with SHA256 */
void tsip_inform_cert_sign(const byte *sign)
{
    if(sign)
        ca_cert_sig = sign;
}
#if (WOLFSSL_RENESAS_TSIP_VER>=109)
void tsip_inform_user_keys_ex(
    byte*     encrypted_provisioning_key,
    byte*     iv,
    byte*     encrypted_user_tls_key,
    word32    encrypted_user_tls_key_type)
{
    WOLFSSL_ENTER("tsip_inform_user_keys_ex");
    g_user_key_info.encrypted_provisioning_key = NULL;
    g_user_key_info.iv = NULL;
    
    if ( encrypted_provisioning_key ) {
        g_user_key_info.encrypted_provisioning_key = encrypted_provisioning_key;
    }
    if ( iv ) {
        g_user_key_info.iv = iv;
    }
    if ( encrypted_user_tls_key ) {
        g_user_key_info.encrypted_user_tls_key = encrypted_user_tls_key;
    }
    
    g_user_key_info.encrypted_user_tls_key_type = encrypted_user_tls_key_type;
    WOLFSSL_LEAVE("tsip_inform_user_keys_ex", 0);
}
#elif (WOLFSSL_RENESAS_TSIP_VER>=106)
/* inform user key                                                     */
/* the function expects to be called from user application             */
/* user has to create these key information by Renesas tool in advance.*/
void tsip_inform_user_keys(
    byte *encrypted_session_key,
    byte *iv,
    byte *encrypted_user_tls_key)
{
    g_user_key_info.encrypted_session_key = NULL;
    g_user_key_info.iv = NULL;
    g_user_key_info.encrypted_user_tls_key = NULL;
    
    if ( encrypted_session_key ) {
        g_user_key_info.encrypted_session_key = encrypted_session_key;
    }
    if ( iv ) {
        g_user_key_info.iv = iv;
    }
    if ( encrypted_user_tls_key ) {
        g_user_key_info.encrypted_user_tls_key = encrypted_user_tls_key;
    }
}
#endif



/* Sha1Hmac */
int wc_tsip_Sha1HmacGenerate(
        const struct WOLFSSL *ssl,
        const byte* myInner, 
        word32      innerSz,
        const byte* in,
        word32      sz, 
        byte*       digest)
{
    WOLFSSL_ENTER("wc_tsip_Sha1HmacGenerate()");

    tsip_hmac_sha_handle_t _handle;
    tsip_hmac_sha_key_index_t key_index;
    int ret;

    if ((ssl == NULL) || (myInner == NULL) || (in == NULL) ||
        (digest == NULL)){
        WOLFSSL_LEAVE("wc_tsip_Sha1HmacGenerate", BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }
    
    if ((ret = tsip_hw_lock()) != 0) {
        WOLFSSL_MSG("hw lock failed");
        WOLFSSL_LEAVE("wc_tsip_Sha1HmacGenerate", ret);
        return ret;
    }
    
    key_index = ssl->keys.tsip_client_write_MAC_secret;
       
    ret = R_TSIP_Sha1HmacGenerateInit(
                    &_handle,
                    &key_index);
    
    if (ret == TSIP_SUCCESS)
        ret = R_TSIP_Sha1HmacGenerateUpdate(
                    &_handle,
                    (uint8_t*)myInner, 
                    (uint32_t)innerSz);
    
    if (ret == TSIP_SUCCESS)
        ret = R_TSIP_Sha1HmacGenerateUpdate(
                    &_handle,
                    (uint8_t*)in,
                    sz);
    
    if (ret == TSIP_SUCCESS)
        ret = R_TSIP_Sha1HmacGenerateFinal(
                    &_handle,
                    digest);
       
    tsip_hw_unlock();

    WOLFSSL_LEAVE("wc_tsip_Sha1HmacGenerate", ret);
    return ret;
}


/* Sha256Hmac */
int wc_tsip_Sha256HmacGenerate(
        const struct WOLFSSL *ssl,
        const byte* myInner, 
        word32      innerSz,
        const byte* in,
        word32      sz,
        byte*       digest)
{
    WOLFSSL_ENTER("wc_tsip_Sha256HmacGenerate");

    tsip_hmac_sha_handle_t _handle;
    tsip_hmac_sha_key_index_t key_index;
    int ret;
    
    if ((ssl == NULL) || (myInner == NULL) || (in == NULL) ||
        (digest == NULL))
      return BAD_FUNC_ARG;
    
    key_index = ssl->keys.tsip_client_write_MAC_secret;

    if ((ret = tsip_hw_lock()) != 0) {
        WOLFSSL_MSG("hw lock failed");
        return ret;
    }
    
    ret = R_TSIP_Sha256HmacGenerateInit(
                &_handle,
                &key_index);
    
    if (ret == TSIP_SUCCESS) {
        ret = R_TSIP_Sha256HmacGenerateUpdate(
                &_handle,
                (uint8_t*)myInner, 
                innerSz);
    }
    else {
        WOLFSSL_MSG("R_TSIP_Sha256HmacGenerateInit failed");
    }

    if (ret == TSIP_SUCCESS) {
        ret = R_TSIP_Sha256HmacGenerateUpdate(
                &_handle,
                (uint8_t*)in,
                sz);
    }
    else {
        WOLFSSL_MSG("R_TSIP_Sha256HmacGenerateUpdate: inner failed");
    }
    if (ret == TSIP_SUCCESS) {

        ret = R_TSIP_Sha256HmacGenerateFinal(
                &_handle,
                digest);
    }
    else {
        WOLFSSL_MSG("R_TSIP_Sha256HmacGenerateUpdate: in failed");
    }
    if (ret != TSIP_SUCCESS) {
        WOLFSSL_MSG("R_TSIP_Sha256HmacGenerateFinal failed");
        ret = 1;
    }
    /* unlock hw */
    tsip_hw_unlock();
    WOLFSSL_LEAVE("wc_tsip_Sha256HmacGenerate", ret);
    return ret;
}
/*
 *  Perform SHA1 and SHA256 Hmac verification
 */
int wc_tsip_ShaXHmacVerify(
        const struct WOLFSSL *ssl,
        const byte* message, 
        word32      messageSz,
        word32      macSz,
        word32      content)
{
    WOLFSSL_ENTER("tsip_ShaXHmacVerify");

    tsip_hmac_sha_handle_t    handle;
    tsip_hmac_sha_key_index_t wrapped_key;

    shaHmacInitFn   initFn   = NULL;
    shaHmacUpdateFn updateFn = NULL;
    shaHmacFinalFn  finalFn  = NULL;

    byte   myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    int ret;

    if ((ssl == NULL) || (message == NULL)){
        WOLFSSL_LEAVE("tsip_ShaXHmacVerify", BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }
    wrapped_key = ssl->keys.tsip_server_write_MAC_secret;

    if (wrapped_key.type == TSIP_KEY_INDEX_TYPE_HMAC_SHA1_FOR_TLS) {
        WOLFSSL_MSG("perform Sha1-Hmac verification");
        initFn   = R_TSIP_Sha1HmacVerifyInit;
        updateFn = R_TSIP_Sha1HmacVerifyUpdate;
        finalFn  = R_TSIP_Sha1HmacVerifyFinal;
    }
    else if (wrapped_key.type == TSIP_KEY_INDEX_TYPE_HMAC_SHA256_FOR_TLS) {
        WOLFSSL_MSG("perform Sha256-Hmac verification");
        initFn   = R_TSIP_Sha256HmacVerifyInit;
        updateFn = R_TSIP_Sha256HmacVerifyUpdate;
        finalFn  = R_TSIP_Sha256HmacVerifyFinal;
    }
    else {
        WOLFSSL_MSG("unsupported key type");
        WOLFSSL_LEAVE("tsip_ShaXHmacVerify", BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }

    if ((ret = tsip_hw_lock()) != 0) {
        WOLFSSL_MSG("hw lock failed\n");
        WOLFSSL_LEAVE("tsip_ShaXHmacVerify", ret);
        return ret;
    }
    
    wolfSSL_SetTlsHmacInner((struct WOLFSSL*)ssl, (byte*)myInner,
                                                     messageSz, content, 1);
    
    ret = initFn(&handle, &wrapped_key);
    
    if (ret == TSIP_SUCCESS) {
        ret = updateFn(&handle, myInner, WOLFSSL_TLS_HMAC_INNER_SZ);
    }
    if (ret == TSIP_SUCCESS) {
        ret = updateFn(&handle, (uint8_t*)message, (uint32_t)messageSz);
    }
    if (ret == TSIP_SUCCESS) {
        ret = finalFn(&handle, (uint8_t*)(message + messageSz), (uint32_t)macSz);
    }
    if (ret != TSIP_SUCCESS) {
        WOLFSSL_MSG("TSIP Mac verification failed");
    }
    
    /* unlock hw */
    tsip_hw_unlock();
    WOLFSSL_LEAVE("tsip_ShaXHmacVerify", ret);
    return ret;
}

/* generate Verify Data based on master secret */
int wc_tsip_generateVerifyData(
    const byte* ms,                 /* master secret */
    const byte* side,               /* 0:client-side 1:server-side */
    const byte* handshake_hash,
          byte* hashes)             /* out */
{
    int ret ;
    uint32_t l_side = R_TSIP_TLS_GENERATE_CLIENT_VERIFY;

    WOLFSSL_ENTER("tsip_generateVerifyData");   
    
    if ((ms == NULL) || (side == NULL) || (handshake_hash == NULL) ||
        (hashes == NULL)) {
        WOLFSSL_LEAVE("tsip_generateVerifyData", BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }
    if (XSTRNCMP((const char*)side, (const char*)tls_server, FINISHED_LABEL_SZ)
                                                                           == 0)
    {
        l_side = R_TSIP_TLS_GENERATE_SERVER_VERIFY;
    }
    
    if ((ret = tsip_hw_lock()) == 0) {
        ret = R_TSIP_TlsGenerateVerifyData(l_side, (uint32_t*)ms,
                       (uint8_t*)handshake_hash, hashes/* out */);
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG("R_TSIP_TlsGenerateSessionKey failed");
        }
    }
    /* unlock hw */
    tsip_hw_unlock();
    WOLFSSL_LEAVE("tsip_generateVerifyData", ret);
    return ret;
}

/* generate keys for TLS communication */
int wc_tsip_generateSessionKey(
    struct WOLFSSL *ssl, 
    TsipUserCtx*    ctx,
    int             devId)
{
    int ret;
    Ciphers *enc;
    Ciphers *dec;
    tsip_hmac_sha_key_index_t key_client_mac;
    tsip_hmac_sha_key_index_t key_server_mac;
    tsip_aes_key_index_t key_client_aes;
    tsip_aes_key_index_t key_server_aes;

    WOLFSSL_ENTER("wc_tsip_generateSessionKey()");
    
    if (ssl== NULL)
      return BAD_FUNC_ARG;
      
    if ((ret = tsip_hw_lock()) == 0) {

#if (WOLFSSL_RENESAS_TSIP_VER>=109)

        uint32_t tsipCS = GetTsipCipherSuite(ssl->options.cipherSuite0,
                                             ssl->options.cipherSuite);

        if (tsipCS == R_TSIP_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
            tsipCS == R_TSIP_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
            WOLFSSL_MSG("Session key for AES-GCM generation skipped.");

            /*  Do not release ssl-> arrays to reference the master secret and 
             *  randoms, as the AES GCM session key will be generated in 
             *  encryption or decription timing.  
             */
            wolfSSL_KeepArrays(ssl);
            ret = TSIP_SUCCESS;
        }
        else {

            ret = R_TSIP_TlsGenerateSessionKey(
                    tsipCS,
                    (uint32_t*)ssl->arrays->tsip_masterSecret, 
                    (uint8_t*) ssl->arrays->clientRandom,
                    (uint8_t*) ssl->arrays->serverRandom,
                    NULL, /* nonce is required only for AES-GCM key */
                    &key_client_mac,
                    &key_server_mac,
                    &key_client_aes,
                    &key_server_aes,
                    NULL, NULL);        
        }
#else /* WOLFSSL_RENESAS_TSIP_VER < 109 */        

        ret = R_TSIP_TlsGenerateSessionKey(
                    _tls2tsipdef(ssl->options.cipherSuite),
                    (uint32_t*)ssl->arrays->tsip_masterSecret, 
                    (uint8_t*)ssl->arrays->clientRandom,
                    (uint8_t*)ssl->arrays->serverRandom,
                    &key_client_mac,
                    &key_server_mac,
                    &key_client_aes,
                    &key_server_aes,
                    NULL, NULL);
#endif                
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG("R_TSIP_TlsGenerateSessionKey failed");
        }
        else {
            /* succeeded creating session keys */
            /* alloc aes instance for both enc and dec */
            enc = &ssl->encrypt;
            dec = &ssl->decrypt;
            
            if (enc) {
                if (enc->aes == NULL) {
                    enc->aes = (Aes*)XMALLOC(sizeof(Aes), ssl->heap, 
                                                    DYNAMIC_TYPE_CIPHER);
                    if (enc->aes == NULL)
                        return MEMORY_E;
                }
                
                XMEMSET(enc->aes, 0, sizeof(Aes));
            }
            if (dec) {
                if (dec->aes == NULL) {
                    dec->aes = (Aes*)XMALLOC(sizeof(Aes), ssl->heap, 
                                                    DYNAMIC_TYPE_CIPHER);
                    if (dec->aes == NULL) {
                        if (enc) {
                            XFREE(enc->aes, NULL, DYNAMIC_TYPE_CIPHER);
                        }
                        return MEMORY_E;
                    }
                }
                
                XMEMSET(dec->aes, 0, sizeof(Aes));
            }

            /* copy key index into aes */
            if (ssl->options.side == PROVISION_CLIENT) {
                XMEMCPY(&enc->aes->ctx.tsip_keyIdx, &key_client_aes, 
                                                    sizeof(key_client_aes));
                XMEMCPY(&dec->aes->ctx.tsip_keyIdx, &key_server_aes, 
                                                    sizeof(key_server_aes));
            }
            else {
                XMEMCPY(&enc->aes->ctx.tsip_keyIdx, &key_server_aes, 
                                                    sizeof(key_server_aes));
                XMEMCPY(&dec->aes->ctx.tsip_keyIdx, &key_client_aes, 
                                                    sizeof(key_client_aes));
            }

            /* copy hac key index into keys */
            ssl->keys.tsip_client_write_MAC_secret = key_client_mac;
            ssl->keys.tsip_server_write_MAC_secret = key_server_mac;

            /* set up key size and marked ready */
            if (enc){
                enc->aes->ctx.keySize = ssl->specs.key_size;
                enc->aes->ctx.setup = 1;
                /* ready for use */
                enc->setup = 1;
            }
            /* set up key size and marked ready */
            if (dec) {
                dec->aes->ctx.keySize = ssl->specs.key_size;
                dec->aes->ctx.setup = 1;
                /* ready for use */
                dec->setup = 1;
            }

            if (ctx->tsip_cipher == 
                            R_TSIP_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
                ctx->tsip_cipher == 
                            R_TSIP_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
                enc->aes->nonceSz = AEAD_MAX_IMP_SZ;
                dec->aes->nonceSz = AEAD_MAX_IMP_SZ;
            }
            
            enc->aes->devId = devId;
            dec->aes->devId = devId;

            ctx->session_key_set = 1;
        }
        /* unlock hw */
        tsip_hw_unlock();
    }
    else 
        WOLFSSL_MSG("hw lock failed");
    
    WOLFSSL_LEAVE("wc_tsip_generateSessionKey", ret);
    return ret;
}



/* generate Master secrete by TSIP */
#if (WOLFSSL_RENESAS_TSIP_VER>=109)

int wc_tsip_generateMasterSecretEx(
        byte        cipherSuiteFirst,
        byte        cipherSuite,
        const byte *pr, /* pre-master    */
        const byte *cr, /* client random */
        const byte *sr, /* server random */
        byte *ms)
{
    int ret;

    WOLFSSL_ENTER("tsip_generateMasterSecretEx");
    
    if ((pr == NULL) || (cr == NULL) || (sr == NULL) ||
        (ms == NULL))
      return BAD_FUNC_ARG;
      
    uint32_t tsipCS = GetTsipCipherSuite(cipherSuiteFirst,cipherSuite );
    if (tsipCS == 0xffffffff)
        return BAD_FUNC_ARG;

    if ((ret = tsip_hw_lock()) == 0) {
        ret = R_TSIP_TlsGenerateMasterSecret( 
            tsipCS,
            (uint32_t*)pr,
            (uint8_t*)cr, (uint8_t*)sr, (uint32_t*)ms);
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG("R_TSIP_TlsGenerateMasterSecret failed");
        }
        /* unlock hw */
        tsip_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("tsip_generateMasterSecretEx", ret);
    return ret;
}

#else /* WOLFSSL_RENESAS_TSIP_VER < 109 */

int wc_tsip_generateMasterSecret(
        const byte* pr, /* pre-master    */
        const byte* cr, /* client random */
        const byte* sr, /* server random */
        byte*       ms)
{
    int ret;
    WOLFSSL_ENTER("tsip_generateMasterSecret");
    if ((pr == NULL) || (cr == NULL) || (sr == NULL) ||
        (ms == NULL))
      return BAD_FUNC_ARG;
      
    if ((ret = tsip_hw_lock()) == 0) {
        ret = R_TSIP_TlsGenerateMasterSecret( 
                (uint32_t*)pr,
                (uint8_t*)cr,
                (uint8_t*)sr,
                (uint32_t*)ms);

        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG("R_TSIP_TlsGenerateMasterSecret failed");
        }
        /* unlock hw */
        tsip_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("tsip_generateMasterSecret", ret);
    return ret;
}
#endif /* WOLFSSL_RENESAS_TSIP_VER */

/*  store elements for session key generation into ssl->keys.
 *  return 0 on success, negative value on failure
 */
int wc_tsip_storeKeyCtx(struct  WOLFSSL* ssl, TsipUserCtx* userCtx)
{
    int ret = 0;

    WOLFSSL_ENTER("tsip_storeKeyCtx");

    if (ssl == NULL || userCtx == NULL)
        ret = BAD_FUNC_ARG;
    
    if (ret == 0) {
        XMEMCPY(userCtx->tsip_masterSecret, ssl->arrays->tsip_masterSecret, 
                                                TSIP_TLS_MASTERSECRET_SIZE);
        XMEMCPY(userCtx->tsip_clientRandom, ssl->arrays->clientRandom,
                                                TSIP_TLS_CLIENTRANDOM_SZ);
        XMEMCPY(userCtx->tsip_serverRandom, ssl->arrays->serverRandom,
                                                TSIP_TLS_SERVERRANDOM_SZ);
        userCtx->tsip_cipher = GetTsipCipherSuite(ssl->options.cipherSuite0,
                                                ssl->options.cipherSuite);
    }

    WOLFSSL_LEAVE("tsip_storeKeyCtx", ret);
    return ret;
}

/* generate pre-Master secrete by TSIP */
int wc_tsip_generatePremasterSecret(byte *premaster, word32 preSz )
{
    WOLFSSL_ENTER("tsip_generatePremasterSecret");
    int ret;
    
    if (premaster == NULL)
      return BAD_FUNC_ARG;
    
    if ((ret = tsip_hw_lock()) == 0 && preSz >=
                                    (R_TSIP_TLS_MASTER_SECRET_WORD_SIZE*4)) {
        /* generate pre-master, 80 bytes */
        ret = R_TSIP_TlsGeneratePreMasterSecret( (uint32_t*)premaster );
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG(" R_TSIP_TlsGeneratePreMasterSecret failed");
        }
        
        /* unlock hw */
        tsip_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed or preSz is smaller than 80");
    }
    WOLFSSL_LEAVE("tsip_generatePremasterSecret", ret);
    return ret;
}

/* 
* generate encrypted pre-Master secrete by TSIP
*/
int wc_tsip_generateEncryptPreMasterSecret(
        WOLFSSL*    ssl,
        byte*       out,
        word32*     outSz)
{
    int ret;

    WOLFSSL_ENTER("tsip_generateEncryptPreMasterSecret");   
    
    if ((ssl == NULL) || (out == NULL) || (outSz == NULL))
      return BAD_FUNC_ARG;
    
    if ((ret = tsip_hw_lock()) == 0) {
        if (*outSz >= 256)
           
            #if  (WOLFSSL_RENESAS_TSIP_VER>=109)
           
            ret = R_TSIP_TlsEncryptPreMasterSecretWithRsa2048PublicKey(
                        (uint32_t*)ssl->peerSceTsipEncRsaKeyIndex,
                        (uint32_t*)ssl->arrays->preMasterSecret,
                        (uint8_t*)out);

            #else
            
            ret = R_TSIP_TlsEncryptPreMasterSecret(
                          (uint32_t*)ssl->peerSceTsipEncRsaKeyIndex,
                          (uint32_t*)ssl->arrays->preMasterSecret,
                          (uint8_t*)out);
            
            #endif
        else
            ret = -1;
            
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG(" R_TSIP_TlsEncryptPreMasterSecret failed");
        }
        else {
            *outSz = 256; /* TSIP can only handles 2048 RSA */
            void* ctx = wolfSSL_GetRsaVerifyCtx(ssl);
            wolfSSL_CTX_SetGenMasterSecretCb(ssl->ctx, 
                                                Renesas_cmn_genMasterSecret);
            wolfSSL_SetGenMasterSecretCtx(ssl, ctx);
        }
        
        tsip_hw_unlock();

    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("tsip_generateEncryptPreMasterSecret", ret);
    return ret;
}


/* Certificate verification by TSIP */
int wc_tsip_tls_CertVerify(
        const uint8_t* cert,       uint32_t certSz,
        const uint8_t* signature,  uint32_t sigSz,
        uint32_t      key_n_start, uint32_t key_n_len,
        uint32_t      key_e_start, uint32_t key_e_len,
        uint8_t*      tsip_encRsaKeyIndex)
{
    int ret;
    uint8_t *sigforSCE;
    uint8_t *pSig;
    const byte rs_size = 0x20;
    byte offset = 0x3;

    WOLFSSL_ENTER("wc_tsip_tls_CertVerify");

    if (cert == NULL)
      return BAD_FUNC_ARG;
    
    if (!signature) {
        WOLFSSL_MSG(" signature for ca verification is not set");
        return -1;
    }
    if (!tsip_encRsaKeyIndex) {
        WOLFSSL_MSG(" tsip_encRsaKeyIndex is NULL.");
        return -1;
    }
    
    /* Public key type: Prime256r1 */
    if (g_user_key_info.encrypted_user_tls_key_type == 
                                    R_TSIP_TLS_PUBLIC_KEY_TYPE_ECDSA_P256) {

        if ((sigforSCE = (uint8_t*)XMALLOC(R_TSIP_ECDSA_DATA_BYTE_SIZE,
                                        NULL, DYNAMIC_TYPE_ECC)) == NULL) {
            WOLFSSL_MSG("failed to malloc memory");
            return MEMORY_E;
        }
        /* initialization */
        XMEMCPY(sigforSCE, 0, R_TSIP_ECDSA_DATA_BYTE_SIZE);
        
        if (signature[offset] == 0x20) {
            XMEMCPY(sigforSCE, &signature[offset+1], rs_size);
            
            offset = 0x25;
            if (signature[offset] == 0x20) {
                XMEMCPY(&sigforSCE[rs_size], &signature[offset+1], rs_size);
            }
            else {
                XMEMCPY(&sigforSCE[rs_size], &signature[offset+2], rs_size);
            }
        } 
        else {
            XMEMCPY(sigforSCE, &signature[offset+2], rs_size);
            offset = 0x26;
         
            if (signature[offset] == rs_size) {
                XMEMCPY(&sigforSCE[rs_size], &signature[offset+1], rs_size);
            } 
            else {
                XMEMCPY(&sigforSCE[rs_size], &signature[offset+2], rs_size);
            }
        }
        pSig = sigforSCE;
    }
    /* Public key type: RSA 2048bit */
    else {
        pSig = (uint8_t*)signature;
    }

    if ((ret = tsip_hw_lock()) == 0) {

        #if (WOLFSSL_RENESAS_TSIP_VER>=109)

         ret = R_TSIP_TlsCertificateVerification(
                g_user_key_info.encrypted_user_tls_key_type,
                (uint32_t*)g_encrypted_publicCA_key,/* encrypted public key  */
                (uint8_t*)cert,                    /* certificate der        */
                certSz,                            /* length of der          */
                (uint8_t*)pSig,                    /* sign data by RSA PSS   */
                key_n_start,  /* start position of public key n in bytes     */
                (key_n_start + key_n_len),     /* length of the public key n */
                key_e_start,                   /* start pos, key e in bytes  */
                (key_e_start + key_e_len),     /* length of the public key e */
                (uint32_t*)tsip_encRsaKeyIndex /* returned encrypted key     */
                );

        #elif (WOLFSSL_RENESAS_TSIP_VER>=106)

        ret = R_TSIP_TlsCertificateVerification(
                (uint32_t*)g_encrypted_publicCA_key,/* encrypted public key  */
                (uint8_t*)cert,                    /* certificate der        */
                certSz,                            /* length of der          */
                (uint8_t*)pSig,                    /* sign data by RSA PSS   */
                key_n_start,  /* start position of public key n in bytes     */
                (key_n_start + key_n_len),     /* length of the public key n */
                key_e_start,                   /* start pos, key e in bytes  */
                (key_e_start + key_e_len),     /* length of the public key e */
                (uint32_t*)tsip_encRsaKeyIndex /* returned encrypted key     */
                );
        #endif

        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG(" R_TSIP_TlsCertificateVerification() failed");
        }
        if (sigforSCE) {
            XFREE(sigforSCE, NULL, DYNAMIC_TYPE_ECC);
        }
        tsip_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("wc_tsip_tls_CertVerify", ret);
    return ret;
}
/* Root Certificate verification */
int wc_tsip_tls_RootCertVerify(
        const byte* cert,           word32 cert_len,
        word32      key_n_start,    word32 key_n_len,
        word32      key_e_start,    word32 key_e_len,
        word32      cm_row)
{
    int ret;
    /* call to generate encrypted public key for certificate verification */
    uint8_t *signature = (uint8_t*)ca_cert_sig;

    WOLFSSL_ENTER("wc_tsip_tls_RootCertVerify");   
    
    if (cert == NULL)
      return BAD_FUNC_ARG;
      
    if (!signature) {
        WOLFSSL_MSG(" signature for ca verification is not set");
        return -1;
    }
    
    if ((ret = tsip_hw_lock()) == 0) {

        #if (WOLFSSL_RENESAS_TSIP_VER>=109)

        ret = R_TSIP_TlsRootCertificateVerification(
                g_user_key_info.encrypted_user_tls_key_type,            
                (uint8_t*)cert,             /* CA cert */            
                (uint32_t)cert_len,         /* length of CA cert */            
                key_n_start,                /* Byte position of public key */
                (key_n_start + key_n_len),
                key_e_start,
                (key_e_start + key_e_len),
                (uint8_t*)ca_cert_sig,      /* "RSA 2048 PSS with SHA256" */
                g_encrypted_publicCA_key);  /* RSA-2048 public key 560 bytes */

        #else /* WOLFSSL_RENESAS_TSIP_VER < 109 */

        ret = R_TSIP_TlsRootCertificateVerification(                         
                (uint8_t*)cert,/* CA cert */
                (uint32_t)cert_len,/* length of CA cert */
                key_n_start, /* Byte position of public key */
                (key_n_start + key_n_len),
                key_e_start,
                (key_e_start + key_e_len),
                (uint8_t*)ca_cert_sig,/* "RSA 2048 PSS with SHA256" */
                /* RSA-2048 public key used by
                    RSA-2048 PSS with SHA256. 560 Bytes*/
                g_encrypted_publicCA_key );
        
        #endif
        
        if (ret != TSIP_SUCCESS) {
            WOLFSSL_MSG(" R_TSIP_TlsRootCertificateVerification() failed");
        }
        else {
            g_CAscm_Idx = cm_row;
        }
        
        tsip_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("wc_tsip_tls_RootCertVerify", ret);
    return ret;
}
#endif /* WOLFSSL_RENESAS_TSIP_TLS */

#ifdef WOLFSSL_RENESAS_TSIP_CRYPT_DEBUG

/* err
 * e_tsip_err
    TSIP_SUCCESS = 0, 
    TSIP_ERR_SELF_CHECK1,  // Self-check 1 fail or TSIP function internal err.
    TSIP_ERR_RESOURCE_CONFLICT, // A resource conflict occurred.
    TSIP_ERR_SELF_CHECK2,       // Self-check 2 fail.
    TSIP_ERR_KEY_SET,           // setting the invalid key.
    TSIP_ERR_AUTHENTICATION,    // Authentication failed.
    TSIP_ERR_CALLBACK_UNREGIST, // Callback function is not registered.
    TSIP_ERR_PARAMETER,         // Illegal Input data.
    TSIP_ERR_PROHIBIT_FUNCTION, // An invalid function call occurred.
 *  TSIP_RESUME_FIRMWARE_GENERATE_MAC,  
                  // There is a continuation of R_TSIP_GenerateFirmwareMAC.
*/

static void hexdump(const uint8_t* in, uint32_t len)
{
    uint32_t i;

    if (in == NULL)
        return;

    for (i = 0; i <= len;i++, in++){
        printf("%02x:", *in);
        if (((i+1)%16)==0){
            printf("\n");
        }
    }
    printf("\n");
}

byte *ret2err(word32 ret)
{
    switch(ret){
        case TSIP_SUCCESS:     return "success";
        case TSIP_ERR_SELF_CHECK1: return "selfcheck1";
        case TSIP_ERR_RESOURCE_CONFLICT: return "rsconflict";
        case TSIP_ERR_SELF_CHECK2: return "selfcheck2";
        case TSIP_ERR_KEY_SET: return "keyset";
        case TSIP_ERR_AUTHENTICATION: return "authentication";
        case TSIP_ERR_CALLBACK_UNREGIST: return "callback unreg";
        case TSIP_ERR_PARAMETER: return "badarg";
        case TSIP_ERR_PROHIBIT_FUNCTION: return "prohibitfunc";
        case TSIP_RESUME_FIRMWARE_GENERATE_MAC: return "conti-generate-mac";
        default:return "unknown";
    }
}

#endif /* WOLFSSL_RENESAS_TSIP_CRYPT_DEBUG */
#endif /* WOLFSSL_RENESAS_TSIP */
