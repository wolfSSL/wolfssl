/* renesas_fspsm_util.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_RENESAS_RSIP) || \
    defined(WOLFSSL_RENESAS_SCEPROTECT)

#include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-types.h>

/* expect to have these variables defined at user application */
extern FSPSM_INSTANCE   gFSPSM_ctrl;
extern FSPSM_CONFIG     gFSPSM_cfg;

#if defined(WOLFSSL_RENESAS_FSPSM)

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-crypt.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#include <stdio.h>

#if defined(DEBUG_PK_CB)
    #define WOLFSSL_PKMSG(_f_, ...) printf(_f_, ##__VA_ARGS__)
#else
    #define WOLFSSL_PKMSG(_f_, ...) WC_DO_NOTHING
#endif

#if defined(WOLFSSL_RENESAS_FSPSM_ECC)
WOLFSSL_GLOBAL FSPSM_ST_PKC gPKCbInfo;
#endif


#ifdef WOLFSSL_RENESAS_FSPSM_TLS
static const byte*  ca_cert_sig;
static fspsm_key_data g_user_key_info;

static uint32_t     g_encrypted_publicCA_key[HW_SCE_SINST_WORD_SIZE];
extern uint32_t     g_CAscm_Idx;          /* index of CM table    */
static uint32_t     fspsm_sess_idx = 0;
#endif

#endif /* WOLFSSL_RENESAS_FSPSM*/

wolfSSL_Mutex       fspsm_mutex;
static int          fspsm_CryptHwMutexInit_ = 0;


/* Mutex Init */
static int fspsm_CryptHwMutexInit(wolfSSL_Mutex* mutex)
{
    return wc_InitMutex(mutex);
}
/* Mutex Lock */
static int fspsm_CryptHwMutexLock(wolfSSL_Mutex* mutex)
{
    return wc_LockMutex(mutex);
}
/* Mutex Unlock */
static int fspsm_CryptHwMutexUnLock(wolfSSL_Mutex* mutex)
{
    return wc_UnLockMutex(mutex);
}

/*
* lock hw engine
* this should be called before using engine.
*/
WOLFSSL_LOCAL int wc_fspsm_hw_lock()
{
    int ret = 0;

    if (fspsm_CryptHwMutexInit_ == 0) {

        ret = fspsm_CryptHwMutexInit(&fspsm_mutex);

        if (ret == 0) {
            fspsm_CryptHwMutexInit_ = 1;
        }
        else {
            WOLFSSL_MSG(" mutex initialization failed.");
            return -1;
        }
    }
    if (fspsm_CryptHwMutexLock(&fspsm_mutex) != 0) {
        /* this should not happens */
        return -1;
    }

    return ret;
}

/*
* release hw engine
*/
WOLFSSL_LOCAL void wc_fspsm_hw_unlock(void)
{
    fspsm_CryptHwMutexUnLock(&fspsm_mutex);
}

/* Open sce driver for use */
WOLFSSL_LOCAL int wc_fspsm_Open()
{
    WOLFSSL_ENTER("wc_fspsm_Open");
    int ret;
    if ((ret = wc_fspsm_hw_lock()) == 0) {

        ret = FSPSM_OPEN(&gFSPSM_ctrl, &gFSPSM_cfg);

        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG("RENESAS SCE Open failed");
        }

    #if defined(WOLFSSL_RENESAS_FSPSM_TLS)
        if (ret == FSP_SUCCESS && g_user_key_info.encrypted_user_tls_key) {

            ret = FSPSM_ROOTCA_RSA2048(
                    g_user_key_info.encrypted_provisioning_key,
                    g_user_key_info.iv,
                    g_user_key_info.encrypted_user_tls_key,
                    &g_user_key_info.user_rsa2048_tls_wrappedkey); /* OUT */

            /* init vars */
             g_CAscm_Idx = (uint32_t)-1;

        }
        else {
            WOLFSSL_MSG("Failed to lock sce hw ");
        }
    #endif
    }

    /* unlock hw */
    wc_fspsm_hw_unlock();

    WOLFSSL_LEAVE("wc_fspsm_Open", ret);
    return ret;
}

/* close SCE driver */
WOLFSSL_LOCAL void wc_fspsm_Close()
{
    WOLFSSL_ENTER("sce Close");
    int ret;

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        /* close SCE */
        ret = FSPSM_CLOSE(&gFSPSM_ctrl);

        /* unlock hw */
        wc_fspsm_hw_unlock();
        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG("RENESAS SCE Close failed");
        }
    }
    else {
        WOLFSSL_MSG("Failed to unlock sce hw ");
    }
}

#define RANDGEN_WORDS  4
WOLFSSL_LOCAL int wc_fspsm_GenerateRandBlock(byte* output, word32 sz)
{
    /* Generate PRNG based on NIST SP800-90A AES CTR-DRBG */
    int ret = 0;
    word32 fspbuf[RANDGEN_WORDS];

    while (sz > 0) {
        word32 len = sizeof(buffer);

        if (sz < len) {
            len = sz;
        }
        /* return 4 words random number*/
        ret = R_RANDOM_GEN((uint8_t* const)fspbuf);
        if(ret == FSP_SUCCESS) {
            XMEMCPY(output, &fspbuf, len);
            output += len;
            sz -= len;
         } else {
            WOLFSSL_MSG_EX("FSP SM Rnd Generate() Returned 0x%08x", ret);
            return WC_HW_E;
        }
    }
    return ret;
}

#if defined(WOLFSSL_RENESAS_FSPSM) && \
    defined(WOLFSSL_RENESAS_FSPSM_TLS)

#if defined(WOLFSSL_RENESAS_FSPSM_ECC)
/* Verify Server Key Exchange while doing ECDH key exchange */
static int fspsm_ServerKeyExVerify(uint32_t type, WOLFSSL* ssl,
                                   const uint8_t* sig,
                                   uint32_t sigSz, void* ctx)
{
    int ret = WOLFSSL_FAILURE;
    FSPSM_ST* cbInfo;
    byte qx[MAX_ECC_BYTES], qy[MAX_ECC_BYTES];
    byte *peerkey = NULL;

    word32 qxLen = sizeof(qx), qyLen = sizeof(qy);
    (void) sigSz;

    /* sanity check */
    if (ssl == NULL || sig == NULL || ctx == NULL)
        return ret;

    cbInfo = (FSPSM_ST*)ctx;

    /* export public peer public key */
    ret = wc_ecc_export_public_raw(ssl->peerEccKey, qx, &qxLen, qy, &qyLen);
    WOLFSSL_PKMSG("qxLen %d qyLen %d\n", qxLen, qyLen);
    if (ret != 0) {
        WOLFSSL_MSG("failed to export peer ecc key");
        return ret;
    }
    /* make peer ecc key data for SCE */
    /* 0padding(24bit) || 04(8bit) || Qx(256bit) || Qy(256bit) */
    peerkey = (byte*)XMALLOC((3 + 1 + qxLen + qyLen), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (peerkey == NULL) {
        WOLFSSL_MSG("failed to malloc ecc key");
        return WOLFSSL_FAILURE;
    }

    XMEMSET(peerkey, 0, (3 + 1 + qxLen + qyLen));
    peerkey[3] = ECC_POINT_UNCOMP;
    XMEMCPY(&peerkey[4], qx, qxLen);
    XMEMCPY(&peerkey[4+qxLen], qy, qyLen);

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        /* 0 : RSA 2048bit, 1 : Reserved, 2 : ECDSA P-256 */
        ret = FSPSM_TLS_SVRKEYExVfy(
            type,
            (uint8_t*) ssl->arrays->clientRandom,
            (uint8_t*) ssl->arrays->serverRandom,
            (uint8_t*) peerkey,
            (uint8_t*) sig,
            (uint32_t*)ssl->peerSceTsipEncRsaKeyIndex,
            (uint32_t*)cbInfo->encrypted_ephemeral_ecdh_public_key);

        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG("failed R_fspsm_TLS_ServerKeyExchangeVerify");
            cbInfo->keyflgs_tls.bits.pk_key_set = 0;
        }
        else {
            ret = WOLFSSL_SUCCESS;
            cbInfo->keyflgs_tls.bits.pk_key_set = 1;
        }
    }
    else {
        WOLFSSL_MSG("Failed to lock sce hw ");
    }

    /* unlock hw */
    wc_fspsm_hw_unlock();

    XFREE(peerkey, 0, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
/* Callback for Rsa Verify */
WOLFSSL_LOCAL int wc_fspsm_RsaVerifyTLS(WOLFSSL* ssl, byte* sig, uint32_t sigSz,
        uint8_t** out, const byte* key, uint32_t keySz, void* ctx)
{
    int ret = WOLFSSL_FAILURE;
    (void) out;
    (void) key;
    (void) keySz;

    WOLFSSL_PKMSG("SCE RSA Verify: sigSz %d, keySz %d\n", sigSz, keySz);

    if (wc_fspsm_usable(ssl, 0))
      ret = fspsm_ServerKeyExVerify(0, ssl, sig, sigSz, ctx);
    else
      ret = CRYPTOCB_UNAVAILABLE;

    if (ret == WOLFSSL_SUCCESS)
        ret = 0; /* 0 for success */

    WOLFSSL_PKMSG("SCE RSA Verify: ret %d\n", ret);

    return ret;
}
/* Callback for Ecc Verify */
WOLFSSL_LOCAL int wc_fspsm_EccVerifyTLS(WOLFSSL* ssl, const uint8_t* sig,
        uint32_t sigSz,  const uint8_t* hash, uint32_t hashSz,
        const uint8_t* key, uint32_t keySz, int* result, void* ctx)
{
    int ret = WOLFSSL_FAILURE;
    uint8_t *sigforSCE;
    const byte rs_size = HW_SCE_ECDSA_DATA_BYTE_SIZE/2;
    byte offset = 0x3;
    (void) sigSz;
    (void) hash;
    (void) hashSz;
    (void) key;
    (void) keySz;

    sigforSCE = NULL;

    WOLFSSL_PKMSG("SCE ECC Verify: ssl->options.serverState = %d sigSz %d, hashSz %d, keySz %d\n",
                    ssl->options.serverState, sigSz, hashSz, keySz);

    if (!wc_fspsm_usable(ssl, 0)) {
      WOLFSSL_PKMSG("Cannot handle cipher suite by SCE");
      return CRYPTOCB_UNAVAILABLE;
    }

    if ((sigforSCE = (uint8_t*)XMALLOC(HW_SCE_ECDSA_DATA_BYTE_SIZE, NULL,
                                                  DYNAMIC_TYPE_TEMP)) == NULL) {
        WOLFSSL_MSG("failed to malloc memory");
        return MEMORY_E;
    }
    /* initialization */
    XMEMSET(sigforSCE, 0, HW_SCE_ECDSA_DATA_BYTE_SIZE);

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

    ret = fspsm_ServerKeyExVerify(2, ssl, sigforSCE, 64, ctx);

    XFREE(sigforSCE, NULL, DYNAMIC_TYPE_TEMP);

    if (ret == WOLFSSL_SUCCESS) {
        *result = 1;
        ret = 0; /* for success */
    }
    else
        *result = 0;

    WOLFSSL_PKMSG("SCE ECC Verify: ret %d, result %d\n", ret, *result);

    return ret;
}

#if defined(WOLFSSL_RENESAS_FSPSM_TLS) || \
    defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)

/* Callback for ECC shared secret */
WOLFSSL_LOCAL int fspsm_EccSharedSecret(WOLFSSL* ssl, ecc_key* otherKey,
        uint8_t* pubKeyDer, unsigned int* pubKeySz,
        uint8_t* out, unsigned int* outlen, int side, void* ctx)
{
    int       ret = WOLFSSL_SUCCESS;
    (void) otherKey;
    (void) side;

    FSPSM_ST* cbInfo = (FSPSM_ST*)ctx;

    (void)ssl;
    (void)cbInfo;

    /* sanity check */
    if (ssl == NULL || pubKeyDer == NULL || pubKeySz == NULL ||
        out == NULL || outlen == NULL || ctx == NULL)
      return WOLFSSL_FAILURE;

    WOLFSSL_PKMSG("PK ECC PMS: Side %s, Peer Curve %d\n",
        side == WOLFSSL_CLIENT_END ? "client" : "server", otherKey->dp->id);

    if (cbInfo->keyflgs_tls.bits.pk_key_set == 1) {
        if ((ret = wc_fspsm_hw_lock()) == 0) {
            /* Generate ECC PUblic key pair */
            ret = FSPSM_TLS_ECCS256R1_KPG(
                &cbInfo->ecc_p256_wrapped_key,
                (uint8_t*)&cbInfo->ecc_ecdh_public_key/* Qx 32 bytes and Qy 32 bytes*/ );
            if (ret != FSP_SUCCESS) {
                WOLFSSL_PKMSG("Failed secp256r1_EphemeralWrappedKeyPairGenerate %d\n", ret);
                return ret;
            }

            /* copy generated ecdh public key into buffer */
            pubKeyDer[0] = ECC_POINT_UNCOMP;
            *pubKeySz = 1 + sizeof(cbInfo->ecc_ecdh_public_key);
            XMEMCPY(&pubKeyDer[1], &cbInfo->ecc_ecdh_public_key,
                        sizeof(cbInfo->ecc_ecdh_public_key));

            /* Generate Premaster Secret */
            ret = FSPSM_TLS_PREMASTERGEN(
                        (uint32_t*)&cbInfo->encrypted_ephemeral_ecdh_public_key,
                        &cbInfo->ecc_p256_wrapped_key,
                        (uint32_t*)out/* pre-master secret 64 bytes */);
            if (ret != FSP_SUCCESS) {
                WOLFSSL_PKMSG("Failed PreMasterSecretGenerateForECC_secp256r1 %d\n", ret);
                return ret;
            }
            else {
                /* set master secret generation callback for use */
                wolfSSL_CTX_SetGenMasterSecretCb(ssl->ctx, Renesas_cmn_genMasterSecret);
                wolfSSL_SetGenMasterSecretCtx(ssl, cbInfo);
            }
        }
        else {
            WOLFSSL_MSG("Failed to lock sce hw ");
        }

        /* unlock hw */
        wc_fspsm_hw_unlock();

        *outlen = 64;
        WOLFSSL_PKMSG("PK ECC PMS: ret %d, PubKeySz %d, OutLen %d\n", ret, *pubKeySz, *outlen);
    }

    return ret;
}
#endif

/* Return tls cipher suite enumeration that is supported by SCE library */
static uint32_t GetSceCipherSuite(
                    uint8_t cipherSuiteFirst,
                    uint8_t cipherSuite)
{
    WOLFSSL_ENTER("GetSceCipherSuite");
    uint32_t sceCipher;

    if (cipherSuiteFirst == CIPHER_BYTE)
    {
        switch(cipherSuite) {
            case TLS_RSA_WITH_AES_128_CBC_SHA256:
                sceCipher = SCE_TLS_RSA_WITH_AES_128_CBC_SHA256;
                break;

            case TLS_RSA_WITH_AES_256_CBC_SHA256:
                sceCipher = SCE_TLS_RSA_WITH_AES_256_CBC_SHA256;
                break;

            default:
                sceCipher = (uint32_t)WOLFSSL_FSPSM_ILLEGAL_CIPHERSUITE;
                break;
        }
        WOLFSSL_MSG("<< GetSceCipherSuite");
        return sceCipher;
    }
    else if (cipherSuiteFirst == ECC_BYTE)
    {
        sceCipher = (uint32_t)WOLFSSL_FSPSM_ILLEGAL_CIPHERSUITE;
        /* comment out until implementation completes */
        switch(cipherSuite) {

            case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
                sceCipher = SCE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
                break;

            case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                sceCipher = SCE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
                break;

            case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
                sceCipher = SCE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
                break;

            case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                sceCipher = SCE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
                break;

            default:
                sceCipher = (uint32_t)WOLFSSL_FSPSM_ILLEGAL_CIPHERSUITE;
                break;
        }
    }
    else{
        sceCipher = (uint32_t)WOLFSSL_FSPSM_ILLEGAL_CIPHERSUITE;
    }

    WOLFSSL_MSG("<< GetSceCipherSuite");

    return sceCipher;
}
/* check if sce tls functions can be used for the cipher       */
/*                                                             */
/* ssl     : a pointer to WOLFSSL object                       */
/* session_key_generated : if session key has been generated   */
/* return  1 for usable, 0 for unusable                        */
WOLFSSL_LOCAL int wc_fspsm_usable(const WOLFSSL *ssl,
                                                uint8_t session_key_generated)
{
    WOLFSSL_ENTER("fspsm_usable");
    uint32_t sceCipher;
    byte side;
    const Ciphers *enc;
    const Ciphers *dec;

    /* sanity check */
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    /* when rsa key index == NULL, SCE isn't used for cert verification. */
    /* in the case, we cannot use TSIP.                                  */
    if (!ssl->peerSceTsipEncRsaKeyIndex)
        return 0;

    /* when enabled Extended Master Secret, we cannot use SCE.            */
    if (ssl->options.haveEMS)
        return 0;

    /* when session_key_generated is set as 1, expects to be created      */
    /* session key already.                                               */
    if (session_key_generated) {
        enc = &ssl->encrypt;
        dec = &ssl->decrypt;
        if (enc == NULL || dec == NULL) {
            /* something wrong */
            return 0;
        }
        if (enc->aes == NULL || dec->aes == NULL) {
            return 0;
        }
        if (enc->aes->ctx.setup == 0) {
            /* session key for SCE is not created */
            return 0;
        }
    }
    /* retrieve cipher suite if SCE supports */
    sceCipher = GetSceCipherSuite(ssl->options.cipherSuite0,
                                     ssl->options.cipherSuite);
    side = ssl->options.side;

    if (sceCipher != (uint32_t)WOLFSSL_FSPSM_ILLEGAL_CIPHERSUITE
                                   && side == WOLFSSL_CLIENT_END)
        return 1;
    else
        return 0;
}

/* Generate Hmac by sha256*/
WOLFSSL_LOCAL int wc_fspsm_Sha256GenerateHmac(const WOLFSSL *ssl,
                const uint8_t* myInner, uint32_t innerSz,const uint8_t* in,
                uint32_t sz, byte* digest)
{
    WOLFSSL_ENTER("fspsm_Sha256HmacGenerate");

    FSPSM_HMAC_HANDLE _handle;
    FSPSM_HMAC_WKEY wrapped_key;
    int ret;

    if ((ssl == NULL) || (myInner == NULL) || (in == NULL) ||
        (digest == NULL))
      return BAD_FUNC_ARG;

    wrapped_key = ssl->keys.fspsm_client_write_MAC_secret;

    if ((ret = wc_fspsm_hw_lock()) != 0) {
        WOLFSSL_MSG("hw lock failed");
        return ret;
    }

    ret = FSPSM_S256HMAC_GInt(
                &_handle,
                &wrapped_key);

    if (ret == FSP_SUCCESS)
        ret = FSPSM_S256HMAC_GUp(
                &_handle,
                (uint8_t*)myInner,
                innerSz);

    if (ret == FSP_SUCCESS)
        ret = FSPSM_S256HMAC_GUp(
                &_handle,
                (uint8_t*)in,
                sz);

    if (ret == FSP_SUCCESS)
        ret = FSPSM_S256HMAC_GFnl(
                &_handle,
                digest);

    if (ret != FSP_SUCCESS)
        ret = WOLFSSL_FAILURE;

    /* unlock hw */
    wc_fspsm_hw_unlock();
    WOLFSSL_LEAVE("fspsm_Sha256HmacGenerate", ret);
    return ret;
}

/* Verify hmac */
WOLFSSL_LOCAL int wc_fspsm_Sha256VerifyHmac(const WOLFSSL *ssl,
        const uint8_t* message, uint32_t messageSz,
        uint32_t macSz, uint32_t content)
{
    WOLFSSL_ENTER("fspsm_Sha256HmacVerify");

    FSPSM_HMAC_HANDLE _handle;
    FSPSM_HMAC_WKEY wrapped_key;
    byte   myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    int ret;

    if ((ssl == NULL) || (message == NULL))
        return BAD_FUNC_ARG;

    wrapped_key = ssl->keys.fspsm_server_write_MAC_secret;

    if ((ret = wc_fspsm_hw_lock()) != 0) {
        WOLFSSL_MSG("hw lock failed");
        return ret;
    }

    wolfSSL_SetTlsHmacInner((WOLFSSL*)ssl, myInner,
                                                        (word32)messageSz, (int)content, 1);

    ret = FSPSM_S256HMAC_VInt(
                &_handle,
                &wrapped_key);

    if (ret == FSP_SUCCESS)
        ret = FSPSM_S256HMAC_VUp(
                &_handle,
                (uint8_t*)myInner,
                WOLFSSL_TLS_HMAC_INNER_SZ);

    if (ret == FSP_SUCCESS)
        ret = FSPSM_S256HMAC_VUp(
                &_handle,
                (uint8_t*)message,
                (uint32_t)messageSz);

    if (ret == FSP_SUCCESS)
        ret = FSPSM_S256HMAC_VFnl(
                &_handle,
                (uint8_t*)(message+messageSz),
                (uint32_t)macSz);

    if (ret != FSP_SUCCESS) {
        WOLFSSL_MSG("FSP SM Mac verification failed");
    }

    /* unlock hw */
    wc_fspsm_hw_unlock();
    WOLFSSL_LEAVE("fspsm_Sha256HmacVerify", ret);
    return ret;
}

/* generate Verify Data based on master secret */
WOLFSSL_LOCAL int wc_fspsm_generateVerifyData(
                            const uint8_t *ms, /* master secret */
                            const uint8_t *side, const uint8_t *handshake_hash,
                            uint8_t *hashes /* out */)
{
    WOLFSSL_ENTER("fspsm_generateVerifyData");
    int ret ;
    uint32_t l_side = SCE_TLS_GENERATE_CLIENT_VERIFY;

    if ((ms == NULL) || (side == NULL) || (handshake_hash == NULL) ||
        (hashes == NULL))
      return BAD_FUNC_ARG;

    if (XSTRNCMP((const char*)side, (const char*)kTlsServerFinStr,
                                                FINISHED_LABEL_SZ) == 0)
    {
        l_side = SCE_TLS_GENERATE_SERVER_VERIFY;
    }

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        ret = FSPSM_VERIFY_DATA_FUNC(l_side, (uint32_t*)ms,
                       (uint8_t*)handshake_hash, hashes/* out */);
        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG("R_fspsm_TLS_VerifyDataGenerate failed");
        }
    }
    /* unlock hw */
    wc_fspsm_hw_unlock();
    WOLFSSL_LEAVE("fspsm_generateVerifyData", ret);
    return ret;
}

/* generate keys for TLS communication */
WOLFSSL_LOCAL int wc_fspsm_generateSessionKey(WOLFSSL *ssl,
                FSPSM_ST* cbInfo, int devId)
{
    WOLFSSL_MSG("fspsm_generateSessionKey()");
    int ret;
    Ciphers *enc;
    Ciphers *dec;
    FSPSM_HMAC_WKEY key_client_mac;
    FSPSM_HMAC_WKEY key_server_mac;

    FSPSM_AES_PWKEY key_client_aes = NULL;
    FSPSM_AES_PWKEY key_server_aes = NULL;

    uint32_t sceCS = GetSceCipherSuite(ssl->options.cipherSuite0,
                                         ssl->options.cipherSuite);

    if (ssl== NULL || cbInfo == NULL)
      return BAD_FUNC_ARG;


    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (sceCS == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
                sceCS == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        {
            WOLFSSL_MSG("Session key for AES-GCM generation skipped.");

            wolfSSL_KeepArrays(ssl);
            ret = FSP_SUCCESS;

        }
        else {
            key_client_aes = (FSPSM_AES_PWKEY)XMALLOC(sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AE);
            key_server_aes = (FSPSM_AES_PWKEY)XMALLOC(sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AE);
            if (key_client_aes == NULL || key_server_aes == NULL) {
                return MEMORY_E;
            }

            ret = FSPSM_SESSIONKEY_GEN_FUNC(
                    GetSceCipherSuite(
                        ssl->options.cipherSuite0,
                        ssl->options.cipherSuite),
                    (uint32_t*)ssl->arrays->fspsm_masterSecret,
                    (uint8_t*) ssl->arrays->clientRandom,
                    (uint8_t*) ssl->arrays->serverRandom,
                    NULL,
                    &key_client_mac,
                    &key_server_mac,
                    key_client_aes,
                    key_server_aes,
                    NULL, NULL);
        }

        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG("R_fspsm_TLS_SessionKeyGenerate failed");
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
                enc->aes->ctx.wrapped_key = (FSPSM_AES_PWKEY)XMALLOC
                                            (sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AE);
                if (enc->aes->ctx.wrapped_key == NULL)
                    return MEMORY_E;
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
                    XMEMSET(dec->aes, 0, sizeof(Aes));

                    dec->aes->ctx.wrapped_key = (FSPSM_AES_PWKEY)XMALLOC
                                            (sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AE);
                    if (dec->aes->ctx.wrapped_key == NULL)
                        return MEMORY_E;
                    }
            }
            /* copy key index into aes */
            if (ssl->options.side == PROVISION_CLIENT) {
                XMEMCPY(enc->aes->ctx.wrapped_key, key_client_aes,
                                                    sizeof(FSPSM_AES_WKEY));
                XMEMCPY(dec->aes->ctx.wrapped_key, key_server_aes,
                                                    sizeof(FSPSM_AES_WKEY));
            }
            else {
                XMEMCPY(enc->aes->ctx.wrapped_key, key_server_aes,
                                                    sizeof(FSPSM_AES_WKEY));
                XMEMCPY(dec->aes->ctx.wrapped_key, key_client_aes,
                                                    sizeof(FSPSM_AES_WKEY));
            }
            /* copy mac key index into keys */
            ssl->keys.fspsm_client_write_MAC_secret = key_client_mac;
            ssl->keys.fspsm_server_write_MAC_secret = key_server_mac;

            /* set up key size and marked ready */
            if (enc) {
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

            if (cbInfo->cipher == SCE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
               cbInfo->cipher == SCE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
                enc->aes->nonceSz = AEAD_MAX_IMP_SZ;
                dec->aes->nonceSz = AEAD_MAX_IMP_SZ;
             }
             enc->aes->devId = devId;
             dec->aes->devId = devId;

            /* marked as session key is set */
            cbInfo->keyflgs_tls.bits.session_key_set = 1;
        }

        XFREE(key_client_aes, aes->heap, DYNAMIC_TYPE_AES);
        XFREE(key_server_aes, aes->heap, DYNAMIC_TYPE_AES);

        /* unlock hw */
        wc_fspsm_hw_unlock();

    }
    else {
        WOLFSSL_LEAVE("hw lock failed", ret);
    }

    WOLFSSL_LEAVE("fspsm_generateSessionKey", ret);
    return ret;
}

/* generate master secret based on pre-master which is generated by SCE */
WOLFSSL_LOCAL int wc_fspsm_generateMasterSecret(
        uint8_t        cipherSuiteFirst,
        uint8_t        cipherSuite,
        const uint8_t *pr, /* pre-master    */
        const uint8_t *cr, /* client random */
        const uint8_t *sr, /* server random */
        uint8_t *ms)
{
    WOLFSSL_ENTER("fspsm_generateMasterSecretEx");
    int ret;

    if ((pr == NULL) || (cr == NULL) || (sr == NULL) ||
        (ms == NULL))
      return BAD_FUNC_ARG;

    uint32_t sceCS = GetSceCipherSuite(cipherSuiteFirst, cipherSuite);
    if (sceCS == 0xffffffff)
        return BAD_FUNC_ARG;

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        ret = FSPSM_MASTERSECRET_GEN_FUNC(
            sceCS,
            (uint32_t*)pr,
            (uint8_t*)cr, (uint8_t*)sr, (uint32_t*)ms);
        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG("R_fspsm_TLS_MasterSecretGenerate failed");
        }
        /* unlock hw */
        wc_fspsm_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("fspsm_generateMasterSecret", ret);
    return ret;
}

/* generate pre-Master secrete by SCE */
WOLFSSL_LOCAL int wc_fspsm_generatePremasterSecret(uint8_t *premaster,
                                                        uint32_t preSz)
{
    WOLFSSL_ENTER("fspsm_generatePremasterSecret");
    int ret;

    if (premaster == NULL)
      return BAD_FUNC_ARG;

    if ((ret = wc_fspsm_hw_lock()) == 0 && preSz >=
                                    (SCE_TLS_MASTER_SECRET_WORD_SIZE*4)) {
            /* generate pre-master, 80 bytes */
            ret = FSPSM_PREGEN_FUNC((uint32_t*)premaster);
            if (ret != FSP_SUCCESS) {
                WOLFSSL_MSG(" R_fspsm_TLS_GeneratePreMasterSecret failed");
            }
        /* unlock hw */
        wc_fspsm_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed or preSz is smaller than 80");
    }

    WOLFSSL_LEAVE("fspsm_generatePremasterSecret", ret);
    return ret;
}


/*
* generate encrypted pre-Master secrete by SCE
*/
WOLFSSL_LOCAL int wc_fspsm_generateEncryptPreMasterSecret(
        WOLFSSL*    ssl,
        uint8_t*       out,
        uint32_t*     outSz)
{
    WOLFSSL_MSG("fspsm_generateEncryptPreMasterSecret");
    int ret;

    if ((ssl == NULL) || (out == NULL) || (outSz == NULL))
      return BAD_FUNC_ARG;

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (*outSz >= 256)
            ret = FSPSM_PREGENENC_FUNC(
                        (uint32_t*)ssl->peerSceTsipEncRsaKeyIndex,
                        (uint32_t*)ssl->arrays->preMasterSecret,
                        (uint8_t*)out);
        else
            ret = -1;

        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG("R_fspsm_TLS_PreMasterSecretEncryptWithRSA2048 failed");
        }
        else {
            *outSz = 256; /* SCE can only handles 2048 RSA */
            /* set GenMaster Callback for Master secret generation */
            void* ctx = wolfSSL_GetRsaVerifyCtx(ssl);
            wolfSSL_CTX_SetGenMasterSecretCb(ssl->ctx,
                                                Renesas_cmn_genMasterSecret);
            wolfSSL_SetGenMasterSecretCtx(ssl, ctx);
        }
        wc_fspsm_hw_unlock();

    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("fspsm_generateEncryptPreMasterSecret", ret);
    return ret;
}


/* Certificate verification by SCE */
WOLFSSL_LOCAL int wc_fspsm_tls_CertVerify(
        const uint8_t* cert,       uint32_t certSz,
        const uint8_t* signature,  uint32_t sigSz,
        uint32_t      key_n_start,uint32_t key_n_len,
        uint32_t      key_e_start,uint32_t key_e_len,
        uint8_t*      fspsm_encPublickey)
{
    WOLFSSL_ENTER("fspsm_tls_CertVerify");
    int ret;
    uint8_t *sigforSCE;
    uint8_t *pSig;
    const byte rs_size = 0x20;
    byte offset = 0x3;
    (void)sigSz;

    sigforSCE = NULL;
    pSig = NULL;

    if (cert == NULL)
      return BAD_FUNC_ARG;

    if (!signature) {
        WOLFSSL_MSG(" signature for ca verification is not set");
        return -1;
    }
    if (!fspsm_encPublickey) {
        WOLFSSL_MSG(" fspsm_encPublickey is NULL.");
        return -1;
    }

    if (g_user_key_info.encrypted_user_tls_key_type ==
                                SCE_TLS_PUBLIC_KEY_TYPE_ECDSA_P256/*ECDSA*/) {

      if ((sigforSCE = (uint8_t*)XMALLOC(HW_SCE_ECDSA_DATA_BYTE_SIZE, NULL,
                                                  DYNAMIC_TYPE_TEMP)) == NULL) {
        WOLFSSL_MSG("failed to malloc memory");
        return MEMORY_E;
      }
      /* initialization */
      XMEMSET(sigforSCE, 0, HW_SCE_ECDSA_DATA_BYTE_SIZE);

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
    else {
      pSig = (uint8_t*)signature;
    }


    if ((ret = wc_fspsm_hw_lock()) == 0) {
        ret = FSPSM_TLSCERT_VRY(
                g_user_key_info.encrypted_user_tls_key_type,
                (uint32_t*)g_encrypted_publicCA_key,/* encrypted public key  */
                (uint8_t*)cert,                 /* certificate der        */
                certSz,                         /* length of der          */
                (uint8_t*)pSig,                 /* sign data by RSA PSS   */
                key_n_start,  /* start position of public key n in bytes     */
                (key_n_start + key_n_len),     /* length of the public key n */
                key_e_start,                   /* start pos, key e in bytes  */
                (key_e_start + key_e_len),     /* length of the public key e */
                (uint32_t*)fspsm_encPublickey  /* returned encrypted key     */
                );
        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG(" R_XXX_TlsCertificateVerification() failed");
        }
        XFREE(sigforSCE, NULL, DYNAMIC_TYPE_TEMP);
        wc_fspsm_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("fspsm_tls_CertVerify", ret);
    return ret;
}

/* Root Certificate verification */
WOLFSSL_LOCAL int wc_fspsm_tls_RootCertVerify(
        const uint8_t* cert,        uint32_t cert_len,
        uint32_t      key_n_start,    uint32_t key_n_len,
        uint32_t      key_e_start,    uint32_t key_e_len,
        uint32_t      cm_row)
{
    int ret;
    /* call to generate encrypted public key for certificate verification */
    uint8_t *signature = (uint8_t*)ca_cert_sig;

    WOLFSSL_ENTER("wc_fspsm_tls_RootCertVerify");

    if (cert == NULL)
      return BAD_FUNC_ARG;

    if (!signature) {
        WOLFSSL_MSG(" signature for ca verification is not set");
        return -1;
    }

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        ret = FSPSM_TLSROOTCERT_VRY(
                g_user_key_info.encrypted_user_tls_key_type,
                (uint8_t*)cert,             /* CA cert */
                (uint32_t)cert_len,         /* length of CA cert */
                key_n_start,                /* Byte position of public key */
                (key_n_start + key_n_len),
                key_e_start,
                (key_e_start + key_e_len),
                (uint8_t*)ca_cert_sig,      /* RSA 2048 PSS with SHA256 */
                g_encrypted_publicCA_key);  /* RSA-2048 public key 560 bytes */
                                            /* ECDSA 96 bytes */
        if (ret != FSP_SUCCESS) {
            WOLFSSL_MSG(" R_fspsm_TLS_RootCertificateVerify() failed");
        }
        else {
            g_CAscm_Idx = cm_row;
        }
        wc_fspsm_hw_unlock();
    }
    else {
        WOLFSSL_MSG(" hw lock failed ");
    }
    WOLFSSL_LEAVE("wc_fspsm_tls_RootCertVerify", ret);
    return ret;
}

/*  store elements for session key generation into ssl->keys.
 *  return 0 on success, negative value on failure
 */
WOLFSSL_LOCAL int wc_fspsm_storeKeyCtx(WOLFSSL* ssl, FSPSM_ST* info)
{
    int ret = 0;

    WOLFSSL_ENTER("fspsm_storeKeyCtx");

    if (ssl == NULL || info == NULL)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        XMEMCPY(info->masterSecret, ssl->arrays->fspsm_masterSecret,
                                                FSPSM_TLS_MASTERSECRET_SIZE);
        XMEMCPY(info->clientRandom, ssl->arrays->clientRandom, 32);
        XMEMCPY(info->serverRandom, ssl->arrays->serverRandom, 32);

        info->cipher = (uint8_t)GetSceCipherSuite(ssl->options.cipherSuite0,
                               ssl->options.cipherSuite);
    }
    WOLFSSL_LEAVE("fspsm_storeKeyCtx", ret);
    return ret;
}

/* to inform ca certificate sign */
/* signature format expects RSA 2048 PSS with SHA256 */
#if defined(WOLFSSL_RENESAS_SCEPROTECT)
WOLFSSL_API void wc_sce_inform_cert_sign(const uint8_t *sign)
#else
WOLFSSL_API void wc_fspsm_inform_cert_sign(const uint8_t *sign)
#endif
{
    if (sign)
        ca_cert_sig = sign;
}

/* let wolfSSL know user key information using TLS operation by SCE */
#if defined(WOLFSSL_RENESAS_SCEPROTECT)
WOLFSSL_API void wc_sce_inform_user_keys(
#else
WOLFSSL_API void wc_fspsm_inform_user_keys(
#endif
    uint8_t* encrypted_provisioning_key,
    uint8_t* iv,
    uint8_t* encrypted_user_tls_key,
    uint32_t encrypted_user_tls_key_type)
{
    WOLFSSL_ENTER("sce_inform_user_keys");
    g_user_key_info.encrypted_provisioning_key = NULL;
    g_user_key_info.iv = NULL;
    g_user_key_info.encrypted_user_tls_key = NULL;

    if (encrypted_provisioning_key ) {
        g_user_key_info.encrypted_provisioning_key = encrypted_provisioning_key;
    }
    if (iv) {
        g_user_key_info.iv = iv;
    }
    if (encrypted_user_tls_key) {
        g_user_key_info.encrypted_user_tls_key = encrypted_user_tls_key;
    }

    g_user_key_info.encrypted_user_tls_key_type = encrypted_user_tls_key_type;

    /* set callback for ECC */
    WOLFSSL_MSG("sce_inform_user_keys_ex");
}


/* Set callbacks needed for sce TLS api handling */
#if defined(WOLFSSL_RENESAS_SCEPROTECT)
WOLFSSL_API void wc_sce_set_callbacks(WOLFSSL_CTX* ctx)
#else
WOLFSSL_API void wc_fspsm_set_callbacks(WOLFSSL_CTX* ctx)
#endif
{
    wolfSSL_CTX_SetEccVerifyCb(ctx, Renesas_cmn_EccVerify);
    wolfSSL_CTX_SetRsaVerifyCb(ctx, Renesas_cmn_RsaVerify);
    wolfSSL_CTX_SetGenPreMasterCb(ctx, Renesas_cmn_generatePremasterSecret);
    wolfSSL_CTX_SetRsaEncCb(ctx, Renesas_cmn_RsaEnc);
    wolfSSL_CTX_SetVerifyMacCb(ctx, Renesas_cmn_VerifyHmac);

    /* reset callbacks */
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, NULL);
}
/* Set callback contexts needed for sce TLS api handling */
#if defined(WOLFSSL_RENESAS_SCEPROTECT)
WOLFSSL_API int wc_sce_set_callback_ctx(WOLFSSL* ssl, void* user_ctx)
#else
WOLFSSL_API int wc_fspsm_set_callback_ctx(WOLFSSL* ssl, void* user_ctx)
#endif
{
    if (fspsm_sess_idx > MAX_FSPSM_CBINDEX) {
        WOLFSSL_MSG("exceeds maximum session index");
        return -1;
    }
    gPKCbInfo.user_PKCbInfo[fspsm_sess_idx] = (FSPSM_ST*)user_ctx;
    gPKCbInfo.user_PKCbInfo[fspsm_sess_idx]->keyflgs_tls.bits.pk_key_set = 0;
    gPKCbInfo.user_PKCbInfo[fspsm_sess_idx]->keyflgs_tls.bits.session_key_set
                                                                            = 0;

    wolfSSL_SetEccVerifyCtx(ssl, user_ctx);
    wolfSSL_SetRsaEncCtx(ssl, user_ctx);
    wolfSSL_SetRsaVerifyCtx(ssl, user_ctx);
    wolfSSL_SetGenPreMasterCtx(ssl, user_ctx);
    wolfSSL_SetEccSharedSecretCtx(ssl, NULL);
    wolfSSL_SetVerifyMacCtx(ssl, user_ctx);

    /* set up crypt callback */
    wc_CryptoCb_CryptInitRenesasCmn(ssl, user_ctx);

    gPKCbInfo.num_session = ++fspsm_sess_idx;

    return 0;
}
#endif /*  !WOLFSSL_RENESAS_FSPSM_CRYPTONLY */

#endif /* WOLFSSL_RENESAS_FSPSM_TLS || WOLFSSL_RENESAS_FSPSM_CRYPTONLY */
#endif /* WOLFSSL_RENESAS_FSPSM) &&  WOLFSSL_RENESAS_FSPSM_TLS */
