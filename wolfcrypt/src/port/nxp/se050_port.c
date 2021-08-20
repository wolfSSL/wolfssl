/* se050_port.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ed25519.h>


#if defined(WOLFSSL_SE050)

#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#include "fsl_sss_api.h"
#include "fsl_sss_se05x_types.h"


/* Global variables */
static sss_session_t *cfg_se050_i2c_pi;
static sss_key_store_t *hostKeyStore;
static sss_key_store_t *keyStore;
int keyId_allocater = 100;

int wolfcrypt_se050_SetConfig(sss_session_t *pSession, sss_key_store_t *pHostKeyStore, sss_key_store_t *pKeyStore) 
{
	printf("Setting SE050 session configuration\n");
	
	XMEMSET(&cfg_se050_i2c_pi, 0, sizeof(cfg_se050_i2c_pi));
	cfg_se050_i2c_pi = pSession;
	
    XMEMSET(&hostKeyStore, 0, sizeof(hostKeyStore));
	hostKeyStore = pHostKeyStore;
	
    XMEMSET(&keyStore, 0, sizeof(keyStore));
	keyStore = pKeyStore;
    
	return 0;
}

int se050_allocate_key()
{
    return keyId_allocater++;
}

#ifndef WC_NO_RNG
int se050_get_random_number(uint32_t count, uint8_t* rand_out)
{
    sss_status_t status;
	sss_rng_context_t rng;
	int ret = 0;

    if (wolfSSL_CryptHwMutexLock() == 0) {
        status = sss_rng_context_init(&rng, cfg_se050_i2c_pi);

        if (status == kStatus_SSS_Success)
            status = sss_rng_get_random(&rng, rand_out, count);

        if (status == kStatus_SSS_Success)
            status = sss_rng_context_free(&rng);

        if (status != kStatus_SSS_Success) {
            ret = RNG_FAILURE_E;
        }
    }
    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif /* WC_NO_RNG */

/* Used for sha/sha224/sha384/sha512 */
int se050_hash_init(SE050_HASH_Context* se050Ctx, void* heap)
{
    se050Ctx->heap = heap;
    se050Ctx->len  = 0;
    se050Ctx->used = 0;
    se050Ctx->msg  = NULL;
    return 0;
}

int se050_hash_update(SE050_HASH_Context* se050Ctx, const byte* data, word32 len)
{
    if (se050Ctx == NULL || (len > 0 && data == NULL)) {
        return BAD_FUNC_ARG;
    }
    
    if (se050Ctx->len < se050Ctx->used + len) {
        if (se050Ctx->msg == NULL) {
            se050Ctx->msg = (byte*)XMALLOC(se050Ctx->used + len, se050Ctx->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
                    if (se050Ctx->msg == NULL) {
                        return MEMORY_E;
                    }
        } 
        else {
            byte* pt = (byte*)XREALLOC(se050Ctx->msg, se050Ctx->used + len, se050Ctx->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (pt == NULL) {
                return MEMORY_E;
            }
            se050Ctx->msg = pt;
        }
        se050Ctx->len = se050Ctx->used + len;
    }
    XMEMCPY(se050Ctx->msg + se050Ctx->used, data , len);
    se050Ctx->used += len;
    return 0;
}

int se050_hash_final(SE050_HASH_Context* se050Ctx, byte* hash, size_t digestLen, sss_algorithm_t algo)
{
    sss_status_t status;
    sss_digest_t digest_ctx;
   // XMEMSET(&digest_ctx, 0, sizeof(digest_ctx));
    
    const byte*     data = se050Ctx->msg;
    int             size = (se050Ctx->len) / SSS_BLOCK_SIZE;
    int             leftover = (se050Ctx->len) % SSS_BLOCK_SIZE;
    const byte*     blocks;
                    blocks = data;    


    if (wolfSSL_CryptHwMutexLock() == 0) { 
        status = sss_digest_context_init(&digest_ctx, cfg_se050_i2c_pi, algo, kMode_SSS_Digest);  
        if(status != kStatus_SSS_Success){
            printf("error 1\n");
            return -1;
        }

        status = sss_digest_init(&digest_ctx);
        if(status != kStatus_SSS_Success){
            printf("error 2 - hash_final...\n");
            return -1;
        }
        /* used to send chunks of size 512 */
        while (size--) {
            status = sss_digest_update(&digest_ctx, blocks, SSS_BLOCK_SIZE);
            if(status != kStatus_SSS_Success){
                printf("error 3\n");
                return -1;
            }
            blocks += SSS_BLOCK_SIZE;       
        }
        if (leftover) {
            status = sss_digest_update(&digest_ctx, blocks, leftover);
            if(status != kStatus_SSS_Success){
                printf("error 3\n");
                return -1;
            }
        }        

        status = sss_digest_finish(&digest_ctx, hash, &digestLen);
        if(status != kStatus_SSS_Success){
            printf("error 4\n");
            return -1;
        }
        sss_digest_context_free(&digest_ctx);

    }

    wolfSSL_CryptHwMutexUnLock();

    return 0;
}

void se050_hash_free(SE050_HASH_Context* se050Ctx)
{
    (void)se050Ctx;
}

#ifndef NO_AES
int se050_aes_set_key(Aes* aes, const byte* key, word32 len,
                                        const byte* iv, int dir)
{
    printf("\n\nrunning se050_set_key\n");
    (void)dir;
    (void)iv;
    sss_status_t status;
    aes->rounds = len/4 + 6;
    sss_object_t newKey;
    sss_key_store_t host_keystore;
    uint32_t keyId = se050_allocate_key();
    aes->keyId = keyId;
    int ret = BAD_MUTEX_E;
    
    if (wolfSSL_CryptHwMutexLock() == 0) {
        ret = 0;
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 55);
        }
        
        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&newKey, &host_keystore);
        }
/* aes_test runs perfectly with kKeyObject_Mode_Persistent, but might have caused previous board to have no free key slots */
        if (status == kStatus_SSS_Success) {
            status = sss_key_object_allocate_handle(&newKey, keyId, kSSS_KeyPart_Default,
                                                kSSS_CipherType_AES, len, 
                                                kKeyObject_Mode_Transient); //kKeyObject_Mode_Persistent
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_set_key(&host_keystore, &newKey, key, len,
                                       len * 8, NULL, 0);
        }
    }
    wolfSSL_CryptHwMutexUnLock();

    if (status != kStatus_SSS_Success) 
        ret = WC_HW_E;
    return ret;
}


int se050_aes_crypt(Aes* aes, const byte* in, byte* out, word32 sz, int dir, sss_algorithm_t algorithm)
{    
    sss_status_t    status;
    sss_object_t    keyObject;
    sss_mode_t      mode;
    sss_key_store_t host_keystore;
    int             ret = BAD_MUTEX_E;
    XMEMSET(&mode, 0, sizeof(mode));

    if (dir == AES_DECRYPTION)
        mode = kMode_SSS_Decrypt;
    else if (dir == AES_ENCRYPTION)
        mode = kMode_SSS_Encrypt;

    if (wolfSSL_CryptHwMutexLock() == 0) {
        ret = 0;

        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
     
        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 55);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&keyObject, &host_keystore);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_get_handle(&keyObject, aes->keyId);
        }

        /* The first call to this function needs an initialization call, subsequent calls just need to call update */
        if (aes->ctxInitDone == 0) {
            aes->ctxInitDone = 1;
            if (status == kStatus_SSS_Success) {
                status = sss_symmetric_context_init(&aes->aes_ctx, cfg_se050_i2c_pi,
                                                    &keyObject, algorithm, mode);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_cipher_init(&aes->aes_ctx, (uint8_t *)aes->reg, sizeof(aes->reg));
            }
        }
        if (status == kStatus_SSS_Success) {
            status = sss_cipher_update(&aes->aes_ctx, in, sz, out, &sz);
        }
    }
    wolfSSL_CryptHwMutexUnLock();

    if (status != kStatus_SSS_Success) 
        ret = WC_HW_E;
    return ret;
}

void se050_aes_free(Aes* aes)
{
    sss_status_t    status;
    sss_key_store_t host_keystore;
    sss_object_t    keyObject;
    aes->ctxInitDone = 0; /* sets back to zero to indicate that a free has been called */

    if (wolfSSL_CryptHwMutexLock() == 0) {    
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
     
        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 55);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&keyObject, &host_keystore);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_get_handle(&keyObject, aes->keyId);
        }
        sss_key_object_free(&keyObject);

        sss_symmetric_context_free(&aes->aes_ctx);

    }
    wolfSSL_CryptHwMutexUnLock();
}

#endif /* NO_AES */

#ifdef WOLFSSL_SP_MATH
    struct sp_int;
    #define MATH_INT_T struct sp_int
#elif defined(USE_FAST_MATH)
    struct fp_int;
    #define MATH_INT_T struct fp_int
#else
    struct mp_int;
	#define MATH_INT_T struct mp_int
#endif
struct ecc_key;
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>


#ifdef HAVE_ECC
int se050_ecc_sign_hash_ex(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, struct ecc_key* key)
{
    sss_status_t        status;
    sss_asymmetric_t    ctx_asymm;
    sss_key_store_t     host_keystore;
    sss_object_t        newKey;
    sss_algorithm_t     algorithm;
    XMEMSET(&algorithm, 0, sizeof(algorithm));

    uint32_t    keyId = se050_allocate_key();
    int         keysize = (word32)key->dp->size;
    int         ret = BAD_MUTEX_E;
    
    /* truncate if digest is larger than 64 */
    if (inLen > 64)
        inLen = 64;

    if (inLen == 20)
        algorithm = kAlgorithm_SSS_SHA1;
    else if (inLen == 28)
        algorithm = kAlgorithm_SSS_SHA224;
    else if (inLen == 32)
        algorithm = kAlgorithm_SSS_SHA256;
    else if (inLen == 48)
        algorithm = kAlgorithm_SSS_SHA384;
    else if (inLen == 64)
        algorithm = kAlgorithm_SSS_SHA512;


    if (wolfSSL_CryptHwMutexLock() == 0) {
        ret = 0;
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 70);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&newKey, &host_keystore);
        }


        if (status == kStatus_SSS_Success) {
            status = sss_key_object_allocate_handle(&newKey, keyId, kSSS_KeyPart_Pair, 
                                                kSSS_CipherType_EC_NIST_P, keysize, 
                                                kKeyObject_Mode_Transient);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_generate_key(&host_keystore, &newKey,
                                                    keysize * 8, NULL);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                                             &newKey, algorithm, kMode_SSS_Sign);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_asymmetric_sign_digest(&ctx_asymm, (uint8_t *)in, inLen,
                                                                   out, outLen);
        }
        sss_asymmetric_context_free(&ctx_asymm);


    }
    wolfSSL_CryptHwMutexUnLock();
    
    if (status != kStatus_SSS_Success) 
        ret = WC_HW_E;
    
    key->keyId = keyId;

    return ret;      
}

int se050_ecc_verify_hash_ex(const byte* hash, word32 hashLen, byte* signature,
                             word32 signatureLen, struct ecc_key* key, int* res)
{
    printf("runing verify!\n");

    sss_status_t        status;
    sss_asymmetric_t    ctx_asymm;
    sss_object_t        newKey;
    sss_key_store_t     host_keystore;
    sss_algorithm_t     algorithm;

    XMEMSET(&algorithm, 0, sizeof(algorithm));

    word32      derSz = 0;
    int         ret = WC_HW_E;
    byte*       derBuf;
    uint32_t    keyId = rand();
    int         keySize = (word32)key->dp->size;
                *res = 0;

    if (hashLen > 64)
        hashLen = 64;

    if (hashLen == 20)
        algorithm = kAlgorithm_SSS_SHA1;
    else if (hashLen == 28)
        algorithm = kAlgorithm_SSS_SHA224;
    else if (hashLen == 32)
        algorithm = kAlgorithm_SSS_SHA256;
    else if (hashLen == 48)
        algorithm = kAlgorithm_SSS_SHA384;
    else if (hashLen == 64)
        algorithm = kAlgorithm_SSS_SHA512;

    printf("KeyId 3 = %d\n", key->keyId);
    
    if (wolfSSL_CryptHwMutexLock() == 0) {
        if (key->keyId == 0) { //this is run when a key was not generated and was instead passed in
            
            ret = wc_EccKeyToPKCS8(key, NULL, &derSz);
            if (ret != -202){
                printf("first wc_EccKeyToPKCS8 failed\n");
                return -1;
            }
            derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_OPENSSL);
            ret = wc_EccKeyToPKCS8(key, derBuf, &derSz);
            if (ret <= 0){
                printf("second wc_EccKeyToPKCS8 failed, ret = %d\n", ret);
                return -1;
            }

            status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);   
  
            if (status == kStatus_SSS_Success) {
                status = sss_key_store_allocate(&host_keystore, 61);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_key_object_init(&newKey, &host_keystore);
            }


            if (status == kStatus_SSS_Success) {
                status = sss_key_object_allocate_handle(&newKey, keyId, kSSS_KeyPart_Pair,
                                                kSSS_CipherType_EC_NIST_P, derSz, 
                                                kKeyObject_Mode_Transient);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_key_store_set_key(&host_keystore, &newKey, derBuf,
                                                derSz, keySize * 8, NULL, 0);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                                            &newKey, algorithm, kMode_SSS_Verify);
            }

            printf("ran through inital key setup !\n");


            if (status == kStatus_SSS_Success) {
                status = sss_asymmetric_verify_digest(&ctx_asymm, (uint8_t *)hash,
                                               hashLen, signature, signatureLen);
            }

            sss_asymmetric_context_free(&ctx_asymm);
            printf("sss_asymmetric_verify_digest with set key worked!\n\n\n");

        }
        else if (key->keyId != 0) { //this is run after a sign function has taken place
            ret = 0;
            
            status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

            if (status == kStatus_SSS_Success)
                status = sss_key_store_allocate(&host_keystore, 60);

            if (status == kStatus_SSS_Success)
                status = sss_key_object_init(&newKey, &host_keystore);

            if (status == kStatus_SSS_Success)
                status = sss_key_object_get_handle(&newKey, key->keyId);
            
            if (status == kStatus_SSS_Success) {
                status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi,
                                            &newKey, algorithm, kMode_SSS_Verify);
            }
                
            if (status == kStatus_SSS_Success) {
                status = sss_asymmetric_verify_digest(&ctx_asymm, (uint8_t *)hash, 
                                               hashLen, signature, signatureLen);
            }

            sss_asymmetric_context_free(&ctx_asymm);
        }

    }
    wolfSSL_CryptHwMutexUnLock();

    if (status != kStatus_SSS_Success) 
        ret = WC_HW_E;

    printf("ran verify correctly!!\n\n\n");


    *res = 1;
    return 0;
}


int se050_ecc_free_key(struct ecc_key* key)
{
    sss_status_t    status = kStatus_SSS_Success;
    sss_object_t    keyObject;
    int             ret = WC_HW_E;
    sss_key_store_t host_keystore;

    /* less tha 10,000 as one example from test.c tried to free a key that was not created on the SE050 */
    if(key->keyId != 0 && key->keyId < 10000) {
        if (wolfSSL_CryptHwMutexLock() == 0) {
            ret = 0;

            status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

            if (status == kStatus_SSS_Success)
                status = sss_key_store_allocate(&host_keystore, 60);

            if (status == kStatus_SSS_Success)
                status = sss_key_object_init(&keyObject, &host_keystore);

            if (status == kStatus_SSS_Success)
                status = sss_key_object_get_handle(&keyObject, key->keyId);

            if (status == kStatus_SSS_Success)
                    sss_key_object_free(&keyObject);
        }
    }
    wolfSSL_CryptHwMutexUnLock();   

    if (status != kStatus_SSS_Success)
        ret = WC_CLEANUP_E;

    return ret;
}

int se050_ecc_create_key(struct ecc_key* key, int keyId, int keySize)
{
    sss_status_t            status = kStatus_SSS_Success;
    sss_object_t            keyPair;
    sss_key_store_t         host_keystore;
    
    uint8_t keyPairExport[128];
    size_t keyPairExportLen               = sizeof(keyPairExport);
    size_t keyPairExportBitLen            = sizeof(keyPairExport) * 8;
    int ret = WC_HW_E;


    if (wolfSSL_CryptHwMutexLock() == 0) {
        ret = 0;

        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);     
        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 60);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&keyPair, &host_keystore);
        }


        if (status == kStatus_SSS_Success) {
            status = sss_key_object_allocate_handle(&keyPair, keyId, kSSS_KeyPart_Pair,
                                            kSSS_CipherType_EC_NIST_P, 256, 
                                            kKeyObject_Mode_None); //kKeyObject_Mode_Transient
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_generate_key(&host_keystore, &keyPair, 256, NULL);
        }


        if (status == kStatus_SSS_Success) {
            status = sss_key_store_get_key(&host_keystore, &keyPair, keyPairExport,
                                         &keyPairExportLen, &keyPairExportBitLen);
        }
    }
    wolfSSL_CryptHwMutexUnLock();   

    if (status != kStatus_SSS_Success)
        ret = WC_CLEANUP_E;

    mp_read_unsigned_bin(key->pubkey.x, keyPairExport, keySize);
    mp_read_unsigned_bin(key->pubkey.y, keyPairExport + keySize, keySize);

    return ret;
}


int se050_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
                      word32* outlen)
{
    sss_status_t            status = kStatus_SSS_Success;
    sss_key_store_t         host_keystore;
    sss_key_store_t         host_keystore_2;
    sss_object_t            ref_private_key;
    sss_object_t            ref_public_key;
    sss_object_t            deriveKey;
    sss_derive_key_t        ctx_derive_key;
    int                     keyId = se050_allocate_key();
    int                     keySize = (word32)public_key->dp->size;
    size_t                  ecdhKeyLen = keySize;
    size_t                  ecdhKeyBitLen = keySize;
    int                     ret = WC_HW_E;

    
    if (public_key->keyId == 0) {
        public_key->keyId = se050_allocate_key();
        se050_ecc_create_key(public_key, public_key->keyId, keySize);

    }
    if (private_key->keyId == 0) {
        private_key->keyId = se050_allocate_key();
        se050_ecc_create_key(private_key, private_key->keyId, keySize);
    }

    if (wolfSSL_CryptHwMutexLock() == 0) {
        ret = 0;
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);
    
        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 60);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&ref_public_key, &host_keystore);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_get_handle(&ref_public_key, public_key->keyId);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_context_init(&host_keystore_2, cfg_se050_i2c_pi);     
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore_2, 60);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&ref_private_key, &host_keystore_2);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_get_handle(&ref_private_key, private_key->keyId);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&deriveKey, hostKeyStore);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_allocate_handle(&deriveKey,
                keyId,
                kSSS_KeyPart_Default, //try kSSS_KeyPart_Part, didn't have any noticable changes
                kSSS_CipherType_AES,
                ecdhKeyLen,
                kKeyObject_Mode_Transient); //try kKeyObject_Mode_None
        }    
        
        if (status == kStatus_SSS_Success) {
            status = sss_derive_key_context_init(&ctx_derive_key, cfg_se050_i2c_pi,
                                        &ref_private_key, kAlgorithm_SSS_ECDH,
                                        kMode_SSS_ComputeSharedSecret);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_derive_key_dh(&ctx_derive_key, &ref_public_key, &deriveKey);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_get_key(hostKeyStore, &deriveKey, out, outlen,
                                                                 &ecdhKeyBitLen);
        }
        if (ctx_derive_key.session != NULL)
            sss_derive_key_context_free(&ctx_derive_key);
        if (deriveKey.keyStore != NULL)
            sss_key_object_free(&deriveKey);

        if (status != kStatus_SSS_Success) 
            ret = WC_HW_E;
    }
    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519


int se050_ed25519_create_key(ed25519_key* key)
{
    printf("\n\nrunning se050_ed25519_create_key\n");
    sss_status_t    status;
    sss_key_store_t host_keystore;
    sss_object_t    newKey;
    int             keysize = ED25519_KEY_SIZE;
    uint32_t        keyId = se050_allocate_key();
                    key->keyId = keyId;
    int             ret = 0;

    if (wolfSSL_CryptHwMutexLock() == 0) {
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);     

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 55);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&newKey, &host_keystore);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_allocate_handle(&newKey, keyId, kSSS_KeyPart_Pair, 
                                                kSSS_CipherType_EC_TWISTED_ED, keysize, 
                                                kKeyObject_Mode_Transient);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_generate_key(&host_keystore, &newKey, keysize * 8, NULL);
        }

        if (status != kStatus_SSS_Success) {
            sss_key_object_free(&newKey);
            ret = WC_HW_E;
        }

    }
    wolfSSL_CryptHwMutexUnLock();


    printf("ran se050_ed25519_create_key\n\n\n");
    return ret;
}

void se050_ed25519_free_key(ed25519_key* key)
{
        sss_status_t status;
        sss_object_t newKey;
        sss_key_store_t host_keystore;

        if (wolfSSL_CryptHwMutexLock() == 0) {

            status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi); 
    
            if (status == kStatus_SSS_Success) {
                status = sss_key_store_allocate(&host_keystore, 60);
            }
            if (status == kStatus_SSS_Success) {
                status = sss_key_object_init(&newKey, &host_keystore);
            }
            if (status == kStatus_SSS_Success) {
                status = sss_key_object_get_handle(&newKey, key->keyId);
            }
            if (status == kStatus_SSS_Success) {
                sss_key_object_free(&newKey);
            }
        }
        wolfSSL_CryptHwMutexUnLock();
}


int se050_ed25519_sign_msg(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, ed25519_key* key)
{
    printf("\n\nhit se050_ed25519_sign_msg...\n");
    sss_status_t        status = kStatus_SSS_Success;
    sss_asymmetric_t    ctx_asymm;
    sss_key_store_t     host_keystore; 
    sss_object_t        newKey;
    int                 ret = 0;
                        inLen = 64;
                        *outLen = 64;

    /* used to fix edge case when ed25519_init is not called prior to signing */
    /* figure out if needed or not for -10801 */
    if (key->keyId > 10000 || key->keyId == 0) { 
        key->keyId = se050_allocate_key();
        ret = se050_ed25519_create_key(key);
        if (ret != 0) {
            printf("calling se050_ed25519_create_key failed..., ret = %d\n", ret);
        }

    }

    if (wolfSSL_CryptHwMutexLock() == 0 && ret == 0) {
        status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);     

        if (status == kStatus_SSS_Success) {
            status = sss_key_store_allocate(&host_keystore, 60);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_init(&newKey, &host_keystore);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_key_object_get_handle(&newKey, key->keyId);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi, 
                                &newKey, kAlgorithm_SSS_SHA512, kMode_SSS_Sign);
        }

        if (status == kStatus_SSS_Success) {
            status = sss_se05x_asymmetric_sign((sss_se05x_asymmetric_t *)&ctx_asymm,
                                             (uint8_t *)in, inLen, out, outLen);
        }

        if(status != kStatus_SSS_Success){
            printf("status != kStatus_SSS_Success, status = %d\n", status);
            sss_key_object_free(&newKey);
            ret = WC_HW_E;
        }
        sss_asymmetric_context_free(&ctx_asymm);
    }
    wolfSSL_CryptHwMutexUnLock();

    return ret;      
}


int se050_ed25519_verify_msg(const byte* signature, word32 signatureLen, const byte* msg,
                             word32 msgLen, struct ed25519_key* key, int* res)
{
    printf("runing se050_ed25519_verify_msg!\n");

    sss_status_t        status = kStatus_SSS_Success;
    sss_asymmetric_t    ctx_asymm;
    sss_object_t        newKey;
    sss_key_store_t     host_keystore;
    int                 ret = 0;
                        msgLen = 64;
                        *res = 1;

    if (wolfSSL_CryptHwMutexLock() == 0) {
            status = sss_key_store_context_init(&host_keystore, cfg_se050_i2c_pi);

            if (status == kStatus_SSS_Success) {
                status = sss_key_store_allocate(&host_keystore, 61);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_key_object_init(&newKey, &host_keystore);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_key_object_get_handle(&newKey, key->keyId);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_asymmetric_context_init(&ctx_asymm, cfg_se050_i2c_pi, 
                            &newKey, kAlgorithm_SSS_SHA512, kMode_SSS_Verify);
            }

            if (status == kStatus_SSS_Success) {
                status = sss_se05x_asymmetric_verify((sss_se05x_asymmetric_t *)&ctx_asymm,
                                             (uint8_t *)msg, msgLen, 
                                             (uint8_t *)signature, (size_t)signatureLen);
            }

            sss_asymmetric_context_free(&ctx_asymm);
    }
    wolfSSL_CryptHwMutexUnLock();

    if (status != kStatus_SSS_Success) {
        ret = WC_HW_E;
        *res = 0;
    }
    return ret;
}

#endif /* HAVE_ED25519 */

#endif /* SE050 */
