/* crypto.c
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

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_AUTOSAR
#ifndef NO_WOLFSSL_AUTOSAR_CRYPTO

#include <wolfssl/wolfcrypt/port/autosar/Csm.h>
#include <wolfssl/wolfcrypt/port/autosar/Crypto.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Low level crypto (software based driver) where wolfCrypt gets called */
Std_ReturnType wolfSSL_Crypto_CBC(Crypto_JobType* job);
Std_ReturnType wolfSSL_Crypto(Crypto_JobType* job);
Std_ReturnType wolfSSL_Crypto_RNG(Crypto_JobType* job);


#ifndef MAX_KEYSTORE
    #define MAX_KEYSTORE 15
#endif
#ifndef MAX_JOBS
    #define MAX_JOBS 10
#endif

static wolfSSL_Mutex crypto_mutex;
struct Keys {
    uint32 keyLen;
    uint32 eId;

    /* raw key */
    uint8 key[AES_MAX_KEY_SIZE/WOLFSSL_BIT_SIZE];
} Keys;


struct Jobs {
    uint32 jobId;
    uint8  inUse; /* is the key available for use */
    Aes aes;
} Jobs;

static struct Jobs activeJobs[MAX_JOBS];
static struct Keys keyStore[MAX_KEYSTORE];


/* tries to get a key of type eId
 * returns 0 on success
 */
static int GetKey(Crypto_JobType* job, uint32 eId, uint8 **key, uint32 *keySz)
{
    int i, ret = 0;

    if (key == NULL || keySz == NULL || *key != NULL) {
        WOLFSSL_MSG("Bad parameter to GetKey");
        return -1;
    }

    if (wc_LockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock crypto mutex");
        return -1;
    }

#ifdef REDIRECTION_CONFIG
    /* keys should be set... */
    if (job->jobRedirectionInfoRef == NULL) {
        WOLFSSL_MSG("Issue with getting key redirection");
        wc_UnLockMutex(&crypto_mutex);
        return -1;
    }

    /* @TODO sanity checks on setup... uint8 redirectionConfig; */
    switch (eid) {
        case job->jobRedirectionInfoRef->inputKeyElementId:
            if (job->jobRedirectionInfoRef->inputKeyId >= MAX_KEYSTORE) {
                WOLFSSL_MSG("Bogus input key ID redirection (too large)");
                ret = -1;
            }
            else {
                i = job->jobRedirectionInfoRef->inputKeyId;
                *key   = keyStore[i].key;
                *keySz = keyStore[i].keyLen;
            }
            break;
        case job->jobRedirectionInfoRef->secondaryInputKeyElementId:
            if (job->jobRedirectionInfoRef->secondaryInputKeyId >= MAX_KEYSTORE) {
                WOLFSSL_MSG("Bogus input key ID redirection (too large)");
                ret = -1;
            }
            else {
                i = job->jobRedirectionInfoRef->secondaryInputKeyId;
                *key   = keyStore[i].key;
                *keySz = keyStore[i].keyLen;
            }
            break;
        case job->jobRedirectionInfoRef->tertiaryInputKeyElementId:
            if (job->jobRedirectionInfoRef->tertiaryInputKeyId >= MAX_KEYSTORE) {
                WOLFSSL_MSG("Bogus input key ID redirection (too large)");
                ret = -1;
            }
            else {
                i = job->jobRedirectionInfoRef->tertiaryInputKeyId;
                *key   = keyStore[i].key;
                *keySz = keyStore[i].keyLen;
            }
            break;
        default:
            WOLFSSL_MSG("Unknown key element ID");
            ret = -1;
            break;
    }
#else
    /* find first key of key element type */
    for (i = 0; i < MAX_KEYSTORE; i++) {
        if (keyStore[i].eId == eId && keyStore[i].keyLen ==
                job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength) {
            /* found matching key available, use it */
            *key = keyStore[i].key;
            *keySz = keyStore[i].keyLen;
        }
    }
#endif

    if (*key == NULL) {
        WOLFSSL_MSG("Unable to find an available key");
        ret = -1;
    }

    if (wc_UnLockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock crypto mutex");
        ret = -1;
    }
    return ret;
}


/* returns a pointer to the Aes struct on success, NULL on failure */
static Aes* GetAesStruct(Crypto_JobType* job)
{
    int i;

    for (i = 0; i < MAX_JOBS; i++) {
        if (activeJobs[i].inUse == 1 && activeJobs[i].jobId == job->jobId) {
            return &activeJobs[i].aes;
        }
    }
    return NULL;
}


/* returns a pointer to the Aes struct on success, NULL on failure */
static Aes* NewAesStruct(Crypto_JobType* job)
{
    int i;

    for (i = 0; i < MAX_JOBS; i++) {
        if (activeJobs[i].inUse == 0) {
            int ret;

            activeJobs[i].inUse = 1;
            activeJobs[i].jobId = job->jobId;
            ret = wc_AesInit(&activeJobs[i].aes, NULL, INVALID_DEVID);
            if (ret != 0) {
                WOLFSSL_MSG("Error initializing AES structure");
                return NULL;
            }
            return &activeJobs[i].aes;
        }
    }
    return NULL;
}


/* free's up the use of an AES structure */
static void FreeAesStruct(Crypto_JobType* job) {
    int i;

    for (i = 0; i < MAX_JOBS; i++) {
        if (activeJobs[i].inUse == 1 && activeJobs[i].jobId == job->jobId) {
            break;
        }
    }

    if (i >= MAX_JOBS) {
        WOLFSSL_MSG("Error finding AES structure");
    }
    else {
        wc_AesFree(&activeJobs[i].aes);
        activeJobs[i].inUse = 0;
        activeJobs[i].jobId = 0;
    }
}


/* returns E_OK on success */
Std_ReturnType wolfSSL_Crypto_CBC(Crypto_JobType* job)
{
    Std_ReturnType ret = E_OK;
    int encrypt;
    Aes* aes ;

    encrypt = (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_ENCRYPT)
        ? AES_ENCRYPTION : AES_DECRYPTION;

    /* check if key should be set */
    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_START) != 0) {
        uint8 *key   = NULL;
        uint8 *iv    = NULL;
        uint32 keySz = 0;
        uint32 ivSz  = 0;

        if (GetKey(job, CRYPTO_KE_CIPHER_KEY, &key, &keySz) != 0) {
            WOLFSSL_MSG("Crypto error with getting a key");
            return E_NOT_OK;
        }

        if (GetKey(job, CRYPTO_KE_CIPHER_IV, &iv, &ivSz) != 0) {
            WOLFSSL_MSG("Crypto error with getting an IV");
            return E_NOT_OK;
        }

        if (iv != NULL && ivSz < WC_AES_BLOCK_SIZE) {
            WOLFSSL_MSG("Error IV is too small");
            return E_NOT_OK;
        }

        aes = NewAesStruct(job);
        if (aes == NULL) {
            WOLFSSL_MSG("Unable to get AES structure for use");
            return E_NOT_OK;
        }

        if (wc_AesSetKey(aes, key, keySz, iv, encrypt) != 0) {
            WOLFSSL_MSG("Crypto error setting up AES key");
            return E_NOT_OK;
        }
        ForceZero(key, keySz);
    }

    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_UPDATE)
            != 0) {
        aes = GetAesStruct(job);
        if (aes == NULL) {
            WOLFSSL_MSG("Error finding AES structure");
            return E_NOT_OK;
        }

        if (encrypt == AES_ENCRYPTION) {
            if (wc_AesCbcEncrypt(aes, job->jobPrimitiveInputOutput.outputPtr,
                    job->jobPrimitiveInputOutput.inputPtr,
                    job->jobPrimitiveInputOutput.inputLength) != 0) {
                WOLFSSL_MSG("AES-CBC encrypt error");
                return E_NOT_OK;
            }
        }
        else {
            if (wc_AesCbcDecrypt(aes, job->jobPrimitiveInputOutput.outputPtr,
                    job->jobPrimitiveInputOutput.inputPtr,
                    job->jobPrimitiveInputOutput.inputLength) != 0) {
                WOLFSSL_MSG("AES-CBC decrypt error");
                return E_NOT_OK;
            }
        }
    }

    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_FINISH)
            != 0) {
        FreeAesStruct(job);
    }

    return ret;
}


/* returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType wolfSSL_Crypto(Crypto_JobType* job)
{
    Std_ReturnType ret = E_OK;

    WOLFSSL_ENTER("wolfSSL_Crypto");

    /* switch on encryption type */
    switch (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode) {
        case CRYPTO_ALGOMODE_CBC:
            ret = wolfSSL_Crypto_CBC(job);
            break;

        case CRYPTO_ALGOMODE_NOT_SET:
            WOLFSSL_MSG("Encrypt algo mode not set!");
            ret = E_NOT_OK;
            break;

        default:
            WOLFSSL_MSG("Unsupported encryption mode");
            ret = E_NOT_OK;
            break;
    }

    WOLFSSL_LEAVE("wolfSSL_Crypto", ret);
    return ret;
}

static WC_RNG rng;
static wolfSSL_Mutex rngMutex;
static volatile byte rngInit = 0;

/* returns E_OK on success */
Std_ReturnType wolfSSL_Crypto_RNG(Crypto_JobType* job)
{
    int ret;

    uint8  *out   = job->jobPrimitiveInputOutput.outputPtr;
    uint32 *outSz = job->jobPrimitiveInputOutput.outputLengthPtr;

    if (outSz == NULL || out == NULL) {
        WOLFSSL_MSG("Bad parameter passed into wolfSSL_Crypto_RNG");
        return E_NOT_OK;
    }

    if (rngInit == 1) {
        if (wc_LockMutex(&rngMutex) != 0) {
            WOLFSSL_MSG("Error locking RNG mutex");
            return E_NOT_OK;
        }
    }

    if (rngInit == 0) {
        if (wc_InitMutex(&rngMutex) != 0) {
            WOLFSSL_MSG("Error initializing RNG mutex");
            return E_NOT_OK;
        }

        if (wc_LockMutex(&rngMutex) != 0) {
            WOLFSSL_MSG("Error locking RNG mutex");
            return E_NOT_OK;
        }

        ret = wc_InitRng_ex(&rng, NULL, 0);
        if (ret != 0) {
            WOLFSSL_MSG("Error initializing RNG");
            wc_UnLockMutex(&rngMutex);
            return E_NOT_OK;
        }
        rngInit = 1;
    }

    ret = wc_RNG_GenerateBlock(&rng, out, *outSz);
    if (ret != 0) {
        WOLFSSL_MSG("Unable to generate random values");
        ret = wc_FreeRng(&rng);
        if (ret != 0) {
            WOLFSSL_MSG("Error free'ing RNG");
        }
        rngInit = 0;
        wc_UnLockMutex(&rngMutex);
        return E_NOT_OK;
    }

    if (wc_UnLockMutex(&rngMutex) != 0) {
        WOLFSSL_MSG("Error unlocking RNG mutex");
        return E_NOT_OK;
    }

    return E_OK;
}


/* returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job)
{
    Std_ReturnType ret = E_OK;
    (void)objectId;

    WOLFSSL_ENTER("Crypto_ProcessJob");
    if (job == NULL) {
        WOLFSSL_MSG("Bad parameter passed to Crypto_ProcessJob");
        ret = E_NOT_OK;
    }

    /* only handle synchronous jobs */
    if (ret == E_OK &&
            job->jobPrimitiveInfo->processingType != CRYPTO_PROCESSING_SYNC) {
        WOLFSSL_MSG("Crypto only supporting synchronous jobs");
        ret = E_NOT_OK;
    }

    if (ret == E_OK) {
        job->jobState = CRYPTO_JOBSTATE_ACTIVE;
        switch (job->jobPrimitiveInfo->primitiveInfo->service) {
            case CRYPTO_ENCRYPT:
                ret = wolfSSL_Crypto(job);
                break;

            case CRYPTO_DECRYPT:
                ret = wolfSSL_Crypto(job);
                break;

            case CRYPTO_RANDOMGENERATE:
                ret = wolfSSL_Crypto_RNG(job);
                break;

            default:
                WOLFSSL_MSG("Unsupported Crypto service");
                ret = E_NOT_OK;
                break;
        }
        job->jobState = CRYPTO_JOBSTATE_IDLE;
    }

    WOLFSSL_LEAVE("Crypto_ProcessJob", ret);
    return ret;
}


/* config currently not used, should always be null */
void Crypto_Init(const Crypto_ConfigType* config)
{
    if (wc_InitMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Issues setting up crypto mutex");
    }
    XMEMSET(&keyStore, 0, MAX_KEYSTORE * sizeof(Keys));
    XMEMSET(&activeJobs, 0, MAX_JOBS * sizeof(Jobs));
    (void)config;
}


/* returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType Crypto_KeyElementSet(uint32 keyId, uint32 eId, const uint8* key,
        uint32 keySz)
{
    Std_ReturnType ret = E_OK;

    if (key == NULL || keySz == 0 || keyId >= MAX_KEYSTORE) {
        WOLFSSL_MSG("Bad argument to Crypto_KeyElementSet");
        ret = E_NOT_OK;
    }

    if (ret == E_OK && wc_LockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock crypto mutex");
        ret = E_NOT_OK;
    }

    if (ret == E_OK) {
        if (keySz > sizeof(keyStore[keyId].key)) {
            ret =  E_NOT_OK;
        }
        if (ret == E_OK) {
            WOLFSSL_MSG("Setting new key");
            keyStore[keyId].eId   = eId;
            XMEMCPY(keyStore[keyId].key, key, keySz);
            keyStore[keyId].keyLen = keySz;
        }

        if (wc_UnLockMutex(&crypto_mutex) != 0) {
            WOLFSSL_MSG("Unable to unlock crypto mutex");
            ret = E_NOT_OK;
        }
    }

    return ret;
}
#endif /* NO_WOLFSSL_AUTOSAR_CRYPTO */
#endif /* WOLFSSL_AUTOSAR */

