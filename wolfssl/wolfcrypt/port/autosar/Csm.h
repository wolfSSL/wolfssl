/* csm.h
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


/* specifications from AUTOSAR_SWS_CryptoServiceManager Release 4.4.0 */
/* naming scheme from 4.4 specifications, needed for applications to use
 * standardized names when linking */


#ifndef WOLFSSL_CSM_H
#define WOLFSSL_CSM_H

#ifdef WOLFSSL_AUTOSAR

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/autosar/StandardTypes.h>

#ifdef __cplusplus
    extern "C" {
#endif


/* Error values */
#define WOLFSSL_CSM_E_PARAM_POINTER  0x01
#define WOLFSSL_CSM_E_SMALL_BUFFER   0x03
#define WOLFSSL_CSM_E_PARAM_HANDLE   0x04
#define WOLFSSL_CSM_E_UNINIT         0x05
#define WOLFSSL_CSM_E_INIT_FAILED    0x07
#define WOLFSSL_CSM_E_PROCESSING_MOD 0x08


#define Crypto_JobType WOLFSSL_JOBTYPE
#define Crypto_JobPrimitiveInputOutputType WOLFSSL_JOBIO
#define Crypto_JobStateType WOLFSSL_JOBSTATE
#define Crypto_VerifyResultType WOLFSSL_VERIFY
#define Crypto_OperationModeType WOLFSSL_OMODE_TYPE

/* implementation specific structure, for now not used */
typedef struct Csm_ConfigType {
    void* heap;
} Csm_ConfigType;

typedef enum WOLFSSL_JOBSTATE {
    CRYPTO_JOBSTATE_IDLE = 0x00,
    CRYPTO_JOBSTATE_ACTIVE = 0x01
} WOLFSSL_JOBSTATE;

typedef enum WOLFSSL_VERIFY {
    CRYPTO_E_VER_OK = 0x00,
    CRYPTO_E_VER_NOT_OK = 0x01
} WOLFSSL_VERIFY;

/* operation modes <Rte_Csm_Type.h> */
typedef enum WOLFSSL_OMODE_TYPE {
    CRYPTO_OPERATIONMODE_START = 0x01,
    CRYPTO_OPERATIONMODE_UPDATE = 0x02,
    CRYPTO_OPERATIONMODE_STREAMSTART = 0x03,
    CRYPTO_OPERATIONMODE_FINISH = 0x04,
    CRYPTO_OPERATIONMODE_SINGLECALL = 0x07
} WOLFSSL_OMODE_TYPE;


typedef enum Crypto_ServiceInfoType {
    CRYPTO_ENCRYPT = 0x03,
    CRYPTO_DECRYPT = 0x04,
    CRYPTO_RANDOMGENERATE = 0x0B,

#ifdef CSM_UNSUPPORTED_ALGS
    /* not yet supported */
    CRYPTO_HASH = 0x00,
    CRYPTO_MACGENERATE = 0x01,
    CRYPTO_MACVERIFY = 0x02,
    CRYPTO_AEADENCRYPT = 0x05,
    CRYPTO_AEADDECRYPT = 0x06,
    CRYPTO_SIGNATUREGENERATE = 0x07,
    CRYPTO_SIGNATUREVERIFY = 0x08,
    CRYPTO_RANDOMSEED = 0x0C,
    CRYPTO_KEYGENERATE= 0x0D,
    CRYPTO_KEYDERIVE = 0x0E,
    CRYPTO_KEYEXCHANGECALCPUBVAL = 0x0F,
    CRYPTO_KEYEXCHANGECALCSECRET = 0x10,
    CRYPTO_CERTIFICATEPARSE = 0x11,
    CRYPTO_CERTIFICATEVERIFY = 0x12,
    CRYPTO_KEYSETVALID = 0x13,
#endif
} Crypto_ServiceInfoType;


typedef enum Crypto_AlgorithmModeType {
    CRYPTO_ALGOMODE_NOT_SET = 0x00,
    CRYPTO_ALGOMODE_CBC = 0x02,

#ifdef CSM_UNSUPPORTED_ALGS
    /* not yet supported */
    CRYPTO_ALGOMODE_ECB = 0x01,
    CRYPTO_ALGOMODE_CFB = 0x03,
    CRYPTO_ALGOMODE_OFB = 0x04,
    CRYPTO_ALGOMODE_CTR = 0x05,
    CRYPTO_ALGOMODE_GCM = 0x06,
    CRYPTO_ALGOMODE_XTS = 0x07,
    CRYPTO_ALGOMODE_RSAES_OAEP = 0x08,
    CRYPTO_ALGOMODE_RSAAES_PKCS1_V1_5 = 0x09,
    CRYPTO_ALGOMODE_RSAAES_PSS = 0x0A,
    CRYPTO_ALGOMODE_RSAASA_PKCS1_V1_5 = 0x0B,
    CRYPTO_ALGOMODE_8ROUNDS = 0x0C, /* ChaCha8 */
    CRYPTO_ALGOMODE_12ROUNDS = 0x0D, /* ChaCha12 */
    CRYPTO_ALGOMODE_20ROUNDS = 0x0E, /* ChaCha20 */
    CRYPTO_ALGOMODE_HMAC = 0x0F,
    CRYPTO_ALGOMODE_CMAC = 0x10,
    CRYPTO_ALGOMODE_GMAC = 0x11,
#endif
} Crypto_AlgorithmModeType;

typedef enum Crypto_AlgorithmFamilyType {
    CRYPTO_ALGOFAM_NOT_SET = 0x00,
    CRYPTO_ALGOFAM_SHA1 = 0x01,
    CRYPTO_ALGOFAM_SHA2_224 = 0x02,
    CRYPTO_ALGOFAM_SHA2_256 = 0x03,
    CRYPTO_ALGOFAM_SHA2_384 = 0x04,
    CRYPTO_ALGOFAM_SHA2_512 = 0x05,
    CRYPTO_ALGOFAM_SHA2_512_224 = 0x06,
    CRYPTO_ALGOFAM_SHA2_512_256 = 0x07,
    CRYPTO_ALGOFAM_SHA3_224 = 0x08,
    CRYPTO_ALGOFAM_SHA3_256 = 0x09,
    CRYPTO_ALGOFAM_SHA3_384 = 0x0A,
    CRYPTO_ALGOFAM_SHA3_512 = 0x0B,
    CRYPTO_ALGOFAM_SHAKE128 = 0x0C,
    CRYPTO_ALGOFAM_SHAKE256 = 0x0D,
    CRYPTO_ALGOFAM_RIPEMD160 = 0x0E,
    CRYPTO_ALGOFAM_BLAKE_1_256 = 0x0D,
    CRYPTO_ALGOFAM_BLAKE_1_512 = 0x10,
    CRYPTO_ALGOFAM_BLAKE_2s_256 = 0x11,
    CRYPTO_ALGOFAM_BLAKE_2s_512 = 0x12,
    CRYPTO_ALGOFAM_3DES = 0x13,
    CRYPTO_ALGOFAM_AES = 0x14,
    CRYPTO_ALGOFAM_CHACHA = 0x15,
    CRYPTO_ALGOFAM_RSA = 0x16,
    CRYPTO_ALGOFAM_ED25519 = 0x17,
    CRYPTO_ALGOFAM_BRAINPOOL = 0x18,
    CRYPTO_ALGOFAM_ECCNIST = 0x19,
    CRYPTO_ALGOFAM_RNG = 0x1B,
    CRYPTO_ALGOFAM_SIPHASH = 0x1C,
    CRYPTO_ALGOFAM_ECIES = 0x1D,
    CRYPTO_ALGOFAM_ECCANSI = 0x1E,
    CRYPTO_ALGOFAM_ECCSEC = 0x1F,
    CRYPTO_ALGOFAM_DRBG = 0x20,
    CRYPTO_ALGOFAM_FIPS186 = 0x21, /* random number gen according to FIPS 186 */
    CRYPTO_ALGOFAM_PADDING_PKCS7 = 0x22,
    CRYPTO_ALGOFAM_PADDING_ONEWITHZEROS = 0x23 /* fill with 0's but first bit
                                                * after data is 1 */
} Crypto_AlgorithmFamilyType;

typedef enum Crypto_KeyID {
    /* Cipher/AEAD */
    CRYPTO_KE_CIPHER_KEY = 0x01,
    CRYPTO_KE_CIPHER_IV =  0x05,
    CRYPTO_KE_CIPHER_PROOF = 0x06,
    CRYPTO_KE_CIPHER_2NDKEY =  0x07
} Crypto_KeyID;


typedef enum Crypto_ProcessingType {
    CRYPTO_PROCESSING_ASYNC = 0x00,
    CRYPTO_PROCESSING_SYNC = 0x01
} Crypto_ProcessingType;


/* removed const on elements @TODO which is different than 8.2.8 in
 * AUTOSAR_SWS_CryptoServiceManager.pdf */
typedef struct Crypto_JobInfoType {
    uint32 jobId;
    uint32 jobPriority;
} Crypto_JobInfoType;

typedef struct Crypto_JobRedirectionInfoType {
    uint8 redirectionConfig;
    uint32 inputKeyId;
    uint32 inputKeyElementId;
    uint32 secondaryInputKeyId;
    uint32 secondaryInputKeyElementId;
    uint32 tertiaryInputKeyId;
    uint32 tertiaryInputKeyElementId;
    uint32 outputKeyId;
    uint32 outputKeyElementId;
    uint32 secondaryOutputKeyId;
    uint32 secondaryOutputKeyElementId;
} Crypto_JobRedirectionInfoType;


enum Crypto_InputOutputRedirectionConfigType {
    CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT = 0x01,
    CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT = 0x02,
    CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT = 0x04,
    CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT = 0x10,
    CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT = 0x20
};


typedef struct WOLFSSL_JOBIO {
    const uint8 *inputPtr;
    uint32       inputLength;
    const uint8 *secondaryInputPtr; /* secondary data for verify */
    uint32       secondaryInputLength;
    const uint8 *tertiaryInputPtr; /* third input data for verify */
    uint32       tertiaryInputLength;
    uint8       *outputPtr;
    uint32      *outputLengthPtr;
    uint8       *secondaryOutputPtr;
    uint32      *secondaryOutputLengthPtr;
    uint64       input64; /* input parameter */
    Crypto_VerifyResultType *verifyPtr;
    uint64      *output64Ptr;
    Crypto_OperationModeType mode;
    uint32       cryIfKeyId;
    uint32       targetCryIfKeyId;
} WOLFSSL_JOBIO;


typedef struct Crypto_AlgorithmInfoType {
    Crypto_AlgorithmFamilyType family;
    Crypto_AlgorithmFamilyType secondaryFamily; /* second algo type if needed */
    uint32 keyLength;
    Crypto_AlgorithmModeType mode; /* i.e. CBC / RSA OAEP */
} Crypto_AlgorithmInfoType;


/* removed const on all 3 elements which is slightly different than AutoSAR */
typedef struct Crypto_PrimitiveInfoType {
    uint32 resultLength;
    Crypto_ServiceInfoType service;
    Crypto_AlgorithmInfoType algorithm;
} Crypto_PrimitiveInfoType;


typedef struct Crypto_JobPrimitiveInfoType {
    uint32 callbackId;
    const Crypto_PrimitiveInfoType *primitiveInfo;
    uint32 cryIfKeyId;
    Crypto_ProcessingType processingType;
    boolean callbackUpdateNotification;
} Crypto_JobPrimitiveInfoType;


typedef struct WOLFSSL_JOBTYPE {
    uint32 jobId;
    WOLFSSL_JOBSTATE jobState;
    WOLFSSL_JOBIO    jobPrimitiveInputOutput;
    const Crypto_JobPrimitiveInfoType* jobPrimitiveInfo;
    const Crypto_JobInfoType* jobInfo;
    Crypto_JobRedirectionInfoType* jobRedirectionInfoRef;
} WOLFSSL_JOBTYPE;


WOLFSSL_API void Csm_Init(const Csm_ConfigType* config);

/* can be called before init, all else return WOLFSSL_CSM_E_UNINIT */
WOLFSSL_API void Csm_GetVersionInfo(Std_VersionInfoType* version);

WOLFSSL_API Std_ReturnType Csm_Decrypt(uint32 jobId,
        Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
        uint8* resultPtr, uint32* resultLengthPtr);
WOLFSSL_API Std_ReturnType Csm_Encrypt(uint32 jobId,
        Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
        uint8* resultPtr, uint32* resultLengthPtr);
WOLFSSL_API Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 keyElementId,
        const uint8* keyPtr, uint32 keyLength);
WOLFSSL_API Std_ReturnType Csm_RandomGenerate( uint32 jobId, uint8* resultPtr,
        uint32* resultLengthPtr);
WOLFSSL_LOCAL void ReportToDET(int err);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_AUTOSAR */
#endif /* WOLFSSL_CSM_H */

