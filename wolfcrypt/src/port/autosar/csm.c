/* csm.c
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
#ifndef NO_WOLFSSL_AUTOSAR_CSM

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/port/autosar/Csm.h>
#include <wolfssl/wolfcrypt/port/autosar/CryIf.h>


/* AutoSAR 4.4 */
/* basic shim layer to plug in wolfSSL crypto */

#ifndef REDIRECTION_CONFIG
Crypto_JobRedirectionInfoType redirect = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
#else
Crypto_JobRedirectionInfoType redirect = {
    REDIRECTION_CONFIG,
    #ifdef REDIRECTION_IN1_KEYID
        REDIRECTION_IN1_KEYID,
    #else
        0,
    #endif

    #ifdef REDIRECTION_IN1_KEYELMID
        REDIRECTION_IN1_KEYELMID,
    #else
        0,
    #endif


    #ifdef REDIRECTION_IN2_KEYID
        REDIRECTION_IN2_KEYID,
    #else
        0,
    #endif

    #ifdef REDIRECTION_IN2_KEYELMID
        REDIRECTION_IN2_KEYELMID,
    #else
        0,
    #endif


    #ifdef REDIRECTION_IN3_KEYID
        REDIRECTION_IN3_KEYID,
    #else
        0,
    #endif

    #ifdef REDIRECTION_IN3_KEYELMID
        REDIRECTION_IN3_KEYELMID,
    #else
        0,
    #endif

    #ifdef REDIRECTION_OUT1_KEYID
        REDIRECTION_OUT1_KEYID,
    #else
        0,
    #endif

    #ifdef REDIRECTION_OUT1_KEYELMID
        REDIRECTION_OUT1_KEYELMID,
    #else
        0,
    #endif


    #ifdef REDIRECTION_OUT2_KEYID
        REDIRECTION_OUT2_KEYID,
    #else
        0,
    #endif

    #ifdef REDIRECTION_OUT2_KEYELMID
        REDIRECTION_OUT2_KEYELMID,
    #else
        0,
    #endif
};
#endif

static byte CsmDevErrorDetect = 1; /* flag for development error detection */

enum {
    CSM_E_PARAM_POINTER,
    CSM_E_SMALL_BUFFER,
    CSM_E_UNINT,
    CSM_E_INIT_FAILED,
    CSM_E_PROCESSING_MODE
};


/* development error reporting */
void ReportToDET(int err)
{
    if (CsmDevErrorDetect == 1) {
        switch (err) {
            case CSM_E_PARAM_POINTER:
                WOLFSSL_MSG("AutoSAR CSM_E_PARAM_POINTER error");
                break;

            case CSM_E_SMALL_BUFFER:
                WOLFSSL_MSG("AutoSAR CSM_E_SMALL_BUFFER error");
                break;

            case CSM_E_UNINT:
                WOLFSSL_MSG("AutoSAR CSM_E_UNINT error");
                break;

            case CSM_E_INIT_FAILED:
                WOLFSSL_MSG("AutoSAR CSM_E_INIT_FAILED error");
                break;

            case CSM_E_PROCESSING_MODE:
                WOLFSSL_MSG("AutoSAR CSM_E_PROCESSING_MODE error");
                break;

            default:
                WOLFSSL_MSG("AutoSAR Unknown error");
        }
    }
}


void Csm_Init(const Csm_ConfigType* config)
{
    (void)config;
    CryIf_Init(NULL);
}


/* getter function for CSM version info */
void Csm_GetVersionInfo(Std_VersionInfoType* version)
{
    if (version != NULL) {
        version->vendorID = 0; /* no vendor or module ID */
        version->moduleID = 0;
        version->sw_major_version = (LIBWOLFSSL_VERSION_HEX >> 24) & 0xFFF;
        version->sw_minor_version = (LIBWOLFSSL_VERSION_HEX >> 12) & 0xFFF;
        version->sw_patch_version = (LIBWOLFSSL_VERSION_HEX) & 0xFFF;
    }
}


/* creates a new job type and passes it down to CryIf
 *
 * return E_OK on success
 */
static Std_ReturnType CreateAndRunJobType(uint32 id,
        Crypto_JobPrimitiveInfoType* jobInfo, Crypto_JobInfoType* jobInfoType,
        const uint8* data, uint32 dataSz, uint8* out, uint32* outSz,
        Crypto_OperationModeType mode)
{
    WOLFSSL_JOBIO   jobIO;
    WOLFSSL_JOBTYPE jobType;

    XMEMSET(&jobIO, 0, sizeof(WOLFSSL_JOBIO));
    jobIO.inputPtr    = data;
    jobIO.inputLength = dataSz;
    jobIO.outputPtr   = out;
    jobIO.outputLengthPtr = outSz;
    jobIO.mode  = mode;

    jobType.jobId = id;
    jobType.jobState = CRYPTO_JOBSTATE_IDLE;
    jobType.jobPrimitiveInputOutput = jobIO;
    jobType.jobPrimitiveInfo = jobInfo;
    jobType.jobInfo = jobInfoType;
    jobType.jobRedirectionInfoRef = &redirect;

    return CryIf_ProcessJob(id, &jobType);
}


/* returns E_OK on success */
static Std_ReturnType Csm_CBC_Operation(uint32 id, Crypto_OperationModeType mode,
        const uint8* data, uint32 dataSz, uint8* out, uint32* outSz,
        Crypto_ServiceInfoType service)
{
    Crypto_JobInfoType jobInfoType;
    Crypto_PrimitiveInfoType pInfo;
    Crypto_JobPrimitiveInfoType jobInfo;

    Crypto_AlgorithmInfoType algorithm = {
        CRYPTO_ALGOFAM_AES,
        CRYPTO_ALGOFAM_NOT_SET,
        16, /* 128 bit key length */
        CRYPTO_ALGOMODE_CBC
    };

    jobInfoType.jobId = id;
    jobInfoType.jobPriority = 0;

    pInfo.resultLength = 16; /* 128 bit key length */
    pInfo.service = service;
    pInfo.algorithm = algorithm;

    jobInfo.callbackId = 0;
    jobInfo.primitiveInfo = &pInfo;
    jobInfo.cryIfKeyId = 0;
    jobInfo.processingType = CRYPTO_PROCESSING_SYNC;
    jobInfo.callbackUpdateNotification = FALSE;

    return CreateAndRunJobType(id, &jobInfo, &jobInfoType,
                data, dataSz, out, outSz, mode);
}


/* single shot encrypt
 * returns E_OK on success */
Std_ReturnType Csm_Encrypt(uint32 id, Crypto_OperationModeType mode,
        const uint8* data, uint32 dataSz, uint8* out, uint32* outSz)
{
    WOLFSSL_ENTER("Csm_Encrypt");
    return Csm_CBC_Operation(id, mode, data, dataSz, out, outSz,CRYPTO_ENCRYPT);
}


/* single shot decrypt
 * returns E_OK on success */
Std_ReturnType Csm_Decrypt(uint32 id, Crypto_OperationModeType mode,
        const uint8* data, uint32 dataSz, uint8* out, uint32* outSz)
{
    WOLFSSL_ENTER("Csm_Decrypt");
    return Csm_CBC_Operation(id, mode, data, dataSz, out, outSz,CRYPTO_DECRYPT);
}


/* returns E_OK on success */
Std_ReturnType Csm_RandomGenerate(uint32 id, uint8* out, uint32* outSz)
{
    Crypto_JobInfoType jobInfoType;
    Crypto_PrimitiveInfoType pInfo;
    Crypto_JobPrimitiveInfoType jobInfo;

    Crypto_AlgorithmInfoType algorithm = {
        CRYPTO_ALGOFAM_DRBG,
        CRYPTO_ALGOFAM_NOT_SET,
        0, /* key length */
        CRYPTO_ALGOMODE_NOT_SET
    };

    jobInfoType.jobId = id;
    jobInfoType.jobPriority = 0;

    pInfo.resultLength = 0;
    pInfo.service = CRYPTO_RANDOMGENERATE;
    pInfo.algorithm = algorithm;

    jobInfo.callbackId = 0;
    jobInfo.primitiveInfo = &pInfo;
    jobInfo.cryIfKeyId = 0;
    jobInfo.processingType = CRYPTO_PROCESSING_SYNC;
    jobInfo.callbackUpdateNotification = FALSE;

    return CreateAndRunJobType(id, &jobInfo, &jobInfoType,
                NULL, 0, out, outSz, CRYPTO_OPERATIONMODE_SINGLECALL);
}


/* returns E_OK on success */
Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 eId,
        const uint8* key, uint32 keySz)
{
    return CryIf_KeyElementSet(keyId, eId, key, keySz);
}

#endif /* NO_WOLFSSL_AUTOSAR_CSM */
#endif /* WOLFSSL_AUTOSAR */

