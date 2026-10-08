/* csm.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <wolfssl/wolfcrypt/aes.h>
#ifdef WOLFSSL_AUTOSAR_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif


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

#ifdef WOLFSSL_AUTOSAR_DET
    /* Supplied by the stack's DET module. Declared here rather than pulled
     * from Det.h so this port does not depend on an AUTOSAR include tree.
     *
     * Std_ReturnType, as the specification declares it -- declaring it void
     * would be an incompatible type for the real definition, which is
     * undefined behaviour across translation units and can be caught at link
     * time under LTO. The value says whether the DET accepted the report and
     * there is nothing useful to do with it here. */
    extern Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId,
            uint8 ApiId, uint8 ErrorId);
#endif

/* Only the log path uses this, and WOLFSSL_MSG() compiles to nothing without
 * DEBUG_WOLFSSL, so it needs both guards or it is an unused function. */
#if !defined(WOLFSSL_AUTOSAR_DET) && defined(DEBUG_WOLFSSL)
static const char* CsmErrorName(uint8 errorId)
{
    switch (errorId) {
        case WOLFSSL_CSM_E_PARAM_POINTER:
            return "CSM_E_PARAM_POINTER";
        case WOLFSSL_CSM_E_SMALL_BUFFER:
            return "CSM_E_SMALL_BUFFER";
        case WOLFSSL_CSM_E_PARAM_HANDLE:
            return "CSM_E_PARAM_HANDLE";
        case WOLFSSL_CSM_E_UNINIT:
            return "CSM_E_UNINIT";
        case WOLFSSL_CSM_E_INIT_FAILED:
            return "CSM_E_INIT_FAILED";
        case WOLFSSL_CSM_E_PROCESSING_MODE:
            return "CSM_E_PROCESSING_MODE";
        default:
            return "unknown CSM error";
    }
}
#endif /* !WOLFSSL_AUTOSAR_DET && DEBUG_WOLFSSL */


/* Development error reporting, shaped after Det_ReportError() so a real DET
 * can be wired in with -DWOLFSSL_AUTOSAR_DET.
 *
 * The error IDs are the ones the CSM specification assigns, taken from Csm.h.
 * An earlier version of this port reported a local 0-based enum instead, so
 * every ID that would have reached a DET was wrong. */
void ReportToDET(uint16 moduleId, uint8 instanceId, uint8 apiId, uint8 errorId)
{
    if (CsmDevErrorDetect != 1) {
        return;
    }

#ifdef WOLFSSL_AUTOSAR_DET
    (void)Det_ReportError(moduleId, instanceId, apiId, errorId);
#else
    #ifdef DEBUG_WOLFSSL
        WOLFSSL_MSG(CsmErrorName(errorId));
    #endif
    (void)moduleId;
    (void)instanceId;
    (void)apiId;
    (void)errorId;
#endif
}


void Csm_Init(const Csm_ConfigType* config)
{
    CryIf_ConfigType cryIfConfig;

    /* No config means software with the default allocator, which is what this
     * port did before heap and devId existed. */
    if (config != NULL) {
        cryIfConfig.heap  = config->heap;
        cryIfConfig.devId = config->devId;
    }
    else {
        cryIfConfig.heap  = NULL;
        cryIfConfig.devId = WOLFSSL_AUTOSAR_DEVID;
    }

    CryIf_Init(&cryIfConfig);
}


/* Cancels a job, releasing the driver slot it holds. See Csm.h for when this
 * is the right thing to call and for the one rule it comes with -- do not
 * cancel a job another thread is driving.
 *
 * returns E_OK when a slot was released */
Std_ReturnType Csm_CancelJob(uint32 jobId, Crypto_OperationModeType mode)
{
    WOLFSSL_JOBTYPE jobType;

    /* The driver needs the jobId to find the slot and nothing else, but a
     * half-initialized job has a way of growing readers later. */
    XMEMSET(&jobType, 0, sizeof(jobType));
    jobType.jobId    = jobId;
    jobType.jobState = CRYPTO_JOBSTATE_ACTIVE;

    /* Only synchronous jobs exist here, so there is no partial cancel to
     * express; the specification's mode has nothing to select. */
    (void)mode;

    return CryIf_CancelJob(jobId, &jobType);
}


/* getter function for CSM version info */
void Csm_GetVersionInfo(Std_VersionInfoType* version)
{
    if (version != NULL) {
        version->vendorID = WOLFSSL_CSM_VENDOR_ID;
        version->moduleID = WOLFSSL_CSM_MODULE_ID;
        /* The shim has no version of its own, so report wolfSSL's. */
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
static Std_ReturnType Csm_CBC_Operation(uint32 id, uint32 keyId,
        Crypto_OperationModeType mode,
        const uint8* data, uint32 dataSz, uint8* out, uint32* outSz,
        Crypto_ServiceInfoType service)
{
    Crypto_JobInfoType jobInfoType;
    Crypto_PrimitiveInfoType pInfo;
    Crypto_JobPrimitiveInfoType jobInfo;

    Crypto_AlgorithmInfoType algorithm = {
        CRYPTO_ALGOFAM_AES,
        CRYPTO_ALGOFAM_NOT_SET,
        /* 0 means "use whatever length the keystore holds", so a 128,
         * 192 or 256 bit key set with Csm_KeyElementSet() all work.
         * Pinning this to 16 made the driver's key lookup reject
         * anything but AES-128. */
        0,
        CRYPTO_ALGOMODE_CBC
    };

    jobInfoType.jobId = id;
    jobInfoType.jobPriority = 0;

    pInfo.resultLength = WC_AES_BLOCK_SIZE;
    pInfo.service = service;
    pInfo.algorithm = algorithm;

    jobInfo.callbackId = 0;
    jobInfo.primitiveInfo = &pInfo;
    /* The slot holding the key element, or WOLFSSL_CSM_KEY_ID_ANY to let the
     * driver resolve it. Cipher and MAC keys share an element ID, so naming
     * the slot is the only way a build using both services can keep them
     * apart. */
    jobInfo.cryIfKeyId = keyId;
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
    return wolfSSL_Csm_EncryptWithKey(id, WOLFSSL_CSM_KEY_ID_ANY, mode, data,
            dataSz, out, outSz);
}


/* single shot decrypt
 * returns E_OK on success */
Std_ReturnType Csm_Decrypt(uint32 id, Crypto_OperationModeType mode,
        const uint8* data, uint32 dataSz, uint8* out, uint32* outSz)
{
    WOLFSSL_ENTER("Csm_Decrypt");
    return wolfSSL_Csm_DecryptWithKey(id, WOLFSSL_CSM_KEY_ID_ANY, mode, data,
            dataSz, out, outSz);
}


/* As Csm_Encrypt() but naming the keystore slot holding the cipher key. See
 * Csm.h -- a wolfSSL extension, not AUTOSAR 4.4 API.
 * returns E_OK on success */
Std_ReturnType wolfSSL_Csm_EncryptWithKey(uint32 id, uint32 keyId,
        Crypto_OperationModeType mode, const uint8* data, uint32 dataSz,
        uint8* out, uint32* outSz)
{
    WOLFSSL_ENTER("wolfSSL_Csm_EncryptWithKey");
    return Csm_CBC_Operation(id, keyId, mode, data, dataSz, out, outSz,
            CRYPTO_ENCRYPT);
}


/* As Csm_Decrypt() but naming the keystore slot holding the cipher key.
 * returns E_OK on success */
Std_ReturnType wolfSSL_Csm_DecryptWithKey(uint32 id, uint32 keyId,
        Crypto_OperationModeType mode, const uint8* data, uint32 dataSz,
        uint8* out, uint32* outSz)
{
    WOLFSSL_ENTER("wolfSSL_Csm_DecryptWithKey");
    return Csm_CBC_Operation(id, keyId, mode, data, dataSz, out, outSz,
            CRYPTO_DECRYPT);
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


#ifdef WOLFSSL_AUTOSAR_CMAC
/* Shared setup for MAC generate and verify.
 * returns E_OK on success */
static Std_ReturnType Csm_CMAC_Operation(uint32 id, uint32 keyId,
        Crypto_OperationModeType mode, const uint8* data, uint32 dataSz,
        uint8* out, uint32* outSz, const uint8* mac, uint32 macSz,
        Crypto_VerifyResultType* verify, Crypto_ServiceInfoType service)
{
    WOLFSSL_JOBIO   jobIO;
    WOLFSSL_JOBTYPE jobType;

    Crypto_JobInfoType jobInfoType;
    Crypto_PrimitiveInfoType pInfo;
    Crypto_JobPrimitiveInfoType jobInfo;

    Crypto_AlgorithmInfoType algorithm = {
        CRYPTO_ALGOFAM_AES,
        CRYPTO_ALGOFAM_NOT_SET,
        0, /* key length comes from the keystore */
        CRYPTO_ALGOMODE_CMAC
    };

    jobInfoType.jobId = id;
    jobInfoType.jobPriority = 0;

    pInfo.resultLength = WC_CMAC_TAG_MAX_SZ;
    pInfo.service = service;
    pInfo.algorithm = algorithm;

    jobInfo.callbackId = 0;
    jobInfo.primitiveInfo = &pInfo;
    /* see Csm_CBC_Operation() -- the MAC key shares element ID 0x01 with the
     * cipher key, so this is what keeps the two apart */
    jobInfo.cryIfKeyId = keyId;
    jobInfo.processingType = CRYPTO_PROCESSING_SYNC;
    jobInfo.callbackUpdateNotification = FALSE;

    /* CreateAndRunJobType() covers the cipher services, which have no
     * secondary input and no verify result, so build the job here instead */
    XMEMSET(&jobIO, 0, sizeof(WOLFSSL_JOBIO));
    jobIO.inputPtr    = data;
    jobIO.inputLength = dataSz;
    jobIO.outputPtr   = out;
    jobIO.outputLengthPtr = outSz;
    jobIO.secondaryInputPtr    = mac;
    jobIO.secondaryInputLength = macSz;
    jobIO.verifyPtr   = verify;
    jobIO.mode        = mode;

    jobType.jobId = id;
    jobType.jobState = CRYPTO_JOBSTATE_IDLE;
    jobType.jobPrimitiveInputOutput = jobIO;
    jobType.jobPrimitiveInfo = &jobInfo;
    jobType.jobInfo = &jobInfoType;
    jobType.jobRedirectionInfoRef = &redirect;

    return CryIf_ProcessJob(id, &jobType);
}


/* AES-CMAC generate. macLengthPtr is in bytes: on entry the size of the macPtr
 * buffer, on a successful FINISH the number of bytes written.
 * returns E_OK on success */
Std_ReturnType Csm_MacGenerate(uint32 id, Crypto_OperationModeType mode,
        const uint8* data, uint32 dataSz, uint8* mac, uint32* macSz)
{
    WOLFSSL_ENTER("Csm_MacGenerate");
    return wolfSSL_Csm_MacGenerateWithKey(id, WOLFSSL_CSM_KEY_ID_ANY, mode,
            data, dataSz, mac, macSz);
}


/* As Csm_MacGenerate() but naming the keystore slot holding the MAC key.
 * returns E_OK on success */
Std_ReturnType wolfSSL_Csm_MacGenerateWithKey(uint32 id, uint32 keyId,
        Crypto_OperationModeType mode, const uint8* data, uint32 dataSz,
        uint8* mac, uint32* macSz)
{
    WOLFSSL_ENTER("wolfSSL_Csm_MacGenerateWithKey");

    if (mac == NULL || macSz == NULL) {
        ReportToDET(WOLFSSL_CSM_MODULE_ID, 0, WOLFSSL_CSM_API_ID_MAC_GENERATE,
                WOLFSSL_CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }

    return Csm_CMAC_Operation(id, keyId, mode, data, dataSz, mac, macSz,
            NULL, 0, NULL, CRYPTO_MACGENERATE);
}


/* AES-CMAC verify. macLength is in BITS, as the Csm specification defines it,
 * and may be shorter than the full tag, in which case only those leading bits
 * are compared -- the driver masks the trailing partial byte. Note the unit:
 * Csm_MacGenerate() reports its length in bytes, so handing one straight to
 * the other asks for eight times less than intended. The comparison result is
 * written to verifyPtr; E_OK only means the job ran.
 * returns E_OK on success */
Std_ReturnType Csm_MacVerify(uint32 id, Crypto_OperationModeType mode,
        const uint8* data, uint32 dataSz, const uint8* mac, uint32 macSz,
        Crypto_VerifyResultType* verify)
{
    WOLFSSL_ENTER("Csm_MacVerify");

    if (mac == NULL || verify == NULL) {
        ReportToDET(WOLFSSL_CSM_MODULE_ID, 0, WOLFSSL_CSM_API_ID_MAC_VERIFY,
                WOLFSSL_CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }

    /* fail closed until the driver says otherwise */
    *verify = CRYPTO_E_VER_NOT_OK;

    /* macSz is a BIT count here, which is what the Csm specification defines
     * macLength as, and it is passed down unconverted -- the driver does the
     * arithmetic and masks a partial trailing byte. The accessible size of
     * macPtr follows from it, ceil(macSz / 8), so there is nothing left for a
     * caller to get wrong and no buffer size to check against.
     *
     * The byte-based form is wolfSSL_Csm_MacVerifyWithKey(), which is a
     * wolfSSL extension and can define its own unit. */
    return Csm_CMAC_Operation(id, WOLFSSL_CSM_KEY_ID_ANY, mode, data, dataSz,
            NULL, NULL, mac, macSz, verify, CRYPTO_MACVERIFY);
}


/* As Csm_MacVerify() but naming the keystore slot holding the MAC key.
 * returns E_OK on success */
Std_ReturnType wolfSSL_Csm_MacVerifyWithKey(uint32 id, uint32 keyId,
        Crypto_OperationModeType mode, const uint8* data, uint32 dataSz,
        const uint8* mac, uint32 macBufSz, uint32 macSz,
        Crypto_VerifyResultType* verify)
{
    WOLFSSL_ENTER("wolfSSL_Csm_MacVerifyWithKey");

    if (mac == NULL || verify == NULL) {
        ReportToDET(WOLFSSL_CSM_MODULE_ID, 0, WOLFSSL_CSM_API_ID_MAC_VERIFY,
                WOLFSSL_CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }

    /* fail closed until the driver says otherwise */
    *verify = CRYPTO_E_VER_NOT_OK;

    /* Bytes here, unlike Csm_MacVerify(): this is a wolfSSL extension, and a
     * byte count with the buffer size beside it cannot be misread. */
    if (macSz > macBufSz) {
        WOLFSSL_MSG("MAC length does not fit the buffer given");
        ReportToDET(WOLFSSL_CSM_MODULE_ID, 0, WOLFSSL_CSM_API_ID_MAC_VERIFY,
                WOLFSSL_CSM_E_SMALL_BUFFER);
        return E_NOT_OK;
    }

    /* The driver works in bits. Bounded above first, so the multiply cannot
     * overflow. */
    if (macSz > WC_CMAC_TAG_MAX_SZ) {
        WOLFSSL_MSG("MAC length is longer than a CMAC tag");
        return E_NOT_OK;
    }

    return Csm_CMAC_Operation(id, keyId, mode, data, dataSz, NULL, NULL,
            mac, macSz * 8U, verify, CRYPTO_MACVERIFY);
}
#endif /* WOLFSSL_AUTOSAR_CMAC */


/* returns E_OK on success */
Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 eId,
        const uint8* key, uint32 keySz)
{
    return CryIf_KeyElementSet(keyId, eId, key, keySz);
}


#ifdef WOLF_PRIVATE_KEY_ID
/* Points a keystore slot at a key held in a device. See Csm.h -- this is a
 * wolfSSL extension, not AUTOSAR 4.4 API.
 * returns E_OK on success */
Std_ReturnType wolfSSL_Csm_KeyElementSetId(uint32 keyId, uint32 eId,
        const uint8* id, uint32 idLen)
{
    WOLFSSL_ENTER("wolfSSL_Csm_KeyElementSetId");
    return CryIf_KeyElementSetId(keyId, eId, id, idLen);
}


/* returns E_OK on success */
Std_ReturnType wolfSSL_Csm_KeyElementSetLabel(uint32 keyId, uint32 eId,
        const char* label)
{
    WOLFSSL_ENTER("wolfSSL_Csm_KeyElementSetLabel");
    return CryIf_KeyElementSetLabel(keyId, eId, label);
}
#endif /* WOLF_PRIVATE_KEY_ID */

#endif /* NO_WOLFSSL_AUTOSAR_CSM */
#endif /* WOLFSSL_AUTOSAR */

