/* csm.h
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


/* Module identity. AUTOSAR requires these in every module header so that
 * dependent modules can check they were built against the same release.
 *
 * The vendor ID is assigned by AUTOSAR and wolfSSL has none, so it is 0 here.
 * Set WOLFSSL_CSM_VENDOR_ID to the integrator's assigned ID if a conformance
 * run needs a real one. */
#ifndef WOLFSSL_CSM_VENDOR_ID
    #define WOLFSSL_CSM_VENDOR_ID 0
#endif
#define WOLFSSL_CSM_MODULE_ID 110U  /* Csm, per the AUTOSAR module ID list */

#define WOLFSSL_CSM_AR_RELEASE_MAJOR_VERSION    4
#define WOLFSSL_CSM_AR_RELEASE_MINOR_VERSION    4
#define WOLFSSL_CSM_AR_RELEASE_REVISION_VERSION 0

/* Development error IDs, as assigned by the CSM specification. These are the
 * values a DET sees, so they are not ours to choose. */
#define WOLFSSL_CSM_E_PARAM_POINTER   0x01
#define WOLFSSL_CSM_E_SMALL_BUFFER    0x03
#define WOLFSSL_CSM_E_PARAM_HANDLE    0x04
#define WOLFSSL_CSM_E_UNINIT          0x05
#define WOLFSSL_CSM_E_INIT_FAILED     0x07
#define WOLFSSL_CSM_E_PROCESSING_MODE 0x08
/* Kept as an alias: the name shipped misspelled in an installed header, so an
 * application may still use it. */
#define WOLFSSL_CSM_E_PROCESSING_MOD  WOLFSSL_CSM_E_PROCESSING_MODE

/* Service IDs for the APIs that report to the DET.
 *
 * UNCONFIRMED: unlike the module and error IDs above, these values have not
 * been checked against the specification's service ID table. They are only
 * ever passed through to the DET, so a wrong one mislabels a report rather
 * than breaking anything -- but confirm them before a conformance run.
 * WOLFSSL_CSM_API_ID_UNKNOWN is deliberately available for a call site whose
 * ID is not known. */
#define WOLFSSL_CSM_API_ID_UNKNOWN       0xFF
#define WOLFSSL_CSM_API_ID_INIT          0x00
#define WOLFSSL_CSM_API_ID_CANCEL_JOB    0x05
#define WOLFSSL_CSM_API_ID_MAC_GENERATE  0x0D
#define WOLFSSL_CSM_API_ID_MAC_VERIFY    0x0F


#define Crypto_JobType WOLFSSL_JOBTYPE
#define Crypto_JobPrimitiveInputOutputType WOLFSSL_JOBIO
#define Crypto_JobStateType WOLFSSL_JOBSTATE
#define Crypto_VerifyResultType WOLFSSL_VERIFY
#define Crypto_OperationModeType WOLFSSL_OMODE_TYPE

/* Default device ID, used when no config is supplied at all.
 *
 * INVALID_DEVID means "software only", which is what this port did before the
 * field existed. A build with no runtime configuration to speak of -- a
 * user_settings.h ECU build, say -- can point the whole port at an HSM by
 * defining this instead of plumbing a config through.
 *
 * Mind that a config IS taken at face value: devId is copied as given, so a
 * zero-initialized Csm_ConfigType selects device 0, which is a valid crypto
 * callback device, not software. Initialize with WOLFSSL_CSM_CONFIG_DEFAULT
 * (below) and override what you need. */
#ifndef WOLFSSL_AUTOSAR_DEVID
    #define WOLFSSL_AUTOSAR_DEVID INVALID_DEVID
#endif

/* Implementation specific structure.
 *
 * heap  - heap hint handed to every wolfCrypt context the driver creates.
 *         NULL for the default allocator; a WOLFSSL_STATIC_MEMORY build passes
 *         its hint here.
 * devId - crypto callback device ID, so the Crypto driver's jobs run on an HSM
 *         or accelerator instead of in software. INVALID_DEVID for software.
 *
 * Passing NULL to Csm_Init() selects NULL and WOLFSSL_AUTOSAR_DEVID. */
typedef struct Csm_ConfigType {
    void* heap;
    int   devId;
} Csm_ConfigType;

/* Initializer matching Csm_Init(NULL): the default allocator and
 * WOLFSSL_AUTOSAR_DEVID, which is INVALID_DEVID -- software -- unless the
 * build overrides it to point the whole port at a device.
 *   Csm_ConfigType cfg = WOLFSSL_CSM_CONFIG_DEFAULT;
 *   cfg.devId = myDevId;
 * Use it rather than zero-initializing, which would select device 0. */
#define WOLFSSL_CSM_CONFIG_DEFAULT { NULL, WOLFSSL_AUTOSAR_DEVID }

#ifdef WOLFSSL_AUTOSAR_CMAC

/* cmac.h for WC_CMAC_TAG_MIN_SZ, which the floor below is documented against
 * and can be set to: without it the macro is undefined here, preprocesses to
 * 0 in the #if, and the recommended override fails the check it is supposed to
 * satisfy. */
#include <wolfssl/wolfcrypt/cmac.h>

/* The MAC services call wc_InitCmac_ex()/wc_CmacUpdate(), which cmac.c
 * compiles only with both of these. --enable-autosar-cmac and the CMake option
 * add them; a user_settings.h build has to, and the symptom otherwise is a
 * clean build where every MAC job fails at run time. */
#ifndef WOLFSSL_CMAC
    #error "WOLFSSL_AUTOSAR_CMAC needs WOLFSSL_CMAC"
#endif
#ifndef WOLFSSL_AES_DIRECT
    #error "WOLFSSL_AUTOSAR_CMAC needs WOLFSSL_AES_DIRECT"
#endif

/* Shortest MAC a verify will compare, in bytes.
 *
 * The default is 3, which is what AUTOSAR SecOC profile 1 truncates its
 * authenticator to (24 bits) -- an AUTOSAR port that refused it would be
 * refusing its own standard's profile. That is below wolfCrypt's own
 * WC_CMAC_TAG_MIN_SZ (4 bytes, 8 under FIPS), which is the floor
 * wc_AesCmacVerify() applies, so it is a deliberate relaxation for this port
 * and no stronger than SecOC itself: a 3 byte tag is forged with probability
 * 2^-24 per attempt, which SecOC's freshness value and its failure counters
 * are what bound in practice.
 *
 * Raise it if the ECU does not need profile 1 -- WC_CMAC_TAG_MIN_SZ, or 16 to
 * refuse truncation outright. Shorter than 3 is not configurable: a 1 byte tag
 * is forged with probability 2^-8, and nothing in AUTOSAR asks for one. */
#ifndef WOLFSSL_AUTOSAR_MAC_MIN_SZ
    #define WOLFSSL_AUTOSAR_MAC_MIN_SZ 3
#endif
#if WOLFSSL_AUTOSAR_MAC_MIN_SZ < 3
    #error "WOLFSSL_AUTOSAR_MAC_MIN_SZ must be at least 3"
#endif

/* WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT restores the first-matching-slot
 * scan for key element 0x01 in a build with the MAC services.
 *
 * By default such a build refuses a job that did not name its slot when more
 * than one populated slot holds 0x01, because the element ID cannot say
 * whether a slot carries a cipher key or a MAC key: resolving it would run a
 * MAC under a cipher key, or the reverse, and report success.
 *
 * Define this only where the ECU uses ONE of the two services and keeps
 * several keys for it in different slots -- then 0x01 has a single meaning and
 * first-match is what the port always did. An ECU using both services should
 * name the slot instead, with wolfSSL_Csm_EncryptWithKey() and friends, which
 * works either way. */
#endif /* WOLFSSL_AUTOSAR_CMAC */

/* Key slot sentinel: let the driver resolve the key itself, by key input
 * redirection if the build configures it and otherwise by scanning the
 * keystore for the first slot of the right element type. This is what the
 * plain Csm_* services pass; see wolfSSL_Csm_EncryptWithKey() and friends for
 * naming a slot outright. */
#define WOLFSSL_CSM_KEY_ID_ANY 0xFFFFFFFFU

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

#ifdef WOLFSSL_AUTOSAR_CMAC
    CRYPTO_MACGENERATE = 0x01,
    CRYPTO_MACVERIFY = 0x02,
#endif

#ifdef CSM_UNSUPPORTED_ALGS
    /* not yet supported */
    CRYPTO_HASH = 0x00,
    #ifndef WOLFSSL_AUTOSAR_CMAC
    CRYPTO_MACGENERATE = 0x01,
    CRYPTO_MACVERIFY = 0x02,
    #endif
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

#ifdef WOLFSSL_AUTOSAR_CMAC
    CRYPTO_ALGOMODE_CMAC = 0x10,
#endif

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
    #ifndef WOLFSSL_AUTOSAR_CMAC
    CRYPTO_ALGOMODE_CMAC = 0x10,
    #endif
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

#ifdef WOLFSSL_AUTOSAR_CMAC
    /* MAC. The specification scopes key element IDs per key, so MAC_KEY and
     * CIPHER_KEY share the value 0x01.
     *
     * This port's keystore is flat -- one slot holds one element -- so the
     * element ID alone cannot tell a cipher key from a MAC key. A build using
     * both services must name the slot it means, with
     * wolfSSL_Csm_EncryptWithKey() / wolfSSL_Csm_MacGenerateWithKey() and
     * their siblings. Key input redirection does NOT separate them: it maps
     * an element ID to one slot for every service, so both would resolve to
     * the same slot. */
    ,CRYPTO_KE_MAC_KEY = 0x01
    ,CRYPTO_KE_MAC_PROOF = 0x02
#endif
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


/* Csm_Init() may be called again to change the configuration, but only while
 * no job owns a slot: a streaming job runs its wolfCrypt context outside the
 * driver's locks, so tearing that context down underneath it would be a
 * use-after-free. FINISH every open job first, or Csm_CancelJob() the ones
 * that will never be finished.
 *
 * A call made while a job is open changes nothing -- the previous heap, devId,
 * keystore and DRBG stay in force. The service returns void, as the
 * specification defines it, so the refusal is reported as CSM_E_INIT_FAILED to
 * the DET (visible with -DWOLFSSL_AUTOSAR_DET, or as a log line under
 * -DDEBUG_WOLFSSL) rather than to the caller. */
WOLFSSL_API void Csm_Init(const Csm_ConfigType* config);

/* Releases the slot a job holds and frees the wolfCrypt context in it, for a
 * job that will never send its FINISH -- an abandoned stream, or one left over
 * from an SW-C that has been restarted. Without it such a slot is held until
 * the ECU resets, and Csm_Init() would refuse to reconfigure forever.
 *
 * mode is accepted for the specification's signature and not used: this port
 * only has synchronous jobs, so there is one way to cancel.
 *
 * Must not be called while another primitive is running on the same job: the
 * two would be operating on one context, and AUTOSAR gives a job a single
 * owner -- cancel it from that owner. Cancelling a job that holds no slot
 * returns E_NOT_OK, which is also what distinguishes "already finished" from
 * "cancelled".
 *
 * returns E_OK when a slot was released */
WOLFSSL_API Std_ReturnType Csm_CancelJob(uint32 jobId,
        Crypto_OperationModeType mode);

/* Can be called before Csm_Init(). Reports the module identity above and the
 * wolfSSL version as the software version, since the shim has no version of
 * its own.
 *
 * The specification wants every other service to report CSM_E_UNINIT when
 * called before init; this port does not track that yet, so they return
 * E_NOT_OK from the driver without a DET report. See the port README. */
WOLFSSL_API void Csm_GetVersionInfo(Std_VersionInfoType* version);

WOLFSSL_API Std_ReturnType Csm_Decrypt(uint32 jobId,
        Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
        uint8* resultPtr, uint32* resultLengthPtr);
WOLFSSL_API Std_ReturnType Csm_Encrypt(uint32 jobId,
        Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
        uint8* resultPtr, uint32* resultLengthPtr);
WOLFSSL_API Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 keyElementId,
        const uint8* keyPtr, uint32 keyLength);

/* wolfSSL extensions, NOT part of the AUTOSAR 4.4 Csm API -- hence the prefix.
 *
 * Same services as above, but naming the keystore slot holding the key
 * instead of leaving the driver to find it. That is what makes a build using
 * both cipher and MAC services safe: both ask for key element 0x01, so a
 * resolved-by-element lookup cannot tell them apart and would take whichever
 * slot comes first.
 *
 * keyId names the slot holding the KEY element only. Other elements -- the
 * cipher IV, element 0x05 -- are still resolved by the driver, which is
 * unambiguous because no other element shares their ID.
 *
 * WOLFSSL_CSM_KEY_ID_ANY restores the resolved-by-element behaviour, which is
 * what the plain Csm_Encrypt()/Csm_Decrypt() pass. */
WOLFSSL_API Std_ReturnType wolfSSL_Csm_EncryptWithKey(uint32 jobId,
        uint32 keyId, Crypto_OperationModeType mode, const uint8* dataPtr,
        uint32 dataLength, uint8* resultPtr, uint32* resultLengthPtr);
WOLFSSL_API Std_ReturnType wolfSSL_Csm_DecryptWithKey(uint32 jobId,
        uint32 keyId, Crypto_OperationModeType mode, const uint8* dataPtr,
        uint32 dataLength, uint8* resultPtr, uint32* resultLengthPtr);

#ifdef WOLF_PRIVATE_KEY_ID
/* wolfSSL extensions, NOT part of the AUTOSAR 4.4 Csm API -- hence the prefix.
 *
 * These point a keystore slot at a key that lives in a device rather than
 * storing key material, so the key never enters RAM. The driver then builds
 * its AES contexts with wc_AesInit_Id()/wc_AesInit_Label(), which leave the
 * software key schedule empty and reach the crypto callback instead.
 *
 * Both the cipher and the MAC services can use such a slot. For MAC jobs
 * wolfCrypt stores the name on the Cmac, offers the operation to the crypto
 * callback, and only rejects a NULL key once the callback has declined -- so a
 * device that will not do the work makes the job fail rather than compute
 * something else.
 *
 * A device ID must be configured in Csm_ConfigType: a job using such a slot
 * is REFUSED when the port is in software mode, rather than running with an
 * empty key schedule.
 *
 * Cipher jobs carry one more condition. Their fail-closed behaviour rests on
 * wolfCrypt's key-is-set check, so a named key is refused wherever that check
 * is not actually enforced: a build without WOLFSSL_AES_REQUIRE_KEY_SET, and
 * any back end marked WC_AES_KEY_SET_CHECK_UNSUPPORTED in aes.h -- STM32,
 * Freescale, CryptoCell, SCE, SiLabs SE, TI, CAAM, PSA, Xilinx and the rest.
 * Those replace wc_AesCbcEncrypt()/Decrypt() with implementations that never
 * consult the check, so forcing WOLFSSL_AES_REQUIRE_KEY_SET on such a target
 * makes the macro true without making the job safe; the refusal stands either
 * way, and the keystore has to hold the key material there. MAC jobs need no
 * such condition: CMAC initialization refuses a NULL key by itself. */
WOLFSSL_API Std_ReturnType wolfSSL_Csm_KeyElementSetId(uint32 keyId,
        uint32 keyElementId, const uint8* idPtr, uint32 idLength);
WOLFSSL_API Std_ReturnType wolfSSL_Csm_KeyElementSetLabel(uint32 keyId,
        uint32 keyElementId, const char* label);
#endif
WOLFSSL_API Std_ReturnType Csm_RandomGenerate( uint32 jobId, uint8* resultPtr,
        uint32* resultLengthPtr);
#ifdef WOLFSSL_AUTOSAR_CMAC
/* MIND THE UNITS -- they differ between these two, as the specification has
 * them.
 *
 * Csm_MacVerify's macLength is in BITS. The accessible size of macPtr follows
 * from it, ceil(macLength / 8), and a length that is not a whole number of
 * bytes compares the trailing partial byte under a mask. 128 bits is the full
 * tag; anything longer is rejected, which is also what a byte count passed by
 * mistake runs into.
 *
 * Csm_MacGenerate's macLengthPtr is in BYTES: on entry the size of macPtr, on
 * a successful FINISH the number of bytes written. The specification's unit
 * for it is UNVERIFIED here, so confirm before a conformance run -- unlike
 * verify, a wrong unit on generate cannot over-read anything, it only reports
 * a length the caller may misread.
 *
 * wolfSSL_Csm_MacVerifyWithKey() is byte-based throughout, being a wolfSSL
 * extension, and takes the buffer size beside the length so neither can be
 * misread.
 *
 * WOLFSSL_AUTOSAR_MAC_MIN_SZ is the shortest tag verify will accept, in
 * bytes. */
WOLFSSL_API Std_ReturnType Csm_MacGenerate(uint32 jobId,
        Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
        uint8* macPtr, uint32* macLengthPtr);
WOLFSSL_API Std_ReturnType Csm_MacVerify(uint32 jobId,
        Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
        const uint8* macPtr, uint32 macLengthBits,
        Crypto_VerifyResultType* verifyPtr);

/* wolfSSL extensions: name the slot holding the MAC key. Required when the
 * build also uses the cipher services, see wolfSSL_Csm_EncryptWithKey(). */
WOLFSSL_API Std_ReturnType wolfSSL_Csm_MacGenerateWithKey(uint32 jobId,
        uint32 keyId, Crypto_OperationModeType mode, const uint8* dataPtr,
        uint32 dataLength, uint8* macPtr, uint32* macLengthPtr);
/* macBufferLength is the size of macPtr, which macLength must fit inside.
 * That is the check Csm_MacVerify() cannot make, and it is what catches a
 * macLength passed in bits. */
WOLFSSL_API Std_ReturnType wolfSSL_Csm_MacVerifyWithKey(uint32 jobId,
        uint32 keyId, Crypto_OperationModeType mode, const uint8* dataPtr,
        uint32 dataLength, const uint8* macPtr, uint32 macBufferLength,
        uint32 macLength, Crypto_VerifyResultType* verifyPtr);
#endif
/* Development error reporting.
 *
 * Shaped after the AUTOSAR DET entry point,
 *   Det_ReportError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId,
 *                   uint8 ErrorId)
 * so an integrator can forward it directly. Build with WOLFSSL_AUTOSAR_DET to
 * do exactly that; otherwise the report goes to the wolfSSL log, which needs
 * --enable-debug and wolfSSL_Debugging_ON() to be visible. */
WOLFSSL_LOCAL void ReportToDET(uint16 moduleId, uint8 instanceId, uint8 apiId,
        uint8 errorId);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_AUTOSAR */
#endif /* WOLFSSL_CSM_H */

