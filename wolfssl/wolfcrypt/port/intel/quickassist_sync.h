/* quickassist_sync.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _INTEL_QUICKASSIST_SYNC_H_
#define _INTEL_QUICKASSIST_SYNC_H_

#ifdef HAVE_INTEL_QA_SYNC

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_ln.h"
#include "cpa_cy_ecdh.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_cy_dh.h"
#include "cpa_cy_drbg.h"
#include "cpa_cy_nrbg.h"
#include "cpa_cy_prime.h"

/* User space utils */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


#if 0
    /* Optional feature for partial QAT hashing support */
    /* This will process updates through hardware instead of caching them */
    #define QAT_HASH_ENABLE_PARTIAL
#endif
#ifdef QAT_HASH_ENABLE_PARTIAL
    #define MAX_QAT_HASH_BUFFERS 2
#endif

/* Detect QAT driver version */
#if defined(CPA_CY_API_VERSION_NUM_MAJOR) && CPA_CY_API_VERSION_NUM_MAJOR > 1
    #define QAT_V2
#endif

#ifdef QAT_V2
    /* quickassist/utilities/libusdm_drv/qae_mem.h */
    /* Provides user-space API's for accessing NUMA allocated memory through usdm_drv */
    #include "qae_mem.h"
#include "linux/include/qae_mem_utils.h"
#endif

#ifdef QAT_USE_POLLING_THREAD
    #include <pthread.h>
#endif
#ifdef QA_DEMO_MAIN
    #include <semaphore.h>
#endif


/* Tunable parameters */
#ifndef QAT_PROCESS_NAME
    #define QAT_PROCESS_NAME     "SSL"
#endif
#ifndef QAT_LIMIT_DEV_ACCESS
    #define QAT_LIMIT_DEV_ACCESS CPA_FALSE
#endif
#ifndef QAT_MAX_DEVICES
    #define QAT_MAX_DEVICES  (1)  /* maximum number of QAT cards */
#endif

#ifndef QAT_RETRY_LIMIT
    #define QAT_RETRY_LIMIT  (100)
#endif
#ifndef QAT_POLL_RESP_QUOTA
    #define QAT_POLL_RESP_QUOTA (0) /* all pending */
#endif

#if !defined(NO_AES) || !defined(NO_DES3)
    #define QAT_ENABLE_CRYPTO
#endif


/* Pre-declarations */
struct IntelQaDev;
struct wc_CryptoInfo;
struct WC_BIGINT;
struct WC_RNG;


#if defined(QAT_ENABLE_HASH) || defined(QAT_ENABLE_CRYPTO)
/* symmetric context */
typedef struct IntelQaSymCtx {
    CpaCySymOpData opData;
    CpaCySymSessionCtx symCtxSrc;
    CpaCySymSessionCtx symCtx;
    word32 symCtxSize;

    /* flags */
    word32 isOpen:1;
    word32 isCopy:1;
} IntelQaSymCtx;
#endif

typedef void (*IntelQaFreeFunc)(struct IntelQaDev*);


/* QuickAssist device */
typedef struct IntelQaDev {
	CpaInstanceHandle handle;
    int devId;
	void* heap;

    /* callback return info */
    int ret;
    byte* out;
    union {
        word32* outLenPtr;
        word32 outLen;
    };

    /* operations */
    IntelQaFreeFunc freeFunc;
    union {
    #ifdef QAT_ENABLE_CRYPTO
        struct {
            IntelQaSymCtx ctx;
            CpaBufferList bufferList;
            CpaFlatBuffer flatBuffer;
            byte* authTag;
            word32 authTagSz;
        } cipher;
    #endif
    } op;

#ifdef QAT_USE_POLLING_THREAD
    pthread_t pollingThread;
    byte pollingCy;
#endif
} IntelQaDev;


/* Interface */
WOLFSSL_LOCAL int IntelQaHardwareStart(const char*, int);
WOLFSSL_LOCAL void IntelQaHardwareStop(void);
WOLFSSL_LOCAL int IntelQaInit(void*);
WOLFSSL_LOCAL void IntelQaDeInit(int);
WOLFSSL_LOCAL int IntelQaNumInstances(void);
WOLFSSL_LOCAL int IntelQaOpen(IntelQaDev*, int);
WOLFSSL_LOCAL void IntelQaClose(IntelQaDev*);
WOLFSSL_LOCAL int IntelQaDevCopy(IntelQaDev*, IntelQaDev*);
WOLFSSL_LOCAL int IntelQaPoll(IntelQaDev*);
WOLFSSL_LOCAL int IntelQaGetCyInstanceCount(void);

#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        WOLFSSL_LOCAL int IntelQaSymAesCbcEncrypt(IntelQaDev*, byte*,
                const byte*, word32, const byte*, word32, const byte*, word32);
    #ifdef HAVE_AES_DECRYPT
        WOLFSSL_LOCAL int IntelQaSymAesCbcDecrypt(IntelQaDev*, byte*,
                const byte*, word32, const byte*, word32, const byte*, word32);
    #endif /* HAVE_AES_DECRYPT */
    #endif /* HAVE_AES_CBC */

    #ifdef HAVE_AESGCM
        WOLFSSL_LOCAL int IntelQaSymAesGcmEncrypt(IntelQaDev*, byte*,
                const byte*, word32, const byte*, word32, const byte*, word32,
                byte*, word32, const byte*, word32);
    #ifdef HAVE_AES_DECRYPT
        WOLFSSL_LOCAL int IntelQaSymAesGcmDecrypt(IntelQaDev*, byte*,
                const byte*, word32, const byte*, word32, const byte*, word32,
                const byte*, word32, const byte*, word32);
    #endif /* HAVE_AES_DECRYPT */
    #endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#ifndef NO_DES3
    WOLFSSL_LOCAL int IntelQaSymDes3CbcEncrypt(IntelQaDev*, byte*,
            const byte*, word32, const byte*, word32, const byte* iv, word32);
    WOLFSSL_LOCAL int IntelQaSymDes3CbcDecrypt(IntelQaDev* dev, byte*,
            const byte*, word32, const byte*, word32, const byte* iv, word32);
#endif /*! NO_DES3 */

#ifdef WOLF_CRYPTO_CB
    WOLFSSL_LOCAL int IntelQaSymSync_CryptoDevCb(int, struct wc_CryptoInfo*,
			void*);
#endif /* WOLF_CRYPTO_CB */


#ifdef WOLFSSL_TRACK_MEMORY
    WOLFSSL_API int InitMemoryTracker(void);
    WOLFSSL_API void ShowMemoryTracker(void);
#endif


WOLFSSL_API void* IntelQaMalloc(size_t size, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
);

WOLFSSL_API void IntelQaFree(void *ptr, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
);

WOLFSSL_API void* IntelQaRealloc(void *ptr, size_t size, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
);
#endif /* HAVE_INTEL_QA_SYNC */

#endif /* _INTEL_QUICKASSIST_SYNC_H_ */
