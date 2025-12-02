/* quickassist.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_INTEL_QA

#ifdef QAT_DEMO_MAIN
    #define QAT_USE_POLLING_THREAD
#endif


#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#ifndef NO_DH
    #include <wolfssl/wolfcrypt/dh.h>
#endif

#include <wolfssl/wolfcrypt/port/intel/quickassist.h>

#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#ifndef QAT_V2
#include "icp_sal_drbg_impl.h"
#endif

#ifdef QAT_HASH_ENABLE_PARTIAL
#ifdef USE_LAC_SESSION_FOR_STRUCT_OFFSET
    #include "lac_session.h"
#endif
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <pthread.h>

/* Async enables (1=non-block, 0=block) */
#ifndef QAT_RSA_ASYNC
#define QAT_RSA_ASYNC        1
#endif
#ifndef QAT_EXPTMOD_ASYNC
#define QAT_EXPTMOD_ASYNC    1
#endif
#ifndef QAT_CIPHER_ASYNC
#define QAT_CIPHER_ASYNC     1
#endif
#ifndef QAT_ECDSA_ASYNC
#define QAT_ECDSA_ASYNC      1
#endif
#ifndef QAT_ECDHE_ASYNC
#define QAT_ECDHE_ASYNC      1
#endif
#ifndef QAT_ECMUL_ASYNC
#define QAT_ECMUL_ASYNC      1
#endif
#ifndef QAT_DH_ASYNC
#define QAT_DH_ASYNC         1
#endif

/* Hash and Drbg do not support async in wolfSSL/wolfCrypt */
#ifndef QAT_HASH_ASYNC
#define QAT_HASH_ASYNC       0
#endif
#ifndef QAT_DRBG_ASYNC
#define QAT_DRBG_ASYNC       0
#endif

#define OS_HOST_TO_NW_32(uData) ByteReverseWord32(uData)

static CpaInstanceHandle* g_cyInstances = NULL;
static CpaInstanceInfo2* g_cyInstanceInfo = NULL;
static Cpa32U* g_cyInstMap = NULL;
static Cpa16U g_numInstances = 0;
static Cpa16U g_instCounter = 0;
static CpaBoolean g_cyServiceStarted = CPA_FALSE;
#ifdef QAT_USE_POLLING_CHECK
    static CpaBoolean* g_cyPolling = NULL;
    static pthread_mutex_t* g_PollLock;
#endif
static volatile int g_initCount = 0;
#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
    static Cpa8U* g_qatEcdhY = NULL;
    static Cpa8U* g_qatEcdhCofactor1 = NULL;
#endif
static pthread_mutex_t g_Hwlock = PTHREAD_MUTEX_INITIALIZER;

typedef struct qatCapabilities {
    /* capabilities */
    word32 supPartial:1;
#ifdef QAT_V2
    word32 supSha3:1;
#endif
} qatCapabilities_t;
static qatCapabilities_t g_qatCapabilities = {
    0
    #ifdef QAT_V2
    , 0
    #endif
};


#if defined(QAT_ENABLE_CRYPTO) || defined(QAT_ENABLE_HASH)
    static int IntelQaSymClose(WC_ASYNC_DEV* dev, int doFree);
#endif
#if defined(QAT_ENABLE_RNG)
static int IntelQaDrbgClose(WC_ASYNC_DEV* dev);
#endif

extern Cpa32U osalLogLevelSet(Cpa32U level);


/* -------------------------------------------------------------------------- */
/* Polling */
/* -------------------------------------------------------------------------- */

#ifdef QAT_USE_POLLING_THREAD
static void* IntelQaPollingThread(void* context)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)context;
#ifdef QAT_DEBUG
    printf("Polling Thread Start\n");
#endif
    while (dev->qat.pollingCy) {
        icp_sal_CyPollInstance(dev->qat.handle, QAT_POLL_RESP_QUOTA);
        wc_AsyncSleep(10);
    }
#ifdef QAT_DEBUG
    printf("Polling Thread Exit\n");
#endif
    pthread_exit(NULL);
}

static CpaStatus IntelQaStartPollingThread(WC_ASYNC_DEV* dev)
{
    if (dev->qat.pollingCy == 0) {
        dev->qat.pollingCy = 1;
    #ifdef QAT_DEBUG
        printf("Polling Thread Created\n");
    #endif
        if (pthread_create(&dev->qat.pollingThread, NULL, IntelQaPollingThread,
                                                            (void*)dev) != 0) {
            printf("Failed create polling thread!\n");
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}

static void IntelQaStopPollingThread(WC_ASYNC_DEV* dev)
{
    dev->qat.pollingCy = 0;
    pthread_join(dev->qat.pollingThread, 0);
}
#endif /* QAT_USE_POLLING_THREAD */



/* -------------------------------------------------------------------------- */
/* Buffer Helpers */
/* -------------------------------------------------------------------------- */
#if defined(HAVE_ECC) || !defined(NO_DH) || !defined(NO_RSA)
static WC_INLINE int IntelQaAllocFlatBuffer(CpaFlatBuffer* buf, int size,
    void* heap)
{
    if (buf == NULL || size <= 0)
        return BAD_FUNC_ARG;
    buf->pData = (byte*)XMALLOC(size, heap, DYNAMIC_TYPE_ASYNC_NUMA);
    if (buf->pData == NULL)
        return MEMORY_E;
    buf->dataLenInBytes = size;
    return 0;
}
#if !defined(NO_DH) || defined(WOLFSSL_KEY_GEN)
static WC_INLINE void IntelQaFreeFlatBuffer(CpaFlatBuffer* buf, void* heap)
{
    if (buf && buf->pData) {
        XFREE(buf->pData, heap, DYNAMIC_TYPE_ASYNC_NUMA);
        buf->pData = NULL;
        buf->dataLenInBytes = 0;
    }
}
#endif
static WC_INLINE int IntelQaBigIntToFlatBuffer(WC_BIGINT* src,
    CpaFlatBuffer* dst)
{
    if (src == NULL || src->buf == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    dst->pData = src->buf;
    dst->dataLenInBytes = src->len;

    return 0;
}

static WC_INLINE int IntelQaFlatBufferToBigInt(CpaFlatBuffer* src,
    WC_BIGINT* dst)
{
    if (src == NULL || src->pData == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    dst->buf = src->pData;
    dst->len = src->dataLenInBytes;

    return 0;
}
#endif


/* -------------------------------------------------------------------------- */
/* Device */
/* -------------------------------------------------------------------------- */
void IntelQaHardwareStop(void)
{
    int i;
    CpaStatus status;

    g_initCount--;  /* track de-init count */
    if (g_initCount != 0) {
        return;
    }

#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
    if (g_qatEcdhY) {
        XFREE(g_qatEcdhY, NULL, DYNAMIC_TYPE_ASYNC_NUMA);
        g_qatEcdhY = NULL;
    }
    if (g_qatEcdhCofactor1) {
        XFREE(g_qatEcdhCofactor1, NULL, DYNAMIC_TYPE_ASYNC_NUMA);
        g_qatEcdhCofactor1 = NULL;
    }
#endif

    if (g_cyServiceStarted == CPA_TRUE) {
        g_cyServiceStarted = CPA_FALSE;
        for (i=0; i<g_numInstances; i++) {
            status = cpaCyStopInstance(g_cyInstances[i]);
            if (status != CPA_STATUS_SUCCESS) {
                printf("IntelQA: Could not stop instance: %d\n", i);
                printf("\tInternal error has occur which probably can only be"
                    "fixed by a reboot\n");
            }
        }
    }

    status = icp_sal_userStop();
    if (status != CPA_STATUS_SUCCESS) {
        printf("IntelQA: Could not stop sal for user space (status %d)\n",
                                                                        status);
    }

    if (g_cyInstMap) {
        XFREE(g_cyInstMap, NULL, DYNAMIC_TYPE_ASYNC);
        g_cyInstMap = NULL;
    }

    if (g_cyInstanceInfo) {
        XFREE(g_cyInstanceInfo, NULL, DYNAMIC_TYPE_ASYNC);
        g_cyInstanceInfo = NULL;
    }

#ifdef QAT_USE_POLLING_CHECK
    if (g_cyPolling) {
        XFREE(g_cyPolling, NULL, DYNAMIC_TYPE_ASYNC);
        g_cyPolling = NULL;
    }
    if (g_PollLock) {
        for (i=0; i<g_numInstances; i++) {
            pthread_mutex_destroy(&g_PollLock[i]);
        }
        XFREE(g_PollLock, NULL, DYNAMIC_TYPE_ASYNC);
        g_PollLock = NULL;
    }
#endif

    if (g_cyInstances) {
        XFREE(g_cyInstances, NULL, DYNAMIC_TYPE_ASYNC);
        g_cyInstances = NULL;
        g_numInstances = 0;
    }

    qaeMemDestroy();

    printf("IntelQA: Stop\n");
}

int IntelQaHardwareStart(const char* process_name, int limitDevAccess)
{
    int ret = 0, i;
    CpaStatus status;

    g_initCount++;
    if (g_initCount > 1) {
        return 0;
    }

    status = qaeMemInit();
    if (status != CPA_STATUS_SUCCESS) {
        printf("IntelQA: Could not start qae mem for user space (status %d)\n",
                                                                        status);
        printf("\tHas the qaeMemDrv.ko module been loaded?\n");
        return ASYNC_INIT_E;
    }

    status = icp_sal_userStartMultiProcess(process_name,
        limitDevAccess ? CPA_TRUE : CPA_FALSE);
    if (status != CPA_STATUS_SUCCESS) {
        printf("IntelQA: Could not start sal for user space! status %d\n",
                                                                        status);
        ret = ASYNC_INIT_E; goto error;
    }

#ifdef QAT_DEBUG
    /* optionally enable debugging */
    /* osalLogLevelSet(8); */
#endif

    status = cpaCyGetNumInstances(&g_numInstances);
    if (status != CPA_STATUS_SUCCESS || g_numInstances == 0) {
        printf("IntelQA: Failed to get num of instances! status %d\n",
                                                                    status);
        ret = INVALID_DEVID; goto error;
    }

    /* Get handles / info */
    g_cyInstances = (CpaInstanceHandle*)XMALLOC(
        sizeof(CpaInstanceHandle) * g_numInstances, NULL, DYNAMIC_TYPE_ASYNC);
    if (g_cyInstances == NULL) {
        printf("IntelQA: Failed to allocate instances\n");
        ret = INVALID_DEVID; goto error;
    }

#ifdef QAT_USE_POLLING_CHECK
    g_cyPolling = (CpaBoolean*)XMALLOC(sizeof(CpaBoolean) * g_numInstances,
        NULL, DYNAMIC_TYPE_ASYNC);
    if (g_cyPolling == NULL) {
        printf("IntelQA: Failed to allocate polling status\n");
        ret = INVALID_DEVID; goto error;
    }
    g_PollLock = (pthread_mutex_t*)XMALLOC(sizeof(pthread_mutex_t) *
        g_numInstances, NULL, DYNAMIC_TYPE_ASYNC);
    if (g_PollLock == NULL) {
        printf("IntelQA: Failed to allocate polling locks\n");
        ret = INVALID_DEVID; goto error;
    }
    for (i=0; i<g_numInstances; i++) {
        pthread_mutex_init(&g_PollLock[i], NULL);
    }
#endif

    g_cyInstanceInfo = (CpaInstanceInfo2*)XMALLOC(
        sizeof(CpaInstanceInfo2) * g_numInstances, NULL, DYNAMIC_TYPE_ASYNC);
    if (g_cyInstanceInfo == NULL) {
        printf("IntelQA: Failed to allocate instance info\n");
        ret = INVALID_DEVID; goto error;
    }

    g_cyInstMap = (Cpa32U*)XMALLOC(
        sizeof(Cpa32U) * g_numInstances, NULL, DYNAMIC_TYPE_ASYNC);
    if (g_cyInstMap == NULL) {
        printf("IntelQA: Failed to allocate instance map\n");
        ret = INVALID_DEVID; goto error;
    }

    status = cpaCyGetInstances(g_numInstances, g_cyInstances);
    if (status != CPA_STATUS_SUCCESS) {
        printf("IntelQA: Failed to get IntelQA instances\n");
        ret = INVALID_DEVID; goto error;
    }

    /* start all instances */
    g_cyServiceStarted = CPA_TRUE;
    for (i=0; i<g_numInstances; i++) {
        Cpa32U coreAffinity = 0;
        CpaCySymCapabilitiesInfo capabilities;
        int j;
        XMEMSET(&capabilities, 0, sizeof(capabilities));

        status = cpaCyInstanceGetInfo2(g_cyInstances[i],
                                                    &g_cyInstanceInfo[i]);
        if (status != CPA_STATUS_SUCCESS) {
            printf("IntelQA: Error getting instance info for %d\n", i);
            ret = INVALID_DEVID; goto error;
        }

        /* loop of the instanceInfo coreAffinity bitmask to find the core */
        for (j=0; j<CPA_MAX_CORES; j++) {
            if (CPA_BITMAP_BIT_TEST(g_cyInstanceInfo[i].coreAffinity, j)) {
                coreAffinity = i;
                break;
            }
        }
        g_cyInstMap[i] = coreAffinity;

        /* capabilities */
        status = cpaCySymQueryCapabilities(g_cyInstances[i], &capabilities);
        if (status == CPA_STATUS_SUCCESS) {
            g_qatCapabilities.supPartial = capabilities.partialPacketSupported;
            if (capabilities.partialPacketSupported != CPA_TRUE) {
                printf("Warning: QAT does not support partial packets!\n");
            }
        }
    #ifdef QAT_V2
        g_qatCapabilities.supSha3 = CPA_BITMAP_BIT_TEST(capabilities.hashes,
            CPA_CY_SYM_HASH_SHA3_256) ? 1 : 0;
    #endif

    #ifdef QAT_DEBUG
        printf("Inst %u, Node: %d, Affin: %u, Dev: %u, Accel %u",
                i, g_cyInstanceInfo[i].nodeAffinity, coreAffinity,
                g_cyInstanceInfo[i].physInstId.packageId,
                g_cyInstanceInfo[i].physInstId.acceleratorId);
        printf(", EE %u, BDF %02X:%02X:%02X, isPolled %d\n",
                g_cyInstanceInfo[i].physInstId.executionEngineId,
                (Cpa8U)((g_cyInstanceInfo[i].physInstId.busAddress) >> 8),
                (Cpa8U)((g_cyInstanceInfo[i].physInstId.busAddress)
                                                            & 0xFF) >> 3,
                (Cpa8U)((g_cyInstanceInfo[i].physInstId.busAddress) & 3),
                g_cyInstanceInfo[i].isPolled);
    #endif

        status = cpaCySetAddressTranslation(g_cyInstances[i],
            qaeVirtToPhysNUMA);
        if (status != CPA_STATUS_SUCCESS) {
            printf("IntelQA: Error setting memory config for inst %d\n", i);
            ret = INVALID_DEVID; goto error;
        }

        status = cpaCyStartInstance(g_cyInstances[i]);
        if (status != CPA_STATUS_SUCCESS) {
            printf("IntelQA: Error starting crypto instance %d\n", i);
            ret = INVALID_DEVID; goto error;
        }
    }

#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
    g_qatEcdhY = XMALLOC(MAX_ECC_BYTES, NULL, DYNAMIC_TYPE_ASYNC_NUMA);
    if (g_qatEcdhY == NULL) {
        ret = MEMORY_E; goto error;
    }
    g_qatEcdhCofactor1 = XMALLOC(MAX_ECC_BYTES, NULL, DYNAMIC_TYPE_ASYNC_NUMA);
    if (g_qatEcdhCofactor1 == NULL) {
        ret = MEMORY_E; goto error;
    }
    *((word32*)g_qatEcdhCofactor1) = OS_HOST_TO_NW_32(1);
#endif

    printf("IntelQA: Instances %d\n", g_numInstances);
    return ret;

error:
    IntelQaHardwareStop();
    return ret;
}


int IntelQaInit(void* threadId)
{
    int ret;
    int devId;
#if !defined(WC_NO_ASYNC_THREADING) && defined(WC_ASYNC_THREAD_BIND)
    pthread_t* thread = (pthread_t*)threadId;
#else
    (void)threadId;
#endif

    ret = pthread_mutex_lock(&g_Hwlock);
    if (ret != 0) {
        printf("IntelQaInit: mutex lock failed! %d\n", ret);
        return BAD_MUTEX_E;
    }

    ret = IntelQaHardwareStart(QAT_PROCESS_NAME, QAT_LIMIT_DEV_ACCESS);
    if (ret != 0) {
        pthread_mutex_unlock(&g_Hwlock);
        return ret;
    }

    if (g_numInstances <= 0) {
        pthread_mutex_unlock(&g_Hwlock);
        return ASYNC_INIT_E;
    }

    /* assign device id */
    devId = (g_instCounter % g_numInstances);
    g_instCounter++;

    pthread_mutex_unlock(&g_Hwlock);

#if !defined(WC_NO_ASYNC_THREADING) && defined(WC_ASYNC_THREAD_BIND)
    /* if no thread provided then just return instance and don't bind */
    if (thread) {
        ret = wc_AsyncThreadBind(thread, g_cyInstMap[devId]);
        if (ret != 0) {
            printf("IntelQA: Thread bind failed! %d\n", ret);
        }
    }
#endif /* !WC_NO_ASYNC_THREADING && !WC_NO_ASYNC_THREAD_BIND */

    return devId;
}

int IntelQaNumInstances(void)
{
    return g_numInstances;
}

int IntelQaOpen(WC_ASYNC_DEV* dev, int devId)
{
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)devId;

    /* clear device info */
    XMEMSET(&dev->qat, 0, sizeof(IntelQaDev));

    if (g_cyInstances == NULL) {
        printf("IntelQA not initialized\n");
        return ASYNC_INIT_E;
    }

    if (devId >= g_numInstances) {
        fprintf(stderr, "IntelQA: devId %d exceeds number of instances %u\n",
                devId, g_numInstances);
        return NO_VALID_DEVID;
    }

    dev->qat.devId = devId;
    dev->qat.handle = g_cyInstances[devId];

#ifdef QAT_DEBUG
    printf("IntelQaOpen %p\n", dev);
#endif

#ifdef QAT_USE_POLLING_THREAD
    /* start polling thread */
    IntelQaStartPollingThread(dev);
#endif

    return 0;
}

#if defined(QAT_ENABLE_CRYPTO) || defined(QAT_ENABLE_HASH)
static int IntelQaDevIsHash(WC_ASYNC_DEV* dev)
{
    int isHash = 0;

    switch (dev->marker) {
        case WOLFSSL_ASYNC_MARKER_ARC4:
        case WOLFSSL_ASYNC_MARKER_AES:
        case WOLFSSL_ASYNC_MARKER_3DES:
        case WOLFSSL_ASYNC_MARKER_RNG:
        case WOLFSSL_ASYNC_MARKER_RSA:
        case WOLFSSL_ASYNC_MARKER_ECC:
        case WOLFSSL_ASYNC_MARKER_DH:
            isHash = 0;
            break;
        case WOLFSSL_ASYNC_MARKER_HMAC:
        case WOLFSSL_ASYNC_MARKER_SHA512:
        case WOLFSSL_ASYNC_MARKER_SHA384:
        case WOLFSSL_ASYNC_MARKER_SHA256:
        case WOLFSSL_ASYNC_MARKER_SHA224:
        case WOLFSSL_ASYNC_MARKER_SHA:
        case WOLFSSL_ASYNC_MARKER_MD5:
        case WOLFSSL_ASYNC_MARKER_SHA3:
            isHash = 1;
            break;
    }

    return isHash;
}

static IntelQaSymCtx* IntelQaGetSymCtx(WC_ASYNC_DEV* dev)
{
#if defined(QAT_ENABLE_CRYPTO) && defined(QAT_ENABLE_HASH)
    return IntelQaDevIsHash(dev) ? &dev->qat.op.hash.ctx :
        &dev->qat.op.cipher.ctx;
#elif defined(QAT_ENABLE_CRYPTO)
    return IntelQaDevIsHash(dev) ? NULL : &dev->qat.op.cipher.ctx;
#elif defined(QAT_ENABLE_HASH)
    return IntelQaDevIsHash(dev) ? &dev->qat.op.hash.ctx : NULL;
#else
    return NULL;
#endif
}

static int IntelQaDevIsSym(WC_ASYNC_DEV* dev)
{
    int isSym = 0;

    switch (dev->marker) {
        case WOLFSSL_ASYNC_MARKER_RNG:
        case WOLFSSL_ASYNC_MARKER_RSA:
        case WOLFSSL_ASYNC_MARKER_ECC:
        case WOLFSSL_ASYNC_MARKER_DH:
            isSym = 0;
            break;
        case WOLFSSL_ASYNC_MARKER_ARC4:
        case WOLFSSL_ASYNC_MARKER_AES:
        case WOLFSSL_ASYNC_MARKER_3DES:
        case WOLFSSL_ASYNC_MARKER_HMAC:
        case WOLFSSL_ASYNC_MARKER_SHA512:
        case WOLFSSL_ASYNC_MARKER_SHA384:
        case WOLFSSL_ASYNC_MARKER_SHA256:
        case WOLFSSL_ASYNC_MARKER_SHA224:
        case WOLFSSL_ASYNC_MARKER_SHA:
        case WOLFSSL_ASYNC_MARKER_MD5:
        case WOLFSSL_ASYNC_MARKER_SHA3:
            isSym = 1;
            break;
    }

    return isSym;
}
#endif

void IntelQaClose(WC_ASYNC_DEV* dev)
{
    if (dev) {
    #ifdef QAT_DEBUG
        printf("IntelQaClose %p\n", dev);
    #endif

    #if defined(QAT_ENABLE_CRYPTO) || defined(QAT_ENABLE_HASH)
        if (IntelQaDevIsSym(dev)) {
            /* close any active session */
            IntelQaSymClose(dev, 1);
        }
    #endif
    #if defined(QAT_ENABLE_RNG)
        if (dev->marker == WOLFSSL_ASYNC_MARKER_RNG) {
            IntelQaDrbgClose(dev);
        }
    #endif

    #ifdef QAT_USE_POLLING_THREAD
        IntelQaStopPollingThread(dev);
    #endif

        dev->qat.handle = NULL;
    }
}

void IntelQaDeInit(int devId)
{
    (void)devId;

    if (pthread_mutex_lock(&g_Hwlock) == 0) {
        IntelQaHardwareStop();
        pthread_mutex_unlock(&g_Hwlock);
    }
}

int IntelQaDevCopy(WC_ASYNC_DEV* src, WC_ASYNC_DEV* dst)
{
    int ret = 0;
#if defined(QAT_ENABLE_HASH) || defined(QAT_ENABLE_CRYPTO)
    IntelQaSymCtx *ctxSrc, *ctxDst;
#ifdef QAT_ENABLE_HASH
    int isHash;
#endif
#endif

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

#if defined(QAT_ENABLE_HASH) || defined(QAT_ENABLE_CRYPTO)
    ctxDst = IntelQaGetSymCtx(dst);
    ctxSrc = IntelQaGetSymCtx(src);

    if (ctxDst == NULL || ctxSrc == NULL) {
        return ret;
    }

#ifdef QAT_DEBUG
    printf("IntelQaDevCopy: dev %p->%p, symCtx %p (src %p), symCtxSize %d\n",
        src, dst, ctxSrc->symCtx, ctxSrc->symCtxSrc, ctxSrc->symCtxSize);
#endif

    ctxDst->isCopy = 1;
    /* force alloc/init on open for copy */
    ctxDst->symCtx = NULL;
    ctxDst->isOpen = 0;
    /* if src is not open, then don't set source ctx */
    if (!ctxSrc->isOpen)
        ctxDst->symCtxSrc = NULL;

#ifdef QAT_ENABLE_HASH
    isHash = IntelQaDevIsHash(src);
    if (isHash) {
        /* need to duplicate tmpIn */
        if (src->qat.op.hash.tmpIn) {
            dst->qat.op.hash.tmpIn = XMALLOC(src->qat.op.hash.tmpInBufSz,
                src->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            if (dst->qat.op.hash.tmpIn == NULL) {
                return MEMORY_E;
            }
            XMEMCPY(dst->qat.op.hash.tmpIn, src->qat.op.hash.tmpIn,
                src->qat.op.hash.tmpInSz);
            dst->qat.op.hash.tmpInSz = src->qat.op.hash.tmpInSz;
            dst->qat.op.hash.tmpInBufSz = src->qat.op.hash.tmpInBufSz;
        }
    }
#endif /* QAT_ENABLE_HASH */
#endif /* QAT_ENABLE_HASH || QAT_ENABLE_CRYPTO */

    return ret;
}

int IntelQaPoll(WC_ASYNC_DEV* dev)
{
    int ret = 0;

#ifndef QAT_USE_POLLING_THREAD
    CpaStatus status;
    WOLF_EVENT* event = &dev->event;

#ifdef QAT_USE_POLLING_CHECK
    pthread_mutex_t* lock = &g_PollLock[dev->qat.devId];
    if (pthread_mutex_lock(lock) == 0) {
        /* test if any other threads are polling */
        if (g_cyPolling[dev->qat.devId]) {
            pthread_mutex_unlock(lock);

            /* return success even though its busy, caller will treat as
             * WC_PENDING_E */
            return 0;
        }

        g_cyPolling[dev->qat.devId] = 1;
        pthread_mutex_unlock(lock);
    }
#endif

    status = icp_sal_CyPollInstance(dev->qat.handle, QAT_POLL_RESP_QUOTA);
    if (status != CPA_STATUS_SUCCESS && status != CPA_STATUS_RETRY) {
        printf("IntelQa: Poll failure %d\n", status);
        ret = -1;
    }

#ifndef WC_NO_ASYNC_THREADING
    if (event->threadId == 0 || event->threadId == wc_AsyncThreadId())
#endif
    {
        /* if event is done */
        if (dev->qat.ret != WC_PENDING_E) {
            /* perform cleanup */
            IntelQaFreeFunc freeFunc = dev->qat.freeFunc;
    #ifdef QAT_DEBUG
            printf("IntelQaOpFree: Dev %p, FreeFunc %p\n", dev, freeFunc);
    #endif
            if (freeFunc) {
                dev->qat.freeFunc = NULL;
                freeFunc(dev);
            }

            /* return response code */
            event->ret = dev->qat.ret;
        }
    }

#ifdef QAT_USE_POLLING_CHECK
    /* indicate we are done polling */
    if (pthread_mutex_lock(lock) == 0) {
        g_cyPolling[dev->qat.devId] = 0;
        pthread_mutex_unlock(lock);
    }
#endif

#else
    (void)dev;
#endif

    return ret;
}

static int IntelQaPollBlockRet(WC_ASYNC_DEV* dev, int ret_wait)
{
    int ret;

    do {
        ret = IntelQaPoll(dev);
        (void)ret; /* not used */

        if (dev->qat.ret != ret_wait) {
            break;
        }
    #ifndef WC_NO_ASYNC_THREADING
        wc_AsyncThreadYield();
    #endif
    } while (1);
    ret = dev->qat.ret;

    return ret;
}

int IntelQaGetCyInstanceCount(void)
{
    return g_numInstances;
}

static WC_INLINE int IntelQaHandleCpaStatus(WC_ASYNC_DEV* dev, CpaStatus status,
    int* ret, byte isAsync, void* callback, int* retryCount)
{
    int retry = 0;

    if (status == CPA_STATUS_SUCCESS) {
        if (isAsync && callback) {
            *ret = WC_PENDING_E;
        }
        else {
            *ret = IntelQaPollBlockRet(dev, WC_PENDING_E);
        }
    }
    else if (status == CPA_STATUS_RETRY) {
        (*retryCount)++;
        if ((*retryCount % (QAT_RETRY_LIMIT + 1)) == QAT_RETRY_LIMIT) {
        #ifndef WC_NO_ASYNC_THREADING
            wc_AsyncThreadYield();
        #else
            wc_AsyncSleep(10);
        #endif
        }
        retry = 1;
    }
    else {
        *ret = ASYNC_OP_E;
    }

    return retry;
}

static WC_INLINE void IntelQaOpInit(WC_ASYNC_DEV* dev, IntelQaFreeFunc freeFunc)
{
    dev->qat.ret = WC_PENDING_E;
    dev->qat.freeFunc = freeFunc;
}


/* -------------------------------------------------------------------------- */
/* RSA Algo */
/* -------------------------------------------------------------------------- */

#ifndef NO_RSA

#ifdef WOLFSSL_KEY_GEN
static void IntelQaGenPrimeFree(WC_ASYNC_DEV* dev)
{
    CpaCyPrimeTestOpData* opData = dev->qat.op.prime_gen.opData;
    CpaFlatBuffer* primeCandidates = dev->qat.op.prime_gen.primeCandidates;
    byte* pMillerRabinData = dev->qat.op.prime_gen.pMillerRabinData;

    if (opData) {
        XFREE(opData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        dev->qat.op.prime_gen.opData = NULL;
    }
    if (primeCandidates) {
        int i;
        for (i = 0; i < QAT_PRIME_GEN_TRIES; i++) {
            if (primeCandidates[i].pData) {
                XFREE(primeCandidates[i].pData, dev->heap,
                    DYNAMIC_TYPE_ASYNC_NUMA);
                primeCandidates[i].pData = NULL;
                primeCandidates[i].dataLenInBytes = 0;
            }
        }
        XFREE(primeCandidates, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        dev->qat.op.prime_gen.primeCandidates = NULL;
    }
    if (pMillerRabinData) {
        XFREE(pMillerRabinData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        dev->qat.op.prime_gen.pMillerRabinData = NULL;
    }
}

static void IntelQaGenPrimeCallback(void *pCallbackTag,
    CpaStatus status, void *pOpData, CpaBoolean testPassed)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyPrimeTestOpData* opData = (CpaCyPrimeTestOpData*)pOpData;
    int opIndex = 0;
    int testStatus = QAT_PRIME_CHK_STATUS_FAILED;

    /* calculate index based on opDate pointer offset */
    if (dev->qat.op.prime_gen.opData && opData) {
        byte* srcop = (byte*)dev->qat.op.prime_gen.opData;
        byte* curop = (byte*)opData;
        size_t offset;
        if (srcop <= curop) {
            offset = (size_t)curop - (size_t)srcop;
            offset /= sizeof(CpaCyPrimeTestOpData);
            if (offset < QAT_PRIME_GEN_TRIES)
                opIndex = (int)offset;
        }
    }

#ifdef QAT_DEBUG
    printf("IntelQaGenPrimeCallback: dev %p, opIndex %d, status %d, "
        "testPassed %d\n", dev, opIndex, status, testPassed);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        testStatus = (testPassed == CPA_TRUE) ?
            QAT_PRIME_CHK_STATUS_PASSED :
            QAT_PRIME_CHK_STATUS_FAILED;
    }

    dev->qat.op.prime_gen.testStatus[opIndex] = testStatus;
}

#ifndef QAT_PRIME_CHECK_TIMEOUT
    /* times to wait in retry for operations */
    #define QAT_PRIME_CHECK_TIMEOUT 100000
#endif
int IntelQaGenPrime(WC_ASYNC_DEV* dev, WC_RNG* rng, byte* primeBuf,
    word32 primeSz)
{
    int ret = 0, retryCount = 0, i, attempt;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyPrimeTestOpData* opData = NULL;
    CpaFlatBuffer* primeCandidates = NULL;
    byte* pMillerRabinData = NULL;
    CpaFlatBuffer millerRabins;
    CpaCyPrimeTestCbFunc callback = IntelQaGenPrimeCallback;
    CpaBoolean testPassed = CPA_FALSE;

    if (dev == NULL || rng == NULL || primeBuf == NULL || primeSz < 64) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaGenPrime: dev %p, sz %d\n", dev, primeSz);
#endif

    /* generate operation data and prime candidates */
    opData = (CpaCyPrimeTestOpData*)XMALLOC(
        sizeof(CpaCyPrimeTestOpData) * QAT_PRIME_GEN_TRIES,
        dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    dev->qat.op.prime_gen.opData = opData;
    primeCandidates = (CpaFlatBuffer*)XMALLOC(
        sizeof(CpaFlatBuffer) * QAT_PRIME_GEN_TRIES,
        dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    dev->qat.op.prime_gen.primeCandidates = primeCandidates;
    if (opData == NULL || primeCandidates == NULL) {
        ret = MEMORY_E; goto exit;
    }
    XMEMSET(opData, 0, sizeof(CpaCyPrimeTestOpData) * QAT_PRIME_GEN_TRIES);
    XMEMSET(primeCandidates, 0, sizeof(CpaFlatBuffer) * QAT_PRIME_GEN_TRIES);
    for (i = 0; i < QAT_PRIME_GEN_TRIES; i++) {
        primeCandidates[i].pData = (byte*)XMALLOC(primeSz, dev->heap,
            DYNAMIC_TYPE_ASYNC_NUMA);
        if (primeCandidates[i].pData == NULL) {
            ret = MEMORY_E; goto exit;
        }
        primeCandidates[i].dataLenInBytes = primeSz;
    }

    /* generate miller rabbin data */
    pMillerRabinData = (byte*)XMALLOC(primeSz * QAT_PRIME_GEN_MR_ROUNDS,
        dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    dev->qat.op.prime_gen.pMillerRabinData = pMillerRabinData;
    if (pMillerRabinData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    ret = wc_RNG_GenerateBlock(rng, pMillerRabinData,
        primeSz * QAT_PRIME_GEN_MR_ROUNDS);
    if (ret != 0)
        goto exit;

    /* make sure each miller rabbin number is greater than 1 */
    for (i = 0; i < QAT_PRIME_GEN_MR_ROUNDS; i++) {
        word32 byteCheck = primeSz - 1;
        byte* round = &pMillerRabinData[i * primeSz];
        if (round[byteCheck] <= 1) {
            ret = wc_RNG_GenerateBlock(rng, &round[byteCheck], 1);
            if (ret != 0)
                goto exit;
            if (round[byteCheck] <= 1)
                round[byteCheck] += 2;
        }
    }
    millerRabins.pData = pMillerRabinData;
    millerRabins.dataLenInBytes = primeSz * QAT_PRIME_GEN_MR_ROUNDS;

    /* populate operation data */
    for (i = 0; i < QAT_PRIME_GEN_TRIES; i++) {
        opData[i].primeCandidate = primeCandidates[i];
        opData[i].performGcdTest = CPA_TRUE;
        opData[i].performFermatTest = CPA_TRUE;
        opData[i].numMillerRabinRounds = QAT_PRIME_GEN_MR_ROUNDS;
        opData[i].millerRabinRandomInput = millerRabins;
        opData[i].performLucasTest = CPA_TRUE;
    }

    /* store info needed for output */
    dev->qat.out = primeBuf;
    dev->qat.outLen = primeSz;
    IntelQaOpInit(dev, IntelQaGenPrimeFree);

    for (attempt = 0; attempt < QAT_PRIME_GEN_RETRIES; attempt++) {
        int expectedDone, doneCount, primePassIndex, errorCount;
        byte* primeData = primeCandidates[0].pData;
        /* Generate primeCandidates */
        ret = wc_RNG_GenerateBlock(rng, primeData, primeSz);
        if (ret != 0)
            goto exit;
        /* prime lower bound has the MSB set, set it in candidate */
        primeData[0] |= 0x80;
        /* make candidate odd */
        primeData[primeSz-1] |= 0x01;

        /* create candidates that are incremented by two */
        for (i = 1; i < QAT_PRIME_GEN_TRIES; i++) {
            word32 byteCheck = primeSz - 1;
            primeData = primeCandidates[i].pData;
            XMEMCPY(primeData,
                primeCandidates[i-1].pData,
                primeCandidates[i-1].dataLenInBytes);

            if (primeData[byteCheck] != 0xFF) {
                primeData[byteCheck] += 2;
            }
            else {
                /* if rollover occurred increment high order bytes */
                /* increment by 1 does not affect odd/even */
                int j;
                for (j = primeSz - 2; j >= 0; j--) {
                    if (primeData[i] != 0xFF) {
                        primeData[i] += 1;
                        break;
                    }
                    else {
                        primeData[i] = 0;
                    }
                }
            }
        }

        /* make sure miller rabbin must be less than prime candidate */
        for (i = 0; i < QAT_PRIME_GEN_MR_ROUNDS; i++) {
            byte* mrData = pMillerRabinData + (i * primeSz);
            int j;
            for (j = 0; j < (int)primeSz; j++) {
                /* if primeData is less then mrData, and primeData is not 0,
                 * then make mrData to be smaller than primeData,
                  * and we are done */
                if ((primeData[j] <= mrData[j]) && primeData[j] != 0) {
                    mrData[j] = primeData[j] - 1;
                    break;
                }
                /* if primeData is 0 then mrData needs to be zero and we check
                 * the next index */
                else if (primeData[j] == 0) {
                    mrData[j] = 0;
                }
                /* primeData is smaller than mrData so we are done */
                else {
                    break;
                }
            }
        }

        /* setup and run prime tests */
        XMEMSET(dev->qat.op.prime_gen.testStatus, 0,
            sizeof(dev->qat.op.prime_gen.testStatus));
        retryCount = 0;
        expectedDone = 0;
        errorCount = 0;
        for (i = 0; i < QAT_PRIME_GEN_TRIES; i++) {
            /* perform prime test */
            do {
                status = cpaCyPrimeTest(dev->qat.handle,
                                        callback,
                                        dev,
                                        &opData[i],
                                        &testPassed);
                if (status == CPA_STATUS_RETRY) {
                    IntelQaPoll(dev);
                }
            } while (status == CPA_STATUS_RETRY &&
                retryCount++ < QAT_PRIME_CHECK_TIMEOUT);

            /* handle error */
            if (status != CPA_STATUS_SUCCESS) {
                errorCount++;
                break;
            }
            expectedDone++;
        }

        /* use blocking polling, till all have completed */
        retryCount = 0;
        primePassIndex = -1;
        do {
            IntelQaPoll(dev);

            /* tally results */
            doneCount = 0;
            for (i = 0; i < expectedDone; i++) {
                byte* testStatus = &dev->qat.op.prime_gen.testStatus[i];
                if (*testStatus != QAT_PRIME_CHK_STATUS_INIT) {
                    doneCount++;
                    /* Track index of first passed operation */
                    if (primePassIndex == -1 &&
                             *testStatus == QAT_PRIME_CHK_STATUS_PASSED)
                        primePassIndex = i;
                    else if (*testStatus == QAT_PRIME_CHK_STATUS_ERROR)
                        errorCount++;
                }
            }

            /* determine if all prime tests are done */
            if (doneCount == expectedDone) {
                break;
            }

        #ifndef WC_NO_ASYNC_THREADING
            wc_AsyncThreadYield();
        #endif
        } while (retryCount++ < QAT_PRIME_CHECK_TIMEOUT);
        if (retryCount == QAT_PRIME_CHECK_TIMEOUT) {
        #ifdef QAT_DEBUG
            printf("cpaCyPrimeTest wait timeout! dev %p\n", dev);
        #endif
            errorCount++;
        }

        /* check if we found a prime */
        if (primePassIndex != -1 && primePassIndex < QAT_PRIME_GEN_TRIES) {
            ret = 0;
            XMEMCPY(primeBuf, primeCandidates[primePassIndex].pData, primeSz);
            break; /* done with success */
        }

        /* handle failure */
        if (errorCount != 0) {
            ret = ASYNC_OP_E;
            break; /* done with failure */
        }

    #ifdef QAT_DEBUG
        printf("cpaCyPrimeTest attempt %d\n", attempt);
    #endif
    } /* for (attempt) */

exit:

    if (ret != 0) {
        printf("cpaCyPrimeTest failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    IntelQaGenPrimeFree(dev);

    return ret;
}


static void IntelQaRsaKeyGenFree(WC_ASYNC_DEV* dev)
{
    CpaCyRsaPrivateKey* privateKey = &dev->qat.op.rsa_keygen.privateKey;

    /* This one is not owned by RsaKey */
    IntelQaFreeFlatBuffer(&privateKey->privateKeyRep1.modulusN, dev->heap);

    /* free remaining on failures only */
    /* ownership of these buffers goes to RsaKey */
    if (dev->qat.ret != 0) {
        CpaCyRsaKeyGenOpData* opData = &dev->qat.op.rsa_keygen.opData;
        CpaCyRsaPublicKey* publicKey = &dev->qat.op.rsa_keygen.publicKey;

        IntelQaFreeFlatBuffer(&publicKey->modulusN, dev->heap);
        IntelQaFreeFlatBuffer(&publicKey->publicExponentE, dev->heap);

        IntelQaFreeFlatBuffer(&privateKey->privateKeyRep1.privateExponentD,
            dev->heap);
        IntelQaFreeFlatBuffer(&privateKey->privateKeyRep2.prime1P, dev->heap);
        IntelQaFreeFlatBuffer(&privateKey->privateKeyRep2.prime2Q, dev->heap);
        IntelQaFreeFlatBuffer(&privateKey->privateKeyRep2.exponent1Dp,
            dev->heap);
        IntelQaFreeFlatBuffer(&privateKey->privateKeyRep2.exponent2Dq,
            dev->heap);
        IntelQaFreeFlatBuffer(&privateKey->privateKeyRep2.coefficientQInv,
            dev->heap);

        (void)opData;
    }
}

static void IntelQaRsaKeyGenCallback(void *pCallbackTag,
        CpaStatus status, void *pKeyGenOpData, CpaCyRsaPrivateKey *pPrivateKey,
        CpaCyRsaPublicKey *pPublicKey)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyRsaKeyGenOpData* opData = (CpaCyRsaKeyGenOpData*)pKeyGenOpData;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaRsaKeyGenCallback: dev %p, status %d\n", dev, status);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        RsaKey* key = dev->qat.op.rsa_keygen.rsakey;
        if (key) {
            /* Populate RsaKey Parameters */
            /* raw BigInt buffer ownership is transferred to RsaKey */
            /* cleanup is handled in wc_FreeRsaKey */

            /* modulusN */
            ret = IntelQaFlatBufferToBigInt(
                    &pPublicKey->modulusN, &key->n.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->n,
                    key->n.raw.buf, key->n.raw.len);

            /* publicExponentE */
            if (ret == 0)
                ret = IntelQaFlatBufferToBigInt(
                    &pPublicKey->publicExponentE, &key->e.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->e,
                    key->e.raw.buf, key->e.raw.len);

            /* privateExponentD */
            if (ret == 0)
                ret = IntelQaFlatBufferToBigInt(
                    &pPrivateKey->privateKeyRep1.privateExponentD, &key->d.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->d,
                    key->d.raw.buf, key->d.raw.len);

            /* prime1P */
            if (ret == 0)
                ret = IntelQaFlatBufferToBigInt(
                    &pPrivateKey->privateKeyRep2.prime1P, &key->p.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->p,
                    key->p.raw.buf, key->p.raw.len);

            /* prime2Q */
            if (ret == 0)
                ret = IntelQaFlatBufferToBigInt(
                    &pPrivateKey->privateKeyRep2.prime2Q, &key->q.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->q,
                    key->q.raw.buf, key->q.raw.len);

            /* exponent1Dp */
            if (ret == 0)
                ret = IntelQaFlatBufferToBigInt(
                    &pPrivateKey->privateKeyRep2.exponent1Dp, &key->dP.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->dP,
                    key->dP.raw.buf, key->dP.raw.len);

            /* exponent2Dq */
            if (ret == 0)
                ret = IntelQaFlatBufferToBigInt(
                    &pPrivateKey->privateKeyRep2.exponent2Dq, &key->dQ.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->dQ,
                    key->dQ.raw.buf, key->dQ.raw.len);

            /* coefficientQInv */
            if (ret == 0)
                ret = IntelQaFlatBufferToBigInt(
                    &pPrivateKey->privateKeyRep2.coefficientQInv, &key->u.raw);
            if (ret == 0)
                ret = mp_read_unsigned_bin(&key->u,
                    key->u.raw.buf, key->u.raw.len);

            /* mark as private key */
            if (ret == 0)
                key->type = RSA_PRIVATE;
        }
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaRsaKeyGen(WC_ASYNC_DEV* dev, RsaKey* key, int keyBits, long e,
    WC_RNG* rng)
{
    int ret = 0, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer prime1P;
    CpaFlatBuffer prime2Q;
    CpaCyRsaKeyGenOpData* opData = NULL;
    CpaCyRsaPrivateKey* privateKey = NULL;
    CpaCyRsaPublicKey* publicKey = NULL;
    CpaCyRsaKeyGenCbFunc callback = IntelQaRsaKeyGenCallback;
    int keySz = keyBits/8;
    int primeSz = keySz/2; /* P & Q */

    if (dev == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaRsaKeyGen: dev %p, keyBits %d\n", dev, keyBits);
#endif

    /* allocate and generate 2 primes (P/Q) */
    XMEMSET(&prime1P, 0, sizeof(prime1P));
    XMEMSET(&prime2Q, 0, sizeof(prime2Q));
    ret = IntelQaAllocFlatBuffer(&prime1P, primeSz, dev->heap);
    if (ret == 0)
        ret = IntelQaGenPrime(dev, rng, prime1P.pData, prime1P.dataLenInBytes);
    if (ret == 0)
        ret = IntelQaAllocFlatBuffer(&prime2Q, primeSz, dev->heap);
    if (ret == 0)
        ret = IntelQaGenPrime(dev, rng, prime2Q.pData, prime2Q.dataLenInBytes);
    if (ret != 0) {
        IntelQaFreeFlatBuffer(&prime1P, dev->heap);
        IntelQaFreeFlatBuffer(&prime2Q, dev->heap);
        return ret;
    }

    /* setup key generation operation */
    opData = &dev->qat.op.rsa_keygen.opData;
    publicKey = &dev->qat.op.rsa_keygen.publicKey;
    privateKey = &dev->qat.op.rsa_keygen.privateKey;

    /* init variables */
    XMEMSET(opData, 0, sizeof(CpaCyRsaDecryptOpData));
    XMEMSET(publicKey, 0, sizeof(CpaCyRsaPublicKey));
    XMEMSET(privateKey, 0, sizeof(CpaCyRsaPrivateKey));

    /* setup private key */
    privateKey->version = CPA_CY_RSA_VERSION_TWO_PRIME;
    privateKey->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    ret  = IntelQaAllocFlatBuffer(&privateKey->privateKeyRep1.modulusN,
        keySz, dev->heap);
    ret += IntelQaAllocFlatBuffer(&privateKey->privateKeyRep1.privateExponentD,
        keySz, dev->heap);
    ret += IntelQaAllocFlatBuffer(&privateKey->privateKeyRep2.exponent1Dp,
        primeSz, dev->heap);
    ret += IntelQaAllocFlatBuffer(&privateKey->privateKeyRep2.exponent2Dq,
        primeSz, dev->heap);
    ret += IntelQaAllocFlatBuffer(&privateKey->privateKeyRep2.coefficientQInv,
        primeSz, dev->heap);
    if (ret != 0) {
        ret = MEMORY_E; goto exit;
    }

    /* setup public key */
    ret  = IntelQaAllocFlatBuffer(&publicKey->modulusN, keySz, dev->heap);
    ret += IntelQaAllocFlatBuffer(&publicKey->publicExponentE, sizeof(long),
        dev->heap);
    if (ret != 0) {
        ret = MEMORY_E; goto exit;
    }

    /* populate exponent */
    publicKey->publicExponentE.pData[3] = (e >> 24) & 0xFF;
    publicKey->publicExponentE.pData[2] = (e >> 16) & 0xFF;
    publicKey->publicExponentE.pData[1] = (e >> 8)  & 0xFF;
    publicKey->publicExponentE.pData[0] =  e        & 0xFF;
    publicKey->publicExponentE.dataLenInBytes =
        publicKey->publicExponentE.pData[3] ? 4 :
        publicKey->publicExponentE.pData[2] ? 3 :
        publicKey->publicExponentE.pData[1] ? 2 :
        publicKey->publicExponentE.pData[0] ? 1 : 0;

    /* populate primes P and Q */
    privateKey->privateKeyRep2.prime1P = prime1P;
    privateKey->privateKeyRep2.prime2Q = prime2Q;

    /* setup operation data */
    opData->version = CPA_CY_RSA_VERSION_TWO_PRIME;
    opData->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    opData->modulusLenInBytes = keySz;
    opData->prime1P = privateKey->privateKeyRep2.prime1P;
    opData->prime2Q = privateKey->privateKeyRep2.prime2Q;
    opData->publicExponentE = publicKey->publicExponentE;

    /* parameters required for output callback */
    dev->qat.op.rsa_keygen.rsakey = key;
    IntelQaOpInit(dev, IntelQaRsaKeyGenFree);

    /* perform RSA key generation */
    do {
        status = cpaCyRsaGenKey(dev->qat.handle,
                                callback,
                                dev,
                                opData,
                                privateKey,
                                publicKey);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, 0,
        callback, &retryCount));

exit:

    if (ret != 0) {
        printf("cpaCyRsaGenKey failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    IntelQaRsaKeyGenFree(dev);

    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

static void IntelQaRsaPrivateFree(WC_ASYNC_DEV* dev)
{
    CpaCyRsaDecryptOpData* opData = &dev->qat.op.rsa_priv.opData;
    CpaFlatBuffer *outBuf = &dev->qat.op.rsa_priv.outBuf;

    if (opData) {
        if (opData->inputData.pData) {
            XFREE(opData->inputData.pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            opData->inputData.pData = NULL;
        }
        if (opData->pRecipientPrivateKey) {
            XMEMSET(opData->pRecipientPrivateKey, 0,
                sizeof(CpaCyRsaPrivateKey));
        }
        XMEMSET(opData, 0, sizeof(CpaCyRsaDecryptOpData));
    }
    if (outBuf) {
        if (outBuf->pData) {
            XFREE(outBuf->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            outBuf->pData = NULL;
        }
        XMEMSET(outBuf, 0, sizeof(CpaFlatBuffer));
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLenPtr = NULL;
}

static void IntelQaRsaPrivateCallback(void *pCallbackTag,
        CpaStatus status, void *pOpdata, CpaFlatBuffer *pOut)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyRsaDecryptOpData* opData = (CpaCyRsaDecryptOpData*)pOpdata;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaRsaPrivateCallback: dev %p, status %d, len %d\n",
        dev, status, pOut->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* validate returned output */

        if (dev->qat.outLenPtr) {
            if (pOut->dataLenInBytes > *dev->qat.outLenPtr) {
                pOut->dataLenInBytes = *dev->qat.outLenPtr;
            }
            *dev->qat.outLenPtr = pOut->dataLenInBytes;
        }

        /* return data */
        if (dev->qat.out && dev->qat.out != pOut->pData) {
            XMEMCPY(dev->qat.out, pOut->pData, pOut->dataLenInBytes);
        }

        /* mark event result */
        ret = 0; /* success */
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaRsaPrivate(WC_ASYNC_DEV* dev,
                    const byte* in, word32 inLen,
                    WC_BIGINT* d, WC_BIGINT* n,
                    byte* out, word32* outLen)
{
    int ret = 0, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyRsaPrivateKey* privateKey = NULL;
    CpaCyRsaDecryptOpData* opData = NULL;
    CpaFlatBuffer* outBuf = NULL;
    CpaCyGenFlatBufCbFunc callback = IntelQaRsaPrivateCallback;

    if (dev == NULL || in == NULL || inLen == 0 || out == NULL ||
            outLen == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaRsaPrivate: dev %p, in %p (%d), out %p\n",
        dev, in, inLen, out);
#endif

    /* setup operation */
    opData = &dev->qat.op.rsa_priv.opData;
    outBuf = &dev->qat.op.rsa_priv.outBuf;
    privateKey = &dev->qat.op.rsa_priv.privateKey;

    /* init variables */
    XMEMSET(opData, 0, sizeof(CpaCyRsaDecryptOpData));
    XMEMSET(outBuf, 0, sizeof(CpaFlatBuffer));
    XMEMSET(privateKey, 0, sizeof(CpaCyRsaPrivateKey));

    /* assign buffers */
    ret =  IntelQaBigIntToFlatBuffer(d,
        &privateKey->privateKeyRep1.privateExponentD);
    ret += IntelQaBigIntToFlatBuffer(n, &privateKey->privateKeyRep1.modulusN);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    /* make sure output length is at least modulus len */
    if (*outLen < n->len) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    /* make sure outLen is not more than inLen */
    if (*outLen > inLen) {
        *outLen = inLen;
    }

    opData->inputData.dataLenInBytes = inLen;
    opData->inputData.pData = XREALLOC((byte*)in, inLen, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);

    outBuf->dataLenInBytes = *outLen;
    outBuf->pData = XREALLOC(out, *outLen, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);

    /* check allocations */
    if (opData->inputData.pData == NULL || outBuf->pData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* setup private key */
    privateKey->version = CPA_CY_RSA_VERSION_TWO_PRIME;
    privateKey->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1;

    /* assign private key to private op data */
    opData->pRecipientPrivateKey = privateKey;

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLenPtr = outLen;
    IntelQaOpInit(dev, IntelQaRsaPrivateFree);

    /* perform RSA decrypt */
    do {
        status = cpaCyRsaDecrypt(dev->qat.handle,
                                callback,
                                dev,
                                opData,
                                outBuf);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_RSA_ASYNC, callback,
        &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyRsaDecrypt failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaRsaPrivateFree(dev);

    return ret;
}

int IntelQaRsaCrtPrivate(WC_ASYNC_DEV* dev,
                    const byte* in, word32 inLen,
                    WC_BIGINT* p, WC_BIGINT* q,
                    WC_BIGINT* dP, WC_BIGINT* dQ,
                    WC_BIGINT* qInv,
                    byte* out, word32* outLen)
{
    int ret = 0, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyRsaPrivateKey* privateKey = NULL;
    CpaCyRsaDecryptOpData* opData = NULL;
    CpaFlatBuffer* outBuf = NULL;
    CpaCyGenFlatBufCbFunc callback = IntelQaRsaPrivateCallback;

    if (dev == NULL || in == NULL || inLen == 0 || out == NULL ||
            outLen == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaRsaCrtPrivate: dev %p, in %p (%d), out %p\n",
        dev, in, inLen, out);
#endif

    /* setup operation */
    opData = &dev->qat.op.rsa_priv.opData;
    outBuf = &dev->qat.op.rsa_priv.outBuf;
    privateKey = &dev->qat.op.rsa_priv.privateKey;

    /* init variables */
    XMEMSET(opData, 0, sizeof(CpaCyRsaDecryptOpData));
    XMEMSET(outBuf, 0, sizeof(CpaFlatBuffer));
    XMEMSET(privateKey, 0, sizeof(CpaCyRsaPrivateKey));

    /* assign buffers */
    ret =  IntelQaBigIntToFlatBuffer(p, &privateKey->privateKeyRep2.prime1P);
    ret += IntelQaBigIntToFlatBuffer(q, &privateKey->privateKeyRep2.prime2Q);
    ret += IntelQaBigIntToFlatBuffer(dP,
        &privateKey->privateKeyRep2.exponent1Dp);
    ret += IntelQaBigIntToFlatBuffer(dQ,
        &privateKey->privateKeyRep2.exponent2Dq);
    ret += IntelQaBigIntToFlatBuffer(qInv,
        &privateKey->privateKeyRep2.coefficientQInv);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    /* make sure output length is at least p len */
    if (*outLen < p->len)
        return BAD_FUNC_ARG;

    /* make sure outLen is not more than inLen */
    if (*outLen > inLen)
        *outLen = inLen;

    opData->inputData.dataLenInBytes = inLen;
    opData->inputData.pData = XREALLOC((byte*)in, inLen, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);

    outBuf->dataLenInBytes = *outLen;
    outBuf->pData = XREALLOC(out, *outLen, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);

    /* check allocations */
    if (opData->inputData.pData == NULL || outBuf->pData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* setup private key */
    privateKey->version = CPA_CY_RSA_VERSION_TWO_PRIME;
    privateKey->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;

    /* assign private key to private op data */
    opData->pRecipientPrivateKey = privateKey;

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLenPtr = outLen;
    IntelQaOpInit(dev, IntelQaRsaPrivateFree);

    /* perform RSA CRT decrypt */
    do {
        status = cpaCyRsaDecrypt(dev->qat.handle,
                                callback,
                                dev,
                                opData,
                                outBuf);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_RSA_ASYNC, callback,
        &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyRsaDecrypt CRT failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaRsaPrivateFree(dev);

    return ret;
}

static void IntelQaRsaPublicFree(WC_ASYNC_DEV* dev)
{
    CpaCyRsaEncryptOpData* opData = &dev->qat.op.rsa_pub.opData;
    CpaFlatBuffer* outBuf = &dev->qat.op.rsa_pub.outBuf;

    if (opData) {
        if (opData->inputData.pData) {
            XFREE(opData->inputData.pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            opData->inputData.pData = NULL;
        }
        XMEMSET(opData, 0, sizeof(CpaCyRsaEncryptOpData));
    }
    if (outBuf) {
        if (outBuf->pData) {
            XFREE(outBuf->pData, dev, DYNAMIC_TYPE_ASYNC_NUMA64);
            outBuf->pData = NULL;
        }
        XMEMSET(outBuf, 0, sizeof(CpaFlatBuffer));
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLenPtr = NULL;
}

static void IntelQaRsaPublicCallback(void *pCallbackTag,
        CpaStatus status, void *pOpdata, CpaFlatBuffer *pOut)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyRsaEncryptOpData* opData = (CpaCyRsaEncryptOpData*)pOpdata;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaRsaPublicCallback: dev %p, status %d, len %d\n",
        dev, status, pOut->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* validate returned output */
        if (dev->qat.outLenPtr) {
            if (pOut->dataLenInBytes > *dev->qat.outLenPtr) {
                pOut->dataLenInBytes = *dev->qat.outLenPtr;
            }
            *dev->qat.outLenPtr = pOut->dataLenInBytes;
        }

        /* return data */
        if (dev->qat.out && dev->qat.out != pOut->pData) {
            XMEMCPY(dev->qat.out, pOut->pData, pOut->dataLenInBytes);
        }

        /* mark event result */
        ret = 0; /* success */
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaRsaPublic(WC_ASYNC_DEV* dev,
                    const byte* in, word32 inLen,
                    WC_BIGINT* e, WC_BIGINT* n,
                    byte* out, word32* outLen)
{
    int ret = 0, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyRsaPublicKey* publicKey = NULL;
    CpaCyRsaEncryptOpData* opData = NULL;
    CpaFlatBuffer* outBuf = NULL;
    CpaCyGenFlatBufCbFunc callback = IntelQaRsaPublicCallback;

    if (dev == NULL || in == NULL || inLen == 0 || out == NULL ||
            outLen == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaRsaPublic: dev %p, in %p (%d), out %p\n",
        dev, in, inLen, out);
#endif

    /* setup operation */
    opData = &dev->qat.op.rsa_pub.opData;
    outBuf = &dev->qat.op.rsa_pub.outBuf;
    publicKey = &dev->qat.op.rsa_pub.publicKey;

    /* init variables */
    XMEMSET(opData, 0, sizeof(CpaCyRsaEncryptOpData));
    XMEMSET(outBuf, 0, sizeof(CpaFlatBuffer));
    XMEMSET(publicKey, 0, sizeof(CpaCyRsaPublicKey));

    /* assign buffers */
    ret =  IntelQaBigIntToFlatBuffer(e, &publicKey->publicExponentE);
    ret += IntelQaBigIntToFlatBuffer(n, &publicKey->modulusN);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    /* make sure output length is at least modulus len */
    if (*outLen < n->len)
        return BAD_FUNC_ARG;

    /* make sure output len is set to modulus size */
    *outLen = n->len;

    opData->inputData.dataLenInBytes = inLen;
    opData->inputData.pData = XREALLOC((byte*)in, inLen, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);

    outBuf->dataLenInBytes = *outLen;
    outBuf->pData = XREALLOC(out, *outLen, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA64);

    /* check allocations */
    if (opData->inputData.pData == NULL || outBuf->pData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* assign public key to public op data */
    opData->pPublicKey = publicKey;

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLenPtr = outLen;
    IntelQaOpInit(dev, IntelQaRsaPublicFree);

    /* perform RSA encrypt */
    do {
        status = cpaCyRsaEncrypt(dev->qat.handle,
                                callback,
                                dev,
                                opData,
                                outBuf);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_RSA_ASYNC, callback,
        &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyRsaEncrypt failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaRsaPublicFree(dev);

    return ret;
}

static void IntelQaRsaModExpFree(WC_ASYNC_DEV* dev)
{
    CpaCyLnModExpOpData* opData = &dev->qat.op.rsa_modexp.opData;
    CpaFlatBuffer* target = &dev->qat.op.rsa_modexp.target;

    if (opData) {
        if (opData->base.pData) {
            XFREE(opData->base.pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            opData->base.pData = NULL;
        }
        XMEMSET(opData, 0, sizeof(CpaCyLnModExpOpData));
    }
    if (target) {
        if (target->pData)
            XFREE(target->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        XMEMSET(target, 0, sizeof(CpaFlatBuffer));
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLenPtr = NULL;
}

static void IntelQaRsaModExpCallback(void *pCallbackTag,
        CpaStatus status, void *pOpdata, CpaFlatBuffer *pOut)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyLnModExpOpData* opData = (CpaCyLnModExpOpData*)pOpdata;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaRsaModExpCallback: dev %p, status %d, len %d\n",
        dev, status, pOut->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* validate returned output */
        if (dev->qat.outLenPtr) {
            if (pOut->dataLenInBytes > *dev->qat.outLenPtr) {
                pOut->dataLenInBytes = *dev->qat.outLenPtr;
            }
            *dev->qat.outLenPtr = pOut->dataLenInBytes;
        }

        /* return data */
        if (dev->qat.out && dev->qat.out != pOut->pData) {
            XMEMCPY(dev->qat.out, pOut->pData, pOut->dataLenInBytes);
        }

        /* mark event result */
        ret = 0; /* success */
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaRsaExptMod(WC_ASYNC_DEV* dev,
                    const byte* in, word32 inLen,
                    WC_BIGINT* e, WC_BIGINT* n,
                    byte* out, word32* outLen)
{
    int ret = 0, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyLnModExpOpData* opData = NULL;
    CpaFlatBuffer* target = NULL;
    CpaCyGenFlatBufCbFunc callback = IntelQaRsaModExpCallback;

    if (dev == NULL || in == NULL || inLen == 0 || out == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaRsaExptMod: dev %p, in %p (%d), out %p\n",
        dev, in, inLen, out);
#endif

    /* setup operation */
    opData = &dev->qat.op.rsa_modexp.opData;
    target = &dev->qat.op.rsa_modexp.target;

    /* init variables */
    XMEMSET(opData, 0, sizeof(CpaCyLnModExpOpData));
    XMEMSET(target, 0, sizeof(CpaFlatBuffer));

    /* assign buffers */
    ret =  IntelQaBigIntToFlatBuffer(e, &opData->exponent);
    ret += IntelQaBigIntToFlatBuffer(n, &opData->modulus);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    opData->base.dataLenInBytes = inLen;
    opData->base.pData = XREALLOC((byte*)in, inLen, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);

    target->dataLenInBytes = *outLen;
    target->pData = XREALLOC(out, *outLen, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);

    /* check allocations */
    if (opData->base.pData == NULL || target->pData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLenPtr = outLen;
    IntelQaOpInit(dev, IntelQaRsaModExpFree);

    /* make modexp call async */
    do {
        status = cpaCyLnModExp(dev->qat.handle,
                               callback,
                               dev,
                               opData,
                               target);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_EXPTMOD_ASYNC,
        callback, &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyLnModExp failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaRsaModExpFree(dev);

    return ret;
}
#endif /* !NO_RSA */


/* -------------------------------------------------------------------------- */
/* Symmetric Algos */
/* -------------------------------------------------------------------------- */

#if defined(QAT_ENABLE_CRYPTO) || defined(QAT_ENABLE_HASH)

static int IntelQaSymOpen(WC_ASYNC_DEV* dev, CpaCySymSessionSetupData* setup,
    CpaCySymCbFunc callback)
{
    int ret = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    IntelQaSymCtx* ctx;

    /* arg check */
    if (dev == NULL || setup == NULL) {
        return BAD_FUNC_ARG;
    }

    ctx = IntelQaGetSymCtx(dev);

    /* Determine size of session context to allocate - use max size */
    status = cpaCySymSessionCtxGetSize(dev->qat.handle, setup, &sessionCtxSize);

    if (status != CPA_STATUS_SUCCESS || (ctx->symCtxSize > 0 &&
                                         ctx->symCtxSize > sessionCtxSize)) {
        printf("Symmetric context size error %d! Buf %d, Exp %d\n",
            status, ctx->symCtxSize, sessionCtxSize);
        return ASYNC_OP_E;
    }

    /* make sure session context is allocated */
    if (ctx->symCtx == NULL) {
        /* Allocate session context */
        ctx->symCtx = XMALLOC(sessionCtxSize, dev->heap,
            DYNAMIC_TYPE_ASYNC_NUMA64);
        if (ctx->symCtx == NULL) {
            return MEMORY_E;
        }
    }
    ctx->symCtxSize = sessionCtxSize;

    if (!ctx->isOpen) {
        ctx->isOpen = 1;

    #ifdef QAT_DEBUG
        printf("IntelQaSymOpen: InitSession dev %p, symCtx %p\n",
            dev, ctx->symCtx);
    #endif

        /* open symmetric session */
        status = cpaCySymInitSession(dev->qat.handle, callback, setup,
            ctx->symCtx);
        if (status != CPA_STATUS_SUCCESS) {
            printf("cpaCySymInitSession failed! dev %p, status %d\n",
                dev, status);
            XFREE(ctx->symCtx, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA64);
            ctx->symCtx = NULL;
            return ASYNC_INIT_E;
        }
    }

    if (ctx->symCtxSrc == NULL) {
        ctx->symCtxSrc = ctx->symCtx;
    }

#ifdef QAT_DEBUG
    printf("IntelQaSymOpen: dev %p, symCtx %p (src %p), symCtxSize %d, "
           "isCopy %d, isOpen %d\n",
        dev, ctx->symCtx, ctx->symCtxSrc, ctx->symCtxSize, ctx->isCopy,
        ctx->isOpen);
#endif

    return ret;
}

static int IntelQaSymClose(WC_ASYNC_DEV* dev, int doFree)
{
    int ret = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    IntelQaSymCtx* ctx;
#ifdef QAT_ENABLE_HASH
    int isHash;
#endif

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

    ctx = IntelQaGetSymCtx(dev);

#ifdef QAT_ENABLE_HASH
    isHash = IntelQaDevIsHash(dev);
#endif

#ifdef QAT_DEBUG
    printf("IntelQaSymClose: dev %p, ctx %p, symCtx %p (src %p), "
           "symCtxSize %d, isCopy %d, isOpen %d, doFree %d\n",
        dev, ctx, ctx->symCtx, ctx->symCtxSrc, ctx->symCtxSize, ctx->isCopy,
        ctx->isOpen, doFree);
#endif

    if (ctx->symCtx == ctx->symCtxSrc && ctx->symCtx != NULL) {
        if (ctx->isOpen) {
            ctx->isOpen = 0;
        #ifdef QAT_DEBUG
            printf("IntelQaSymClose: RemoveSession dev %p, symCtx %p\n",
                dev, ctx->symCtx);
        #endif
            status = cpaCySymRemoveSession(dev->qat.handle, ctx->symCtx);
            if (status == CPA_STATUS_RETRY) {
                printf("cpaCySymRemoveSession retry!\n");
                /* treat this as error, since session should not be active */
                ret = ASYNC_OP_E;
            }
            else if (status != CPA_STATUS_SUCCESS) {
                printf("cpaCySymRemoveSession failed! status %d\n", status);
                ret = ASYNC_OP_E;
            }
        }
    }

    if (doFree) {
        XFREE(ctx->symCtx, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA64);
        ctx->symCtx = NULL;
        ctx->symCtxSrc = NULL;
        ctx->symCtxSize = 0;
    }

#ifdef QAT_ENABLE_HASH
    /* make sure hash temp buffer is cleared */

    if (isHash) {
        if (dev->qat.op.hash.tmpIn) {
            XFREE(dev->qat.op.hash.tmpIn, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        }
    }
#endif

    return ret;
}

#endif /* QAT_ENABLE_CRYPTO || QAT_ENABLE_HASH */


/* -------------------------------------------------------------------------- */
/* AES/DES Algo */
/* -------------------------------------------------------------------------- */

#ifdef QAT_ENABLE_CRYPTO
static void IntelQaSymCipherFree(WC_ASYNC_DEV* dev)
{
    IntelQaSymCtx* ctx = &dev->qat.op.cipher.ctx;
    CpaCySymOpData* opData = &ctx->opData;
    CpaBufferList* pDstBuffer = &dev->qat.op.cipher.bufferList;

    if (opData) {
        if (opData->pAdditionalAuthData) {
            XFREE(opData->pAdditionalAuthData, dev->heap,
                DYNAMIC_TYPE_ASYNC_NUMA);
            opData->pAdditionalAuthData = NULL;
        }
        if (opData->pIv) {
            XFREE(opData->pIv, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            opData->pIv = NULL;
        }
        XMEMSET(opData, 0, sizeof(CpaCySymOpData));
    }
    if (pDstBuffer) {
        if (pDstBuffer->pBuffers) {
            if (pDstBuffer->pBuffers->pData) {
                XFREE(pDstBuffer->pBuffers->pData, dev->heap,
                    DYNAMIC_TYPE_ASYNC_NUMA);
                pDstBuffer->pBuffers->pData = NULL;
            }
            XMEMSET(pDstBuffer->pBuffers, 0, sizeof(CpaFlatBuffer));
        }
        if (pDstBuffer->pPrivateMetaData) {
            XFREE(pDstBuffer->pPrivateMetaData, dev->heap,
                DYNAMIC_TYPE_ASYNC_NUMA);
            pDstBuffer->pPrivateMetaData = NULL;
        }
        XMEMSET(pDstBuffer, 0, sizeof(CpaBufferList));
    }

    /* close and free sym context */
    IntelQaSymClose(dev, 1);

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLen = 0;
#ifndef NO_AES
    dev->qat.op.cipher.authTag = NULL;
    dev->qat.op.cipher.authTagSz = 0;
#endif
}

static void IntelQaSymCipherCallback(void *pCallbackTag, CpaStatus status,
    const CpaCySymOp operationType, void *pOpData, CpaBufferList *pDstBuffer,
    CpaBoolean verifyResult)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCySymOpData* opData = (CpaCySymOpData*)pOpData;
    int ret = ASYNC_OP_E;

    (void)opData;
    (void)verifyResult;
    (void)pDstBuffer;
    (void)operationType;

#ifdef QAT_DEBUG
    printf("IntelQaSymCipherCallback: dev %p, type %d, status %d, "
           "verifyResult %d, num %d\n",
        dev, operationType, status, verifyResult, pDstBuffer->numBuffers);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* validate returned output */
        if (pDstBuffer && pDstBuffer->numBuffers >= 1) {
            /* check length */
            word32 outLen = pDstBuffer->pBuffers->dataLenInBytes;

            if (outLen > dev->qat.outLen) {
                outLen = dev->qat.outLen;
            }

            /* return data */
            if (dev->qat.out && dev->qat.out != pDstBuffer->pBuffers->pData) {
                XMEMCPY(dev->qat.out, pDstBuffer->pBuffers->pData, outLen);
            }

            /* capture IV for next call */
            if (dev->qat.op.cipher.iv && dev->qat.op.cipher.ivSz > 0) {
                word32 ivSz = dev->qat.op.cipher.ivSz;
                if (ivSz > outLen)
                    ivSz = outLen;
                /* copy last block */
                XMEMCPY(dev->qat.op.cipher.iv,
                        &pDstBuffer->pBuffers->pData[outLen - ivSz],
                        ivSz);
            }

        #ifndef NO_AES
            /* return authTag */
            if (dev->qat.op.cipher.authTag &&
                dev->qat.op.cipher.authTagSz > 0) {
                word32 authTagLen = dev->qat.op.cipher.authTagSz;

                /* check authtag length */
                if (authTagLen + outLen > pDstBuffer->pBuffers->dataLenInBytes)
                    authTagLen = pDstBuffer->pBuffers->dataLenInBytes - outLen;

                XMEMCPY(dev->qat.op.cipher.authTag,
                    pDstBuffer->pBuffers->pData + outLen, authTagLen);
            }
        #endif

            /* return length */
            dev->qat.outLen = outLen;

            /* mark event result */
            ret = 0; /* success */
        }
    }

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

static int IntelQaSymCipher(WC_ASYNC_DEV* dev, byte* out, const byte* in,
    word32 inOutSz, const byte* key, word32 keySz, byte* iv, word32 ivSz,
    CpaCySymOp symOperation, CpaCySymCipherAlgorithm cipherAlgorithm,
    CpaCySymCipherDirection cipherDirection,

    /* for auth ciphers (CCM or GCM) */
    CpaCySymHashAlgorithm hashAlgorithm,
    byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymOpData* opData = NULL;
    CpaCySymSessionSetupData setup;
    const Cpa32U numBuffers = 1;
    CpaBufferList* bufferList = NULL;
    CpaFlatBuffer* flatBuffer = NULL;
    CpaCySymCbFunc callback = IntelQaSymCipherCallback;
    Cpa8U* ivBuf = NULL;
    Cpa8U* dataBuf = NULL;
    Cpa32U dataLen = inOutSz;
    Cpa8U* metaBuf = NULL;
    Cpa32U metaSize = 0;
    Cpa8U* authInBuf = NULL;
    Cpa32U authInSzAligned = authInSz;
    IntelQaSymCtx* ctx;

#ifdef QAT_DEBUG
    printf("IntelQaSymCipher: dev %p, out %p, in %p, inOutSz %d, op %d, "
           "algo %d, dir %d, hash %d\n",
        dev, out, in, inOutSz, symOperation, cipherAlgorithm, cipherDirection,
        hashAlgorithm);
#endif

    /* check args */
    if (out == NULL || in == NULL || inOutSz == 0 ||
        key == NULL || keySz == 0 || iv == NULL || ivSz == 0) {
        return BAD_FUNC_ARG;
    }
    if (hashAlgorithm != CPA_CY_SYM_HASH_NONE &&
        (authTag == NULL || authTagSz == 0)) {
        return BAD_FUNC_ARG;
    }

    /* get meta size */
    status = cpaCyBufferListGetMetaSize(dev->qat.handle, numBuffers, &metaSize);
    if (status != CPA_STATUS_SUCCESS && metaSize <= 0) {
        ret = BUFFER_E; goto exit;
    }

    /* if authtag provided then it will be appended to end of input */
    if (authTag && authTagSz > 0) {
        dataLen += authTagSz;
    }

    /* allocate buffers */
    ctx = &dev->qat.op.cipher.ctx;
    opData = &ctx->opData;
    bufferList = &dev->qat.op.cipher.bufferList;
    flatBuffer = &dev->qat.op.cipher.flatBuffer;
    metaBuf = XMALLOC(metaSize, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    dataBuf = XREALLOC((byte*)in, dataLen, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    ivBuf = XREALLOC((byte*)iv, AES_BLOCK_SIZE, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);

    /* check allocations */
    if (ivBuf == NULL || metaBuf == NULL || dataBuf == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* AAD */
    if (authIn && authInSz > 0) {
        /* make sure AAD is block aligned */
        if (authInSzAligned % AES_BLOCK_SIZE) {
            authInSzAligned += AES_BLOCK_SIZE -
                (authInSzAligned % AES_BLOCK_SIZE);
        }

        authInBuf = XREALLOC((byte*)authIn, authInSzAligned, dev->heap,
            DYNAMIC_TYPE_ASYNC_NUMA);
        if (authInBuf == NULL) {
            ret = MEMORY_E; goto exit;
        }
        /* clear remainder */
        XMEMSET(authInBuf + authInSz, 0, authInSzAligned - authInSz);
    }

    /* init buffers */
    XMEMSET(&setup, 0, sizeof(CpaCySymSessionSetupData));
    XMEMSET(opData, 0, sizeof(CpaCySymOpData));
    XMEMSET(bufferList, 0, sizeof(CpaBufferList));
    XMEMSET(flatBuffer, 0, sizeof(CpaFlatBuffer));
    XMEMSET(metaBuf, 0, metaSize);

    bufferList->pBuffers = flatBuffer;
    bufferList->numBuffers = numBuffers;
    bufferList->pPrivateMetaData = metaBuf;
    flatBuffer->dataLenInBytes = dataLen;
    flatBuffer->pData = dataBuf;

    /* setup */
    setup.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    setup.symOperation = symOperation;
    setup.cipherSetupData.cipherAlgorithm = cipherAlgorithm;
    setup.cipherSetupData.cipherKeyLenInBytes = keySz;
    setup.cipherSetupData.pCipherKey = (byte*)key;
    setup.cipherSetupData.cipherDirection = cipherDirection;

    /* setup auth ciphers */
    if (hashAlgorithm != CPA_CY_SYM_HASH_NONE) {
        setup.algChainOrder =
            (cipherDirection == CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT) ?
                CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH :
                CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;

        setup.hashSetupData.hashAlgorithm = hashAlgorithm;
        setup.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        setup.hashSetupData.digestResultLenInBytes = authTagSz;
        setup.hashSetupData.authModeSetupData.aadLenInBytes = authInSz;

        setup.digestIsAppended = CPA_TRUE;
    }

    /* open session */
    ret = IntelQaSymOpen(dev, &setup, callback);
    if (ret != 0) {
        goto exit;
    }

    /* operation data */
    opData->sessionCtx = ctx->symCtx;
    opData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    opData->pIv = ivBuf;
    opData->ivLenInBytes = ivSz;
    opData->cryptoStartSrcOffsetInBytes = 0;
    opData->messageLenToCipherInBytes = inOutSz;
    if (authIn && authInSz > 0) {
        opData->pAdditionalAuthData = authInBuf;
    }
    if (cipherDirection == CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT) {
        if (authTag && authTagSz > 0) {
            /* append digest to end of data buffer */
            XMEMCPY(flatBuffer->pData + inOutSz, authTag, authTagSz);
        }
    }

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLen = inOutSz;
    /* optional return of next IV */
    if (cipherAlgorithm != CPA_CY_SYM_CIPHER_AES_GCM && iv) {
        if (ivSz > inOutSz)
            ivSz = inOutSz;
        if (cipherDirection == CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT) {
            /* capture this on the callback */
            dev->qat.op.cipher.iv = iv;
            dev->qat.op.cipher.ivSz = ivSz;
        }
        else {
            /* capture last block of input as next IV */
            XMEMCPY(iv, &in[inOutSz - ivSz], ivSz);
        }
    }
    if (cipherDirection == CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT) {
        dev->qat.op.cipher.authTag = authTag;
        dev->qat.op.cipher.authTagSz = authTagSz;
    }
    else {
        dev->qat.op.cipher.authTag = NULL;
        dev->qat.op.cipher.authTagSz = 0;
    }
    IntelQaOpInit(dev, IntelQaSymCipherFree);

    /* perform symmetric AES operation async */
    /* use same buffer list for in-place operation */
    do {
        status = cpaCySymPerformOp(dev->qat.handle,
                                   dev,
                                   opData,
                                   bufferList,
                                   bufferList,
                                   NULL);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_CIPHER_ASYNC,
        callback, &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCySymPerformOp Cipher failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaSymCipherFree(dev);

    return ret;
}

#ifdef HAVE_AES_CBC
int IntelQaSymAesCbcEncrypt(WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            byte* iv, word32 ivSz)
{
    return IntelQaSymCipher(dev, out, in, sz,
        key, keySz, iv, ivSz,
        CPA_CY_SYM_OP_CIPHER, CPA_CY_SYM_CIPHER_AES_CBC,
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
        CPA_CY_SYM_HASH_NONE, NULL, 0, NULL, 0);
}

#ifdef HAVE_AES_DECRYPT
int IntelQaSymAesCbcDecrypt(WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            byte* iv, word32 ivSz)
{
    return IntelQaSymCipher(dev, out, in, sz,
        key, keySz, iv, ivSz,
        CPA_CY_SYM_OP_CIPHER, CPA_CY_SYM_CIPHER_AES_CBC,
        CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT,
        CPA_CY_SYM_HASH_NONE, NULL, 0, NULL, 0);
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */


#ifdef HAVE_AESGCM
int IntelQaSymAesGcmEncrypt(WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz,
            byte* authTag, word32 authTagSz,
            const byte* authIn, word32 authInSz)
{
    return IntelQaSymCipher(dev, out, in, sz,
        key, keySz, (byte*)iv, ivSz,
        CPA_CY_SYM_OP_ALGORITHM_CHAINING, CPA_CY_SYM_CIPHER_AES_GCM,
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
        CPA_CY_SYM_HASH_AES_GCM, authTag, authTagSz, authIn, authInSz);
}
#ifdef HAVE_AES_DECRYPT
int IntelQaSymAesGcmDecrypt(WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz,
            const byte* authTag, word32 authTagSz,
            const byte* authIn, word32 authInSz)
{
    return IntelQaSymCipher(dev, out, in, sz,
        key, keySz, (byte*)iv, ivSz,
        CPA_CY_SYM_OP_ALGORITHM_CHAINING, CPA_CY_SYM_CIPHER_AES_GCM,
        CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT,
        CPA_CY_SYM_HASH_AES_GCM, (byte*)authTag, authTagSz, authIn, authInSz);
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */

#ifndef NO_DES3
int IntelQaSymDes3CbcEncrypt(WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            byte* iv, word32 ivSz)
{
    return IntelQaSymCipher(dev, out, in, sz,
        key, keySz, iv, ivSz,
        CPA_CY_SYM_OP_CIPHER, CPA_CY_SYM_CIPHER_3DES_CBC,
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
        CPA_CY_SYM_HASH_NONE, NULL, 0, NULL, 0);
}

int IntelQaSymDes3CbcDecrypt(WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            byte* iv, word32 ivSz)
{
    return IntelQaSymCipher(dev, out, in, sz,
        key, keySz, iv, ivSz,
        CPA_CY_SYM_OP_CIPHER, CPA_CY_SYM_CIPHER_3DES_CBC,
        CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT,
        CPA_CY_SYM_HASH_NONE, NULL, 0, NULL, 0);
}
#endif /* !NO_DES3 */

#endif /* QAT_ENABLE_CRYPTO */


/* -------------------------------------------------------------------------- */
/* Hashing Algo */
/* -------------------------------------------------------------------------- */

#ifdef QAT_ENABLE_HASH
static int IntelQaSymHashGetInfo(CpaCySymHashAlgorithm hashAlgorithm,
    Cpa32U* pBlockSize, Cpa32U* pDigestSize)
{
    Cpa32U blockSize = 0;
    Cpa32U digestSize = 0;

    switch(hashAlgorithm) {
        case CPA_CY_SYM_HASH_MD5:
        #ifndef NO_MD5
            blockSize = WC_MD5_BLOCK_SIZE;
            digestSize = WC_MD5_DIGEST_SIZE;
        #endif
            break;
        case CPA_CY_SYM_HASH_SHA1:
        #ifndef NO_SHA
            blockSize = WC_SHA_BLOCK_SIZE;
            digestSize = WC_SHA_DIGEST_SIZE;
        #endif
            break;
        case CPA_CY_SYM_HASH_SHA224:
        #ifdef WOLFSSL_SHA224
            blockSize = WC_SHA224_BLOCK_SIZE;
            digestSize = WC_SHA224_DIGEST_SIZE;
        #endif
            break;
        case CPA_CY_SYM_HASH_SHA256:
        #ifndef NO_SHA256
            blockSize = WC_SHA256_BLOCK_SIZE;
            digestSize = WC_SHA256_DIGEST_SIZE;
        #endif
            break;
        case CPA_CY_SYM_HASH_SHA384:
        #if defined(WOLFSSL_SHA512) && defined(WOLFSSL_SHA384)
            blockSize = WC_SHA384_BLOCK_SIZE;
            digestSize = WC_SHA384_DIGEST_SIZE;
        #endif
            break;
        case CPA_CY_SYM_HASH_SHA512:
        #ifdef WOLFSSL_SHA512
            blockSize = WC_SHA512_BLOCK_SIZE;
            digestSize = WC_SHA512_DIGEST_SIZE;
        #endif
            break;
    #ifdef QAT_V2
        case CPA_CY_SYM_HASH_SHA3_256:
        #ifdef WOLFSSL_SHA3
            blockSize = WC_SHA3_256_BLOCK_SIZE;
            digestSize = WC_SHA3_256_DIGEST_SIZE;
        #endif
            break;
    #endif

        /* not supported */
        case CPA_CY_SYM_HASH_NONE:
        case CPA_CY_SYM_HASH_AES_XCBC:
        case CPA_CY_SYM_HASH_AES_CCM:
        case CPA_CY_SYM_HASH_AES_GCM:
        case CPA_CY_SYM_HASH_KASUMI_F9:
        case CPA_CY_SYM_HASH_SNOW3G_UIA2:
        case CPA_CY_SYM_HASH_AES_CMAC:
        case CPA_CY_SYM_HASH_AES_GMAC:
        case CPA_CY_SYM_HASH_AES_CBC_MAC:
    #ifdef QAT_V2
        case CPA_CY_SYM_HASH_ZUC_EIA3:
    #ifdef QAT_V2_4_PLUS
        case CPA_CY_SYM_HASH_SHA3_224:
        case CPA_CY_SYM_HASH_SHA3_384:
        case CPA_CY_SYM_HASH_SHA3_512:
        case CPA_CY_SYM_HASH_SHAKE_128:
        case CPA_CY_SYM_HASH_SHAKE_256:
        case CPA_CY_SYM_HASH_POLY:
        case CPA_CY_SYM_HASH_SM3:
    #endif /* QAT_V2_4_PLUS */
    #endif /* QAT_V2 */
        default:
            return -1;
    }

    if (pBlockSize)
        *pBlockSize = blockSize;
    if (pDigestSize)
        *pDigestSize = digestSize;

    return 0;
}

static void IntelQaSymHashFree(WC_ASYNC_DEV* dev)
{
    IntelQaSymCtx* ctx = &dev->qat.op.hash.ctx;
    CpaCySymOpData* opData = &ctx->opData;
    CpaBufferList* pDstBuffer = dev->qat.op.hash.srcList;
    int idx;

    if (opData) {
        if (opData->pDigestResult) {
            XFREE(opData->pDigestResult, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            opData->pDigestResult = NULL;
        }
        XMEMSET(opData, 0, sizeof(CpaCySymOpData));
    }

    if (pDstBuffer) {
        idx = pDstBuffer->numBuffers;
        while (--idx >= 0) {
            if (pDstBuffer->pBuffers[idx].pData) {
                XFREE(pDstBuffer->pBuffers[idx].pData, dev->heap,
                    DYNAMIC_TYPE_ASYNC_NUMA);
                pDstBuffer->pBuffers[idx].pData = NULL;
            }
        }

        XFREE(pDstBuffer, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    }

    /* if final */
    if (dev->qat.out) {
        int doFree = 0;

        /* free any tmp input */
        if (dev->qat.op.hash.tmpIn) {
            XFREE(dev->qat.op.hash.tmpIn, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        }
        dev->qat.op.hash.tmpIn = NULL;
        dev->qat.op.hash.tmpInSz = 0;
        dev->qat.op.hash.tmpInBufSz = 0;

        if (ctx->isCopy || ctx->symCtx != ctx->symCtxSrc) {
            doFree = 1;
        }

    #ifdef QAT_DEBUG
        printf("IntelQaSymHashFree: dev %p, doFree %d\n", dev, doFree);
    #endif

        /* close session */
        IntelQaSymClose(dev, doFree);
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLen = 0;
}

static void IntelQaSymHashCallback(void *pCallbackTag, CpaStatus status,
    const CpaCySymOp operationType, void *pOpData, CpaBufferList *pDstBuffer,
    CpaBoolean verifyResult)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCySymOpData* opData = (CpaCySymOpData*)pOpData;
    int ret = ASYNC_OP_E;

    (void)opData;
    (void)verifyResult;
    (void)pDstBuffer;
    (void)operationType;

#ifdef QAT_DEBUG
    printf("IntelQaSymHashCallback: dev %p, type %d, status %d, "
           "verifyResult %d, num %d\n",
        dev, operationType, status, verifyResult, pDstBuffer->numBuffers);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        if (dev->qat.out) {
            /* is final */

            /* return digest */
            if (dev->qat.outLen > 0 && dev->qat.out != opData->pDigestResult) {
                XMEMCPY(dev->qat.out, opData->pDigestResult, dev->qat.outLen);
            }
        }

        /* mark event result */
        ret = 0; /* success */
    }

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

/* For hash update call with out == NULL */
/* For hash final call with out != NULL */
/* All input is cached in memory or only sent to hardware on final */
#ifndef QAT_HASH_ALLOC_BLOCK_SZ
    #define QAT_HASH_ALLOC_BLOCK_SZ 1024
#endif
static int IntelQaSymHashCache(WC_ASYNC_DEV* dev, byte* out, const byte* in,
    word32 inOutSz, CpaCySymHashMode hashMode,
    CpaCySymHashAlgorithm hashAlgorithm,

    /* For HMAC auth mode only */
    Cpa8U* authKey, Cpa32U authKeyLenInBytes)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymOpData* opData = NULL;
    CpaCySymCbFunc callback = IntelQaSymHashCallback;
    CpaBufferList* srcList = NULL;
    Cpa32U bufferListSize = 0;
    Cpa8U* digestBuf = NULL;
    Cpa32U metaSize = 0;
    Cpa32U totalMsgSz = 0;
    Cpa32U blockSize;
    Cpa32U digestSize;
    CpaCySymPacketType packetType;
    IntelQaSymCtx* ctx;
    CpaCySymSessionSetupData setup;
    const int bufferCount = 1;

    ret = IntelQaSymHashGetInfo(hashAlgorithm, &blockSize, &digestSize);
    if (ret != 0) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaSymHashCache: dev %p, out %p, in %p, inOutSz %d, mode %d"
        ", algo %d, digSz %d, blkSz %d\n",
        dev, out, in, inOutSz, hashMode, hashAlgorithm, digestSize, blockSize);
#endif

    ctx = &dev->qat.op.hash.ctx;

    /* handle input processing */
    if (in) {
        if (dev->qat.op.hash.tmpIn == NULL) {
            dev->qat.op.hash.tmpInSz = 0;
            dev->qat.op.hash.tmpInBufSz =
                (inOutSz + QAT_HASH_ALLOC_BLOCK_SZ - 1)
                       & ~(QAT_HASH_ALLOC_BLOCK_SZ - 1);
            if (dev->qat.op.hash.tmpInBufSz == 0)
                dev->qat.op.hash.tmpInBufSz = QAT_HASH_ALLOC_BLOCK_SZ;
            dev->qat.op.hash.tmpIn = (byte*)XMALLOC(dev->qat.op.hash.tmpInBufSz,
                dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            if (dev->qat.op.hash.tmpIn == NULL) {
                ret = MEMORY_E; goto exit;
            }
        }
        /* determine if we need to grow buffer */
        else if ((dev->qat.op.hash.tmpInSz + inOutSz) >
                                                dev->qat.op.hash.tmpInBufSz) {
            byte* oldIn = dev->qat.op.hash.tmpIn;
            dev->qat.op.hash.tmpInBufSz = (dev->qat.op.hash.tmpInSz + inOutSz +
                QAT_HASH_ALLOC_BLOCK_SZ - 1) & ~(QAT_HASH_ALLOC_BLOCK_SZ - 1);

             dev->qat.op.hash.tmpIn = (byte*)XMALLOC(
                dev->qat.op.hash.tmpInBufSz,
                dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            if (dev->qat.op.hash.tmpIn == NULL) {
                ret = MEMORY_E; goto exit;
            }
            XMEMCPY(dev->qat.op.hash.tmpIn, oldIn, dev->qat.op.hash.tmpInSz);
            XFREE(oldIn, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        }

        /* copy input to new buffer */
        XMEMCPY(&dev->qat.op.hash.tmpIn[dev->qat.op.hash.tmpInSz], in, inOutSz);
        dev->qat.op.hash.tmpInSz += inOutSz;

        ret = 0; /* success */
        goto exit;
    }
    else if (out != NULL && dev->qat.op.hash.tmpIn == NULL) {
        /* QAT requires an input buffer even for an empty hash */
        dev->qat.op.hash.tmpInSz = 0;
        dev->qat.op.hash.tmpInBufSz = 16; /* use minimum alignment (16 bytes) */
        dev->qat.op.hash.tmpIn = (byte*)XMALLOC(dev->qat.op.hash.tmpInBufSz,
            dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        if (dev->qat.op.hash.tmpIn == NULL) {
            ret = MEMORY_E; goto exit;
        }
    }

    /* handle output processing */
    packetType = CPA_CY_SYM_PACKET_TYPE_FULL;

    /* get meta size */
    status = cpaCyBufferListGetMetaSize(dev->qat.handle, bufferCount,
        &metaSize);
    if (status != CPA_STATUS_SUCCESS && metaSize <= 0) {
        ret = BUFFER_E; goto exit;
    }

    /* allocate buffer list */
    bufferListSize = sizeof(CpaBufferList) +
        (bufferCount * sizeof(CpaFlatBuffer)) + metaSize;
    srcList = XMALLOC(bufferListSize, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    if (srcList == NULL) {
        ret = MEMORY_E; goto exit;
    }
    dev->qat.op.hash.srcList = srcList;
    XMEMSET(srcList, 0, bufferListSize);
    srcList->pBuffers = (CpaFlatBuffer*)(
        (byte*)srcList + sizeof(CpaBufferList));
    srcList->pPrivateMetaData = (byte*)srcList + sizeof(CpaBufferList) +
        (bufferCount * sizeof(CpaFlatBuffer));

    srcList->numBuffers = bufferCount;
    srcList->pBuffers[0].dataLenInBytes = dev->qat.op.hash.tmpInSz;
    srcList->pBuffers[0].pData = dev->qat.op.hash.tmpIn;
    totalMsgSz = dev->qat.op.hash.tmpInSz;

    dev->qat.op.hash.tmpInSz = 0;
    dev->qat.op.hash.tmpInBufSz = 0;
    dev->qat.op.hash.tmpIn = NULL;

    /* build output */
    if (out) {
        /* use blockSize for alloc, but we are only returning digestSize */
        digestBuf = XMALLOC(blockSize, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        if (digestBuf == NULL) {
            ret = MEMORY_E; goto exit;
        }
    }

    /* setup */
    XMEMSET(&setup, 0, sizeof(CpaCySymSessionSetupData));
    setup.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    setup.symOperation = CPA_CY_SYM_OP_HASH;
    setup.partialsNotRequired = CPA_TRUE;
    setup.hashSetupData.hashMode = hashMode;
    setup.hashSetupData.hashAlgorithm = hashAlgorithm;
    setup.hashSetupData.digestResultLenInBytes = digestSize;
    setup.hashSetupData.authModeSetupData.authKey = authKey;
    setup.hashSetupData.authModeSetupData.authKeyLenInBytes = authKeyLenInBytes;

    /* open session */
    ret = IntelQaSymOpen(dev, &setup, callback);
    if (ret != 0) {
        goto exit;
    }

    /* operation data */
    opData = &ctx->opData;
    XMEMSET(opData, 0, sizeof(CpaCySymOpData));
    opData->sessionCtx = ctx->symCtx;
    opData->packetType = packetType;
    opData->messageLenToHashInBytes = totalMsgSz;
    opData->pDigestResult = digestBuf;

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLen = inOutSz;
    IntelQaOpInit(dev, IntelQaSymHashFree);

    /* perform symmetric hash operation async */
    /* use same buffer list for in-place operation */
    do {
        status = cpaCySymPerformOp(dev->qat.handle,
                                   dev,
                                   opData,
                                   srcList,
                                   srcList,
                                   NULL);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_HASH_ASYNC, callback,
        &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCySymPerformOp Hash failed! dev %p, status %d, ret %d\n",
            dev, status, ret);

        /* handle cleanup */
        IntelQaSymHashFree(dev);
    }

    return ret;
}

#ifdef QAT_HASH_ENABLE_PARTIAL

/* For hash update call with out == NULL */
/* For hash final call with out != NULL */
static int IntelQaSymHashPartial(WC_ASYNC_DEV* dev, byte* out, const byte* in,
    word32 inOutSz, CpaCySymHashMode hashMode,
    CpaCySymHashAlgorithm hashAlgorithm,

    /* For HMAC auth mode only */
    Cpa8U* authKey, Cpa32U authKeyLenInBytes)
{
    int ret, retryCount = 0, i;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymOpData* opData = NULL;
    CpaCySymCbFunc callback = IntelQaSymHashCallback;
    CpaBufferList* srcList = NULL;
    Cpa32U bufferListSize = 0;
    Cpa8U* digestBuf = NULL;
    Cpa32U metaSize = 0;
    Cpa32U totalMsgSz = 0;
    Cpa32U blockSize;
    Cpa32U digestSize;
    CpaCySymPacketType packetType;
    IntelQaSymCtx* ctx;
    CpaCySymSessionSetupData setup;

    int* bufferCount;
    byte** buffers;
    word32* buffersSz;

    ret = IntelQaSymHashGetInfo(hashAlgorithm, &blockSize, &digestSize);
    if (ret != 0) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaSymHashPartial: dev %p, out %p, in %p, inOutSz %d, mode %d, "
        "algo %d, digSz %d, blkSz %d\n",
        dev, out, in, inOutSz, hashMode, hashAlgorithm, digestSize, blockSize);
#endif

    ctx = &dev->qat.op.hash.ctx;

    bufferCount = &dev->qat.op.hash.bufferCount;
    buffers = dev->qat.op.hash.buffers;
    buffersSz = dev->qat.op.hash.buffersSz;

    /* handle input processing */
    if (in) {
        /* if tmp has data or input is not block aligned */
        if (dev->qat.op.hash.tmpInSz > 0 || inOutSz == 0 ||
            (inOutSz % blockSize) != 0) {
            /* need to handle unaligned hashing, using local tmp */

            /* make sure we have tmpIn allocated */
            if (dev->qat.op.hash.tmpIn == NULL) {
                dev->qat.op.hash.tmpInSz = 0;
                dev->qat.op.hash.tmpIn = XMALLOC(blockSize, dev->heap,
                    DYNAMIC_TYPE_ASYNC_NUMA);
                if (dev->qat.op.hash.tmpIn == NULL) {
                    ret = MEMORY_E; goto exit;
                }
                dev->qat.op.hash.tmpInBufSz = blockSize;
            }

            /* setup processing for block aligned part of input or use tmpIn */
            if (dev->qat.op.hash.tmpInSz > 0) {
                word32 remainSz = blockSize - dev->qat.op.hash.tmpInSz;

                /* attempt to fill tmpIn and process block */
                if (inOutSz < remainSz) {
                    /* not enough to fill buffer */
                    XMEMCPY(&dev->qat.op.hash.tmpIn[dev->qat.op.hash.tmpInSz],
                        in, inOutSz);
                    dev->qat.op.hash.tmpInSz += inOutSz;
                }
                else {
                    /* fill tmp buffer and add */
                    XMEMCPY(&dev->qat.op.hash.tmpIn[dev->qat.op.hash.tmpInSz],
                        in, remainSz);
                    dev->qat.op.hash.tmpInSz += remainSz;
                    buffers[*bufferCount] = dev->qat.op.hash.tmpIn;
                    buffersSz[*bufferCount] = dev->qat.op.hash.tmpInSz;
                    (*bufferCount)++;
                    inOutSz -= remainSz;
                    in += remainSz;
                    dev->qat.op.hash.tmpIn = NULL;
                    dev->qat.op.hash.tmpInSz = 0;

                    /* use remainder of block aligned */
                    if (inOutSz >= blockSize) {
                        word32 unalignedSz = (inOutSz % blockSize);
                        word32 inSz = inOutSz - unalignedSz;

                        buffersSz[*bufferCount] = inSz;
                        buffers[*bufferCount] = (byte*)XMALLOC(inSz,
                                    dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
                        if (buffers[*bufferCount] == NULL) {
                            ret = MEMORY_E; goto exit;
                        }
                        XMEMCPY(buffers[*bufferCount], (byte*)in, inSz);

                        (*bufferCount)++;
                        inOutSz -= inSz;
                        in += inSz;
                    }

                    /* save remainder to tmpIn */
                    if (inOutSz > 0) {
                        dev->qat.op.hash.tmpInSz = 0;
                        dev->qat.op.hash.tmpIn = XMALLOC(blockSize, dev->heap,
                            DYNAMIC_TYPE_ASYNC_NUMA);
                        if (dev->qat.op.hash.tmpIn == NULL) {
                            ret = MEMORY_E; goto exit;
                        }
                        dev->qat.op.hash.tmpInBufSz = blockSize;

                        XMEMCPY(dev->qat.op.hash.tmpIn, in, inOutSz);
                        dev->qat.op.hash.tmpInSz = inOutSz;
                    }
                }
            }
            else {
                /* if not enough to fit into blockSize store into tmpIn */
                if (inOutSz < blockSize) {
                    dev->qat.op.hash.tmpInSz = inOutSz;
                    XMEMCPY(dev->qat.op.hash.tmpIn, in, inOutSz);
                }
                else {
                    word32 unalignedSz = (inOutSz % blockSize);
                    word32 inSz = inOutSz - unalignedSz;

                    buffersSz[*bufferCount] = inSz;
                    buffers[*bufferCount] = (byte*)XREALLOC((byte*)in,
                        inSz, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
                    if (buffers[*bufferCount] == NULL) {
                        ret = MEMORY_E; goto exit;
                    }
                    (*bufferCount)++;

                    /* store remainder */
                    dev->qat.op.hash.tmpInSz = unalignedSz;
                    XMEMCPY(dev->qat.op.hash.tmpIn, &in[inSz], unalignedSz);
                }
            }

        }
        else {
            /* use input directly */
            buffersSz[*bufferCount] = inOutSz;
            buffers[*bufferCount] = (byte*)XREALLOC((byte*)in,
                buffersSz[*bufferCount], dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            if (buffers[*bufferCount] == NULL) {
                ret = MEMORY_E; goto exit;
            }
            (*bufferCount)++;
        }
    }

    /* determine if early exit is okay */
    if (out == NULL) {
        /* if not final and no in buffers then exit with success */
        if (*bufferCount == 0) {
            ret = 0; /* return success */
            goto exit;
        }

        /* for auth must pass in buffer, so leave one in buffer cache */
        else if (hashMode == CPA_CY_SYM_HASH_MODE_AUTH && *bufferCount <= 1) {
            ret = 0; /* return success */
            goto exit;
        }
    }

    /* determine packet type and add any remainder to input processing */
    packetType = CPA_CY_SYM_PACKET_TYPE_PARTIAL;
    if (out) {
        /* if remainder then add it */
        if (dev->qat.op.hash.tmpIn) {
            /* add buffer and use final hash type */
            buffers[*bufferCount] = dev->qat.op.hash.tmpIn;
            buffersSz[*bufferCount] = dev->qat.op.hash.tmpInSz;
            (*bufferCount)++;
            dev->qat.op.hash.tmpIn = NULL;
            dev->qat.op.hash.tmpInSz = 0;
        }

        /* determine if this is full or partial */
        if (ctx->symCtxSrc == NULL || (!ctx->isOpen && !ctx->isCopy)) {
            packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        }
        else {
            packetType = CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL;
        }
    }

    /* get meta size */
    status = cpaCyBufferListGetMetaSize(dev->qat.handle, *bufferCount,
        &metaSize);
    if (status != CPA_STATUS_SUCCESS && metaSize <= 0) {
        ret = BUFFER_E; goto exit;
    }

    /* allocate buffer list */
    bufferListSize = sizeof(CpaBufferList) +
        (*bufferCount * sizeof(CpaFlatBuffer)) + metaSize;
    srcList = XMALLOC(bufferListSize, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    if (srcList == NULL) {
        ret = MEMORY_E; goto exit;
    }
    dev->qat.op.hash.srcList = srcList;
    XMEMSET(srcList, 0, bufferListSize);
    srcList->pBuffers = (CpaFlatBuffer*)(
        (byte*)srcList + sizeof(CpaBufferList));
    srcList->pPrivateMetaData = (byte*)srcList + sizeof(CpaBufferList) +
        (*bufferCount * sizeof(CpaFlatBuffer));
    for (i = 0; i < *bufferCount; i++) {
        srcList->pBuffers[i].dataLenInBytes = buffersSz[i];
        srcList->pBuffers[i].pData = buffers[i];
        totalMsgSz += buffersSz[i];
    }
    srcList->numBuffers = *bufferCount;

    /* clear buffer cache */
    dev->qat.op.hash.bufferCount = 0;
    for (i=0; i<MAX_QAT_HASH_BUFFERS; i++) {
        dev->qat.op.hash.buffers[i] = NULL;
        dev->qat.op.hash.buffersSz[i] = 0;
    }

    /* build output */
    if (out) {
        /* use blockSize for alloc, but we are only returning digestSize */
        digestBuf = XMALLOC(blockSize, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        if (digestBuf == NULL) {
            ret = MEMORY_E; goto exit;
        }
    }

    /* setup */
    XMEMSET(&setup, 0, sizeof(CpaCySymSessionSetupData));
    setup.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    setup.symOperation = CPA_CY_SYM_OP_HASH;
    setup.partialsNotRequired = (packetType == CPA_CY_SYM_PACKET_TYPE_FULL) ?
        CPA_TRUE : CPA_FALSE;
    setup.hashSetupData.hashMode = hashMode;
    setup.hashSetupData.hashAlgorithm = hashAlgorithm;
    setup.hashSetupData.digestResultLenInBytes = digestSize;
    setup.hashSetupData.authModeSetupData.authKey = authKey;
    setup.hashSetupData.authModeSetupData.authKeyLenInBytes = authKeyLenInBytes;

    /* open session */
    ret = IntelQaSymOpen(dev, &setup, callback);
    if (ret != 0) {
        goto exit;
    }

    /* workarounds for handling symmetric context copies */
    if (packetType == CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL) {
        /* set the partialState for partial  */
    #ifdef USE_LAC_SESSION_FOR_STRUCT_OFFSET
        word32 parStaOffset = (word32)offsetof(lac_session_desc_t,
            partialState);
    #else
        word32 parStaOffset = (28 * 16);
    #endif

        /* make sure partialState is partial, try + 16 alignments as well */
        for (i = 0; i < 4; i++) {
            word32* priorVal = (word32*)((byte*)ctx->symCtx + parStaOffset +
                (i * 16));
            if (*priorVal == CPA_CY_SYM_PACKET_TYPE_FULL) {
                *priorVal = CPA_CY_SYM_PACKET_TYPE_PARTIAL;
                break;
            }
        }
    }
    if (ctx->symCtx != ctx->symCtxSrc) {
        /* copy hash state (digest into new symmetric context) */
        byte* symCtxDst = (byte*)ctx->symCtx;
        byte* symCtxSrc = (byte*)ctx->symCtxSrc;
        /* copy from hashStatePrefixBuffer to end */
    #ifdef USE_LAC_SESSION_FOR_STRUCT_OFFSET
        const word32 copyRegion = (word32)offsetof(lac_session_desc_t,
            hashStatePrefixBuffer);
    #else
        const word32 copyRegion = (41 * 16);
    #endif
        XMEMCPY(&symCtxDst[copyRegion], &symCtxSrc[copyRegion],
            ctx->symCtxSize - copyRegion);
    }

    /* operation data */
    opData = &ctx->opData;
    XMEMSET(opData, 0, sizeof(CpaCySymOpData));
    opData->sessionCtx = ctx->symCtx;
    opData->packetType = packetType;
    opData->messageLenToHashInBytes = totalMsgSz;
    opData->pDigestResult = digestBuf;

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLen = inOutSz;
    IntelQaOpInit(dev, IntelQaSymHashFree);

    /* perform symmetric hash operation async */
    /* use same buffer list for in-place operation */
    do {
        status = cpaCySymPerformOp(dev->qat.handle,
                                   dev,
                                   opData,
                                   srcList,
                                   srcList,
                                   NULL);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_HASH_ASYNC, callback,
        &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCySymPerformOp Hash partial failed! dev %p, status %d, "
               "ret %d\n", dev, status, ret);

        /* handle cleanup */
        IntelQaSymHashFree(dev);
    }

    return ret;
}
#endif /* QAT_HASH_ENABLE_PARTIAL */


/* For hash update call with out == NULL */
/* For hash final call with out != NULL */
static int IntelQaSymHash(WC_ASYNC_DEV* dev, byte* out, const byte* in,
    word32 inOutSz, CpaCySymHashMode hashMode,
    CpaCySymHashAlgorithm hashAlgorithm,

    /* For HMAC auth mode only */
    Cpa8U* authKey, Cpa32U authKeyLenInBytes)
{
    /* check args */
    if (dev == NULL || (out == NULL && in == NULL) ||
                                    hashAlgorithm == CPA_CY_SYM_HASH_NONE) {
        return BAD_FUNC_ARG;
    }

    /* trap call with both in and out set */
    if (in != NULL && out != NULL) {
        printf("IntelQaSymHash: Cannot call with in and out both set\n");
        return BAD_FUNC_ARG;
    }

    if (inOutSz == 0) {
        return 0; /* nothing to do, return success */
    }

#ifdef QAT_HASH_ENABLE_PARTIAL
    if (g_qatCapabilities.supPartial
    #ifdef QAT_V2
        && hashAlgorithm != CPA_CY_SYM_HASH_SHA3_256
    #endif
    ) {
        return IntelQaSymHashPartial(dev, out, in, inOutSz, hashMode,
            hashAlgorithm, authKey, authKeyLenInBytes);
    }
    else
#endif
    return IntelQaSymHashCache(dev, out, in, inOutSz, hashMode,
        hashAlgorithm, authKey, authKeyLenInBytes);
}

#ifdef WOLFSSL_SHA512
int IntelQaSymSha512(WC_ASYNC_DEV* dev, byte* out, const byte* in, word32 sz)
{
    return IntelQaSymHash(dev, out, in, sz,
        CPA_CY_SYM_HASH_MODE_PLAIN, CPA_CY_SYM_HASH_SHA512, NULL, 0);
}

#ifdef WOLFSSL_SHA384
int IntelQaSymSha384(WC_ASYNC_DEV* dev, byte* out, const byte* in, word32 sz)
{
    return IntelQaSymHash(dev, out, in, sz,
        CPA_CY_SYM_HASH_MODE_PLAIN, CPA_CY_SYM_HASH_SHA384, NULL, 0);
}
#endif /* WOLFSSL_SHA384 */
#endif /* WOLFSSL_SHA512 */

#ifndef NO_SHA256
int IntelQaSymSha256(WC_ASYNC_DEV* dev, byte* out, const byte* in, word32 sz)
{
    return IntelQaSymHash(dev, out, in, sz,
        CPA_CY_SYM_HASH_MODE_PLAIN, CPA_CY_SYM_HASH_SHA256, NULL, 0);
}
#ifdef WOLFSSL_SHA224
int IntelQaSymSha224(WC_ASYNC_DEV* dev, byte* out, const byte* in, word32 sz)
{
    return IntelQaSymHash(dev, out, in, sz,
        CPA_CY_SYM_HASH_MODE_PLAIN, CPA_CY_SYM_HASH_SHA224, NULL, 0);
}
#endif /* WOLFSSL_SHA224 */
#endif /* !NO_SHA256 */

#ifndef NO_SHA
int IntelQaSymSha(WC_ASYNC_DEV* dev, byte* out, const byte* in, word32 sz)
{
    return IntelQaSymHash(dev, out, in, sz,
        CPA_CY_SYM_HASH_MODE_PLAIN, CPA_CY_SYM_HASH_SHA1, NULL, 0);
}
#endif /* !NO_SHA */

#ifndef NO_MD5
int IntelQaSymMd5(WC_ASYNC_DEV* dev, byte* out, const byte* in, word32 sz)
{
    return IntelQaSymHash(dev, out, in, sz,
        CPA_CY_SYM_HASH_MODE_PLAIN, CPA_CY_SYM_HASH_MD5, NULL, 0);
}
#endif /* !NO_MD5 */

#if defined(WOLFSSL_SHA3) && defined(QAT_V2)
int IntelQaSymSha3(WC_ASYNC_DEV* dev, byte* out, const byte* in, word32 sz)
{
    if (g_qatCapabilities.supSha3) {
        return IntelQaSymHash(dev, out, in, sz,
            CPA_CY_SYM_HASH_MODE_PLAIN, CPA_CY_SYM_HASH_SHA3_256, NULL, 0);
    }
    return NOT_COMPILED_IN;
}
#endif

#ifndef NO_HMAC
    int IntelQaHmacGetType(int macType, word32* hashAlgorithm)
    {
        int ret = NOT_COMPILED_IN;

        switch (macType) {
        #ifndef NO_MD5
            case WC_MD5:
                if (hashAlgorithm) *hashAlgorithm = CPA_CY_SYM_HASH_MD5;
                ret = 0;
                break;
        #endif
        #ifndef NO_SHA
            case WC_SHA:
                if (hashAlgorithm) *hashAlgorithm = CPA_CY_SYM_HASH_SHA1;
                ret = 0;
                break;
        #endif
        #ifdef WOLFSSL_SHA224
            case WC_SHA224:
                if (hashAlgorithm) *hashAlgorithm = CPA_CY_SYM_HASH_SHA224;
                ret = 0;
                break;
        #endif
        #ifndef NO_SHA256
            case WC_SHA256:
                if (hashAlgorithm) *hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
                ret = 0;
                break;
        #endif
        #ifdef WOLFSSL_SHA512
        #ifdef WOLFSSL_SHA384
            case WC_SHA384:
                if (hashAlgorithm) *hashAlgorithm = CPA_CY_SYM_HASH_SHA384;
                ret = 0;
                break;
        #endif
            case WC_SHA512:
                if (hashAlgorithm) *hashAlgorithm = CPA_CY_SYM_HASH_SHA512;
                ret = 0;
                break;
        #endif
        #if defined(WOLFSSL_SHA3) && defined(QAT_V2)
            case WC_SHA3_256:
                if (g_qatCapabilities.supSha3) {
                    if (hashAlgorithm)
                        *hashAlgorithm = CPA_CY_SYM_HASH_SHA3_256;
                    ret = 0;
                }
                break;
        #endif
        #ifdef HAVE_BLAKE2
            case BLAKE2B_ID:
        #endif
        #ifdef WOLFSSL_SHA3
            case WC_SHA3_224:
            case WC_SHA3_384:
            case WC_SHA3_512:
        #endif
            default:
                ret = NOT_COMPILED_IN;
        }
        return ret;
    }

    int IntelQaHmac(struct WC_ASYNC_DEV* dev,
        int macType, byte* keyRaw, word16 keyLen,
        byte* out, const byte* in, word32 sz)
    {
        int ret;
        CpaCySymHashAlgorithm hashAlgorithm;

        ret = IntelQaHmacGetType(macType, &hashAlgorithm);
        if (ret != 0)
            return ret;

        return IntelQaSymHash(dev, out, in, sz,
            CPA_CY_SYM_HASH_MODE_AUTH, hashAlgorithm, keyRaw, keyLen);
    }
#endif /* !NO_HMAC */

#endif /* QAT_ENABLE_HASH */



/* -------------------------------------------------------------------------- */
/* ECC Algo */
/* -------------------------------------------------------------------------- */

#ifdef HAVE_ECC

#ifdef HAVE_ECC_DHE

/* ECC Point Multiple Used for Public Key computation Key Gen */
static void IntelQaEccPointMulFree(WC_ASYNC_DEV* dev)
{
    CpaCyEcPointMultiplyOpData* opData = &dev->qat.op.ecc_mul.opData;
    CpaFlatBuffer* pXk = &dev->qat.op.ecc_mul.pXk;
    CpaFlatBuffer* pYk = &dev->qat.op.ecc_mul.pYk;

    if (pXk) {
        if (pXk->pData != NULL) {
            XFREE(pXk->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        }
        XMEMSET(pXk, 0, sizeof(CpaFlatBuffer));
    }
    if (pYk) {
        if (pYk->pData != NULL) {
            XFREE(pYk->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        }
        XMEMSET(pYk, 0, sizeof(CpaFlatBuffer));
    }

    if (opData) {
        if (opData->h.pData) {
            if (opData->h.pData != g_qatEcdhCofactor1) {
                XFREE(opData->h.pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            }
            opData->h.pData = NULL;
        }
        XMEMSET(opData, 0, sizeof(CpaCyEcPointMultiplyOpData));
    }

    /* clear temp pointers */
    dev->qat.op.ecc_mul.pubX = NULL;
    dev->qat.op.ecc_mul.pubY = NULL;
    dev->qat.op.ecc_mul.pubZ = NULL;
}

static void IntelQaEccPointMulCallback(void *pCallbackTag, CpaStatus status,
    void* pOpData, CpaBoolean multiplyStatus, CpaFlatBuffer* pXk,
    CpaFlatBuffer* pYk)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyEcPointMultiplyOpData* opData = (CpaCyEcPointMultiplyOpData*)pOpData;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaEccPointMulCallback: dev %p, status %d, multiplyStatus %d, "
           "xLen %d, yLen %d\n",
        dev, status, multiplyStatus, pXk->dataLenInBytes, pYk->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* check multiply status */
        if (multiplyStatus == 0) {
            /* fail */
            WOLFSSL_MSG("IntelQaEccPointMulCallback: multiply failed");
            ret = ECC_CURVE_OID_E;
        }
        else {
            ret = mp_read_unsigned_bin(dev->qat.op.ecc_mul.pubX,
                pXk->pData, pXk->dataLenInBytes);
            if (ret == 0)
                ret = mp_read_unsigned_bin(dev->qat.op.ecc_mul.pubY,
                    pYk->pData, pYk->dataLenInBytes);
            if (ret == 0)
                ret = mp_set(dev->qat.op.ecc_mul.pubZ, 1); /* always 1 */
        }
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaEccPointMul(WC_ASYNC_DEV* dev, WC_BIGINT* k,
    MATH_INT_T* pubX, MATH_INT_T* pubY, MATH_INT_T* pubZ,
    WC_BIGINT* xG, WC_BIGINT* yG, WC_BIGINT* a, WC_BIGINT* b, WC_BIGINT* q,
    word32 cofactor)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyEcPointMultiplyOpData* opData = NULL;
    CpaFlatBuffer* pXk = NULL;
    CpaFlatBuffer* pYk = NULL;
    CpaCyEcPointMultiplyCbFunc callback = IntelQaEccPointMulCallback;
    CpaBoolean* multiplyStatus;

    /* check arguments */
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaEccPointMul dev %p\n", dev);
#endif

    /* setup operation */
    opData = &dev->qat.op.ecc_mul.opData;
    pXk = &dev->qat.op.ecc_mul.pXk;
    pYk = &dev->qat.op.ecc_mul.pYk;
    multiplyStatus = &dev->qat.op.ecc_mul.multiplyStatus;

    /* init buffers */
    XMEMSET(opData, 0, sizeof(CpaCyEcPointMultiplyOpData));
    XMEMSET(pXk, 0, sizeof(CpaFlatBuffer));
    XMEMSET(pYk, 0, sizeof(CpaFlatBuffer));
    XMEMSET(multiplyStatus, 0, sizeof(CpaBoolean));

    /* setup operation data */
    opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    ret = IntelQaBigIntToFlatBuffer(k, &opData->k);
    ret += IntelQaBigIntToFlatBuffer(xG, &opData->xg);
    ret += IntelQaBigIntToFlatBuffer(yG, &opData->yg);
    if (a != NULL && a->buf == NULL) {
        /* The Koblitz curves can have a zero param "a" */
        ret += IntelQaAllocFlatBuffer(&opData->a, k->len, dev->heap);
        XMEMSET(opData->a.pData, 0, k->len);
    }
    else {
        ret += IntelQaBigIntToFlatBuffer(a, &opData->a);
    }
    ret += IntelQaBigIntToFlatBuffer(b, &opData->b);
    ret += IntelQaBigIntToFlatBuffer(q, &opData->q);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    /* setup cofactor */
    /* for this point multiply the cofactor should not be used,
     * so always pass 1 */
    /* if using default value 1 then use shared global */
    opData->h.dataLenInBytes = 4;
    opData->h.pData = g_qatEcdhCofactor1;
    (void)cofactor;

    ret =  IntelQaAllocFlatBuffer(pXk, q->len, dev->heap);
    ret += IntelQaAllocFlatBuffer(pYk, q->len, dev->heap);
    if (ret != 0) {
        ret = MEMORY_E; goto exit;
    }

    /* store info needed for output */
    dev->qat.op.ecc_mul.pubX = pubX;
    dev->qat.op.ecc_mul.pubY = pubY;
    dev->qat.op.ecc_mul.pubZ = pubZ;
    IntelQaOpInit(dev, IntelQaEccPointMulFree);

    /* perform point multiply */
    do {
        status = cpaCyEcPointMultiply(dev->qat.handle,
            callback,
            dev,
            opData,
            multiplyStatus,
            pXk,
            pYk);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_ECMUL_ASYNC,
        callback, &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyEcPointMultiply failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaEccPointMulFree(dev);

    return ret;
}

static void IntelQaEcdhFree(WC_ASYNC_DEV* dev)
{
    CpaCyEcdhPointMultiplyOpData* opData = &dev->qat.op.ecc_ecdh.opData;
    CpaFlatBuffer* resultX = &dev->qat.op.ecc_ecdh.pXk;
    CpaFlatBuffer* resultY = &dev->qat.op.ecc_ecdh.pYk;

    if (resultX) {
        if (resultX->pData) {
            XFREE(resultX->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            resultX->pData = NULL;
        }
        if (resultY->pData) {
            /* Don't free, since isn't used, persist global */
            /* XFREE(resultY->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA); */
            resultY->pData = NULL;
        }
        XMEMSET(resultX, 0, sizeof(CpaFlatBuffer));
        XMEMSET(resultY, 0, sizeof(CpaFlatBuffer));
    }

    if (opData) {
        if (opData->h.pData) {
            if (opData->h.pData != g_qatEcdhCofactor1) {
                XFREE(opData->h.pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            }
            opData->h.pData = NULL;
        }
        XMEMSET(opData, 0, sizeof(CpaCyEcdhPointMultiplyOpData));
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLenPtr = NULL;
}

static void IntelQaEcdhCallback(void *pCallbackTag, CpaStatus status,
    void* pOpData, CpaBoolean multiplyStatus, CpaFlatBuffer* pXk,
    CpaFlatBuffer* pYk)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyEcdhPointMultiplyOpData* opData =
        (CpaCyEcdhPointMultiplyOpData*)pOpData;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaEcdhCallback: dev %p, status %d, multiplyStatus %d, "
           "xLen %d, yLen %d\n",
        dev, status, multiplyStatus, pXk->dataLenInBytes, pYk->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* validate returned output */
        if (dev->qat.outLenPtr) {
            if (pXk->dataLenInBytes > *dev->qat.outLenPtr) {
                pXk->dataLenInBytes = *dev->qat.outLenPtr;
            }
            *dev->qat.outLenPtr = pXk->dataLenInBytes;
        }

        /* return data */
        if (dev->qat.out && dev->qat.out != pXk->pData) {
            XMEMCPY(dev->qat.out, pXk->pData, pXk->dataLenInBytes);
        }

        /* check multiply status */
        if (multiplyStatus == 0) {
            /* fail */
            WOLFSSL_MSG("IntelQaEcdhCallback: multiply failed");
            ret = ECC_CURVE_OID_E;
        }
        else {
            /* mark event result */
            ret = 0; /* success */
        }
    }
    (void)opData;
    (void)pYk;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaEcdh(WC_ASYNC_DEV* dev, WC_BIGINT* k, WC_BIGINT* xG,
    WC_BIGINT* yG, byte* out, word32* outlen,
    WC_BIGINT* a, WC_BIGINT* b, WC_BIGINT* q,
    word32 cofactor)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyEcdhPointMultiplyOpData* opData = NULL;
    CpaFlatBuffer* pXk = NULL;
    CpaFlatBuffer* pYk = NULL;
    CpaCyEcdhPointMultiplyCbFunc callback = IntelQaEcdhCallback;
    CpaBoolean* multiplyStatus;

    /* check arguments */
    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaEcdh dev %p\n", dev);
#endif

    /* setup operation */
    opData = &dev->qat.op.ecc_ecdh.opData;
    pXk = &dev->qat.op.ecc_ecdh.pXk;
    pYk = &dev->qat.op.ecc_ecdh.pYk;
    multiplyStatus = &dev->qat.op.ecc_ecdh.multiplyStatus;

    /* init buffers */
    XMEMSET(opData, 0, sizeof(CpaCyEcdhPointMultiplyOpData));
    XMEMSET(pXk, 0, sizeof(CpaFlatBuffer));
    XMEMSET(pYk, 0, sizeof(CpaFlatBuffer));
    XMEMSET(multiplyStatus, 0, sizeof(CpaBoolean));

    /* setup operation data */
    opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    ret = IntelQaBigIntToFlatBuffer(k, &opData->k);
    ret += IntelQaBigIntToFlatBuffer(xG, &opData->xg);
    ret += IntelQaBigIntToFlatBuffer(yG, &opData->yg);
    if (a != NULL && a->buf == NULL) {
        /* The Koblitz curves can have a zero param "a" */
        ret += IntelQaAllocFlatBuffer(&opData->a, k->len, dev->heap);
        XMEMSET(opData->a.pData, 0, k->len);
    }
    else {
        ret += IntelQaBigIntToFlatBuffer(a, &opData->a);
    }
    ret += IntelQaBigIntToFlatBuffer(b, &opData->b);
    ret += IntelQaBigIntToFlatBuffer(q, &opData->q);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    /* setup cofactor */
    /* for this point multiply the cofactor should not be used,
     * so always pass 1 */
    /* if using default value 1 then use shared global */
    opData->h.dataLenInBytes = 4;
    opData->h.pData = g_qatEcdhCofactor1;
    (void)cofactor;

    pXk->dataLenInBytes = q->len; /* bytes key size / 8 (aligned) */
    pXk->pData = XREALLOC(out, pXk->dataLenInBytes, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);
    pYk->dataLenInBytes = q->len;
    pYk->pData = g_qatEcdhY;

    /* store info needed for output */
    dev->qat.out = out;
    dev->qat.outLenPtr = outlen;
    IntelQaOpInit(dev, IntelQaEcdhFree);

    /* perform point multiply */
    do {
        status = cpaCyEcdhPointMultiply(dev->qat.handle,
            callback,
            dev,
            opData,
            multiplyStatus,
            pXk,
            pYk);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_ECDHE_ASYNC,
        callback, &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyEcdhPointMultiply failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaEcdhFree(dev);

    return ret;
}
#endif /* HAVE_ECC_DHE */


#ifdef HAVE_ECC_SIGN

static void IntelQaEcdsaSignFree(WC_ASYNC_DEV* dev)
{
    CpaCyEcdsaSignRSOpData* opData = &dev->qat.op.ecc_sign.opData;
    CpaFlatBuffer *pR = &dev->qat.op.ecc_sign.R;
    CpaFlatBuffer *pS = &dev->qat.op.ecc_sign.S;

    if (opData) {
        XMEMSET(opData, 0, sizeof(CpaCyEcdsaSignRSOpData));
    }

    if (pR) {
        if (pR->pData)
            XFREE(pR->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        XMEMSET(pR, 0, sizeof(CpaFlatBuffer));
    }
    if (pS) {
        if (pS->pData)
            XFREE(pS->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
        XMEMSET(pS, 0, sizeof(CpaFlatBuffer));
    }

    /* clear temp pointers */
    dev->qat.op.ecc_sign.pR = NULL;
    dev->qat.op.ecc_sign.pS = NULL;
}

static void IntelQaEcdsaSignCallback(void *pCallbackTag,
        CpaStatus status, void *pOpData, CpaBoolean signStatus,
        CpaFlatBuffer *pR, CpaFlatBuffer *pS)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyEcdsaSignRSOpData* opData = (CpaCyEcdsaSignRSOpData*)pOpData;
    int ret = ASYNC_OP_E;

    (void)signStatus;

#ifdef QAT_DEBUG
    printf("IntelQaEcdsaSignCallback: dev %p, status %d, signStatus %d, "
           "rLen %d, sLen %d\n",
        dev, status, signStatus, pR->dataLenInBytes, pS->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* check sign status */
        if (signStatus == 0) {
            /* fail */
            WOLFSSL_MSG("IntelQaEcdsaSignCallback: sign failed");
            ret = ECC_CURVE_OID_E;
        }
        else {
            /* success - populate result */
            ret = IntelQaFlatBufferToBigInt(pR, dev->qat.op.ecc_sign.pR);
            if (ret == 0) {
                ret = IntelQaFlatBufferToBigInt(pS, dev->qat.op.ecc_sign.pS);
            }
        }
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaEcdsaSign(WC_ASYNC_DEV* dev,
            WC_BIGINT* m, WC_BIGINT* d,
            WC_BIGINT* k,
            WC_BIGINT* r, WC_BIGINT* s,
            WC_BIGINT* a, WC_BIGINT* b,
            WC_BIGINT* q, WC_BIGINT* n,
            WC_BIGINT* xg, WC_BIGINT* yg)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyEcdsaSignRSOpData* opData = NULL;
    CpaCyEcdsaSignRSCbFunc callback = IntelQaEcdsaSignCallback;
    CpaBoolean* signStatus;
    CpaFlatBuffer* pR = NULL;
    CpaFlatBuffer* pS = NULL;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaEcdsaSign dev %p\n", dev);
#endif

    /* setup operation */
    opData = &dev->qat.op.ecc_sign.opData;
    pR = &dev->qat.op.ecc_sign.R;
    pS = &dev->qat.op.ecc_sign.S;
    signStatus = &dev->qat.op.ecc_sign.signStatus;

    /* init buffers */
    XMEMSET(opData, 0, sizeof(CpaCyEcdsaSignRSOpData));
    XMEMSET(pR, 0, sizeof(CpaFlatBuffer));
    XMEMSET(pS, 0, sizeof(CpaFlatBuffer));
    XMEMSET(signStatus, 0, sizeof(CpaBoolean));

    /* setup operation data */
    opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    ret =  IntelQaBigIntToFlatBuffer(m, &opData->m);
    ret += IntelQaBigIntToFlatBuffer(d, &opData->d);
    ret += IntelQaBigIntToFlatBuffer(k, &opData->k);
    ret += IntelQaBigIntToFlatBuffer(a, &opData->a);
    ret += IntelQaBigIntToFlatBuffer(b, &opData->b);
    ret += IntelQaBigIntToFlatBuffer(q, &opData->q);
    ret += IntelQaBigIntToFlatBuffer(n, &opData->n);
    ret += IntelQaBigIntToFlatBuffer(xg, &opData->xg);
    ret += IntelQaBigIntToFlatBuffer(yg, &opData->yg);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    pR->dataLenInBytes = n->len; /* bytes key size / 8 (aligned) */
    pS->dataLenInBytes = n->len;
    pR->pData = XREALLOC(r->buf, pR->dataLenInBytes, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);
    pS->pData = XREALLOC(s->buf, pS->dataLenInBytes, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);

    if (pR->pData == NULL || pS->pData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* store info needed for output */
    dev->qat.op.ecc_sign.pR = r;
    dev->qat.op.ecc_sign.pS = s;
    IntelQaOpInit(dev, IntelQaEcdsaSignFree);

    /* Perform ECDSA sign */
    do {
        status = cpaCyEcdsaSignRS(dev->qat.handle,
            callback,
            dev,
            opData,
            signStatus,
            pR,
            pS);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_ECDSA_ASYNC,
        callback, &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyEcdsaSignRS failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaEcdsaSignFree(dev);

    return ret;
}

#endif /* HAVE_ECC_SIGN */


#ifdef HAVE_ECC_VERIFY
static void IntelQaEcdsaVerifyFree(WC_ASYNC_DEV* dev)
{
    CpaCyEcdsaVerifyOpData* opData = &dev->qat.op.ecc_verify.opData;

    if (opData) {
        XMEMSET(opData, 0, sizeof(CpaCyEcdsaVerifyOpData));
    }

    /* clear temp pointers */
    dev->qat.op.ecc_verify.stat = NULL;
}

static void IntelQaEcdsaVerifyCallback(void *pCallbackTag,
        CpaStatus status, void *pOpData, CpaBoolean verifyStatus)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyEcdsaVerifyOpData* opData = (CpaCyEcdsaVerifyOpData*)pOpData;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaEcdsaVerifyCallback: dev %p, status %d, verifyStatus %d\n",
        dev, status, verifyStatus);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* populate result */
        *dev->qat.op.ecc_verify.stat = verifyStatus;

        /* check verify status */
        if (verifyStatus == 0) {
            /* fail */
            WOLFSSL_MSG("IntelQaEcdsaVerifyCallback: verify failed");
            ret = ECC_CURVE_OID_E;
        }
        else {
            /* mark event result */
            ret = 0; /* success */
        }
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaEcdsaVerify(WC_ASYNC_DEV* dev, WC_BIGINT* m,
    WC_BIGINT* xp, WC_BIGINT* yp,
    WC_BIGINT* r, WC_BIGINT* s,
    WC_BIGINT* a, WC_BIGINT* b,
    WC_BIGINT* q, WC_BIGINT* n,
    WC_BIGINT* xg, WC_BIGINT* yg, int* pVerifyStatus)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyEcdsaVerifyOpData* opData = NULL;
    CpaCyEcdsaVerifyCbFunc callback = IntelQaEcdsaVerifyCallback;
    CpaBoolean* verifyStatus;

    if (dev == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaEcdsaVerify dev %p\n", dev);
#endif

    /* setup operation */
    opData = &dev->qat.op.ecc_verify.opData;
    verifyStatus = &dev->qat.op.ecc_verify.verifyStatus;

    /* init buffers */
    XMEMSET(opData, 0, sizeof(CpaCyEcdsaVerifyOpData));
    XMEMSET(verifyStatus, 0, sizeof(CpaBoolean));

    /* setup operation data */
    opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    ret =  IntelQaBigIntToFlatBuffer(m,  &opData->m);
    ret += IntelQaBigIntToFlatBuffer(r,  &opData->r);
    ret += IntelQaBigIntToFlatBuffer(s,  &opData->s);
    ret += IntelQaBigIntToFlatBuffer(xp, &opData->xp);
    ret += IntelQaBigIntToFlatBuffer(yp, &opData->yp);
    ret += IntelQaBigIntToFlatBuffer(a,  &opData->a);
    ret += IntelQaBigIntToFlatBuffer(b,  &opData->b);
    ret += IntelQaBigIntToFlatBuffer(q,  &opData->q);
    ret += IntelQaBigIntToFlatBuffer(n,  &opData->n);
    ret += IntelQaBigIntToFlatBuffer(xg, &opData->xg);
    ret += IntelQaBigIntToFlatBuffer(yg, &opData->yg);
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    /* store info needed for output */
    dev->qat.op.ecc_verify.stat = pVerifyStatus;
    IntelQaOpInit(dev, IntelQaEcdsaVerifyFree);

    /* Perform ECDSA verify */
    do {
        status = cpaCyEcdsaVerify(dev->qat.handle,
            callback,
            dev,
            opData,
            verifyStatus);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_ECDSA_ASYNC,
        callback, &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyEcdsaVerify failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaEcdsaVerifyFree(dev);

    return ret;
}
#endif /* HAVE_ECC_VERIFY */

#endif /* HAVE_ECC */


#ifndef NO_DH

static void IntelQaDhKeyGenFree(WC_ASYNC_DEV* dev)
{
    CpaCyDhPhase1KeyGenOpData* opData = &dev->qat.op.dh_gen.opData;
    CpaFlatBuffer* pOut = &dev->qat.op.dh_gen.pOut;

    if (opData) {
        IntelQaFreeFlatBuffer(&opData->privateValueX, dev->heap);

        XMEMSET(opData, 0, sizeof(CpaCyDhPhase1KeyGenOpData));
    }

    if (pOut) {
        if (pOut->pData) {
            XFREE(pOut->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            pOut->pData = NULL;
        }
        XMEMSET(pOut, 0, sizeof(CpaFlatBuffer));
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLenPtr = NULL;
}

static void IntelQaDhKeyGenCallback(void *pCallbackTag, CpaStatus status,
        void *pOpData, CpaFlatBuffer *pOut)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyDhPhase1KeyGenOpData* opData = (CpaCyDhPhase1KeyGenOpData*)pOpData;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaDhKeyGenCallback: dev %p, status %d, len %d\n",
        dev, status, pOut->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* validate returned output */
        if (dev->qat.outLenPtr) {
            if (pOut->dataLenInBytes > *dev->qat.outLenPtr) {
                pOut->dataLenInBytes = *dev->qat.outLenPtr;
            }
            *dev->qat.outLenPtr = pOut->dataLenInBytes;
        }

        /* return data */
        if (dev->qat.out && dev->qat.out != pOut->pData) {
            XMEMCPY(dev->qat.out, pOut->pData, pOut->dataLenInBytes);
        }

        /* mark event result */
        ret = 0; /* success */
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaDhKeyGen(WC_ASYNC_DEV* dev, WC_BIGINT* p, WC_BIGINT* g,
    WC_BIGINT* x, byte* pub, word32* pubSz)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyDhPhase1KeyGenOpData* opData = NULL;
    CpaCyGenFlatBufCbFunc callback = IntelQaDhKeyGenCallback;
    CpaFlatBuffer* pOut = NULL;

    if (dev == NULL || p == NULL || p->buf == NULL || g == NULL || x == NULL ||
                                  pub == NULL || pubSz == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaDhKeyGen dev %p\n", dev);
#endif

    /* setup operation */
    opData = &dev->qat.op.dh_gen.opData;
    pOut = &dev->qat.op.dh_gen.pOut;

    /* init buffers */
    XMEMSET(opData, 0, sizeof(CpaCyDhPhase1KeyGenOpData));
    XMEMSET(pOut, 0, sizeof(CpaFlatBuffer));

    /* setup operation data */
    ret =  IntelQaBigIntToFlatBuffer(p, &opData->primeP);
    ret += IntelQaBigIntToFlatBuffer(g, &opData->baseG);
    /* transfer control of big int buffer to opData structure */
    ret += IntelQaBigIntToFlatBuffer(x, &opData->privateValueX);
    /* don't let caller free x, do it in IntelQaDhKeyGenFree */
    x->buf = NULL;
    x->len = 0;
    if (ret != 0) {
        ret = BAD_FUNC_ARG; goto exit;
    }
    pOut->dataLenInBytes = p->len;
    pOut->pData = XREALLOC(pub, p->len, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    if (pOut->pData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* store info needed for output */
    *pubSz = p->len;
    dev->qat.out = pub;
    dev->qat.outLenPtr = pubSz;
    IntelQaOpInit(dev, IntelQaDhKeyGenFree);

    /* Perform DhKeyGen */
    do {
        status = cpaCyDhKeyGenPhase1(dev->qat.handle,
            callback,
            dev,
            opData,
            pOut);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_DH_ASYNC, callback,
        &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyDhKeyGenPhase1 failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaDhKeyGenFree(dev);

    return ret;
}

static void IntelQaDhAgreeFree(WC_ASYNC_DEV* dev)
{
    CpaCyDhPhase2SecretKeyGenOpData* opData = &dev->qat.op.dh_agree.opData;
    CpaFlatBuffer* pOut = &dev->qat.op.dh_agree.pOut;

    if (pOut) {
        if (pOut->pData) {
            XFREE(pOut->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            pOut->pData = NULL;
        }
        XMEMSET(pOut, 0, sizeof(CpaFlatBuffer));
    }
    if (opData) {
        if (opData->remoteOctetStringPV.pData) {
            XFREE(opData->remoteOctetStringPV.pData, dev->heap,
                DYNAMIC_TYPE_ASYNC_NUMA);
            opData->remoteOctetStringPV.pData = NULL;
        }
        if (opData->privateValueX.pData) {
            XFREE(opData->privateValueX.pData, dev->heap,
                DYNAMIC_TYPE_ASYNC_NUMA);
            opData->privateValueX.pData = NULL;
        }
        XMEMSET(opData, 0, sizeof(CpaCyDhPhase2SecretKeyGenOpData));
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
    dev->qat.outLenPtr = NULL;
}

static void IntelQaDhAgreeCallback(void *pCallbackTag, CpaStatus status,
        void *pOpData, CpaFlatBuffer *pOut)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyDhPhase2SecretKeyGenOpData* opData =
        (CpaCyDhPhase2SecretKeyGenOpData*)pOpData;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaDhAgreeCallback: dev %p, status %d, len %d\n",
        dev, status, pOut->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        word32 idxTrim = 0;
        byte* out = (byte*)pOut->pData;

        /* check output size */
        if (dev->qat.outLenPtr) {
            if (pOut->dataLenInBytes > *dev->qat.outLenPtr) {
                pOut->dataLenInBytes = *dev->qat.outLenPtr;
            }
        }

        /* count leading zeros */
        while (out[idxTrim] == 0 && idxTrim < pOut->dataLenInBytes) {
            idxTrim++;
        }
        pOut->dataLenInBytes -= idxTrim;

        /* return data and trim leading zeros */
        if (dev->qat.out && (dev->qat.out != pOut->pData || idxTrim > 0)) {
            XMEMMOVE(dev->qat.out, &out[idxTrim], pOut->dataLenInBytes);
        }

        /* return final length */
        if (dev->qat.outLenPtr) {
            *dev->qat.outLenPtr = pOut->dataLenInBytes;
        }

        /* mark event result */
        ret = 0; /* success */
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaDhAgree(WC_ASYNC_DEV* dev, WC_BIGINT* p,
    byte* agree, word32* agreeSz, const byte* priv, word32 privSz,
    const byte* otherPub, word32 pubSz)
{
    int ret, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyDhPhase2SecretKeyGenOpData* opData = NULL;
    CpaCyGenFlatBufCbFunc callback = IntelQaDhAgreeCallback;
    CpaFlatBuffer* pOut = NULL;

    if (dev == NULL || agree == NULL || agreeSz == NULL ||
            priv == NULL || privSz == 0 || otherPub == NULL || pubSz == 0) {
        return BAD_FUNC_ARG;
    }

#ifdef QAT_DEBUG
    printf("IntelQaDhAgree dev %p, agreeSz %d\n", dev, *agreeSz);
#endif

    /* setup operation */
    opData = &dev->qat.op.dh_agree.opData;
    pOut = &dev->qat.op.dh_agree.pOut;

    /* init buffers */
    XMEMSET(opData, 0, sizeof(CpaCyDhPhase2SecretKeyGenOpData));
    XMEMSET(pOut, 0, sizeof(CpaFlatBuffer));

    /* setup operation data */
    ret = IntelQaBigIntToFlatBuffer(p, &opData->primeP);
    if (ret != 0) {
        goto exit;
    }

    opData->remoteOctetStringPV.dataLenInBytes = pubSz;
    opData->remoteOctetStringPV.pData = XREALLOC((byte*)otherPub, pubSz,
        dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
    opData->privateValueX.dataLenInBytes = privSz;
    opData->privateValueX.pData = XREALLOC((byte*)priv, privSz, dev->heap,
        DYNAMIC_TYPE_ASYNC_NUMA);
    pOut->dataLenInBytes = p->len;
    pOut->pData = XREALLOC(agree, p->len, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);

    if (opData->remoteOctetStringPV.pData == NULL ||
        opData->privateValueX.pData == NULL || pOut->pData == NULL) {
        ret = MEMORY_E; goto exit;
    }

    /* store info needed for output */
    dev->qat.out = agree;
    dev->qat.outLenPtr = agreeSz;
    IntelQaOpInit(dev, IntelQaDhAgreeFree);

    /* Perform DhKeyGen */
    do {
        status = cpaCyDhKeyGenPhase2Secret(dev->qat.handle,
            callback,
            dev,
            opData,
            pOut);
    } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_DH_ASYNC, callback,
        &retryCount));

    if (ret == WC_PENDING_E)
        return ret;

exit:

    if (ret != 0) {
        printf("cpaCyDhKeyGenPhase2Secret failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaDhAgreeFree(dev);

    return ret;
}

#endif /* !NO_DH */


#if defined(QAT_ENABLE_RNG)
/* -------------------------------------------------------------------------- */
/* Random NRBG/DRBG */
/* -------------------------------------------------------------------------- */
int IntelQaNrbg(CpaFlatBuffer* pBuffer, Cpa32U length)
{
    CpaStatus status;
    CpaCyNrbgOpData opData;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (pBuffer == NULL || length == 0) {
        return BAD_FUNC_ARG;
    }

    if (pBuffer->dataLenInBytes < length) {
        return BAD_FUNC_ARG;
    }

    /* For now use the first crypto instance - assumed to be started already */
    status = cpaCyGetInstances(1, &instanceHandle);
    if (instanceHandle == NULL || status != CPA_STATUS_SUCCESS) {
        return ASYNC_INIT_E;
    }

    /* init buffers */
    XMEMSET(&opData, 0, sizeof(CpaCyNrbgOpData));
    opData.lengthInBytes = length;

    /* Perform NRBG generation */
    status = cpaCyNrbgGetEntropy(instanceHandle, NULL, NULL, &opData, pBuffer);
    if (status != CPA_STATUS_SUCCESS) {
        printf("cpaCyNrbgGetEntropy failed! status %d\n", status);
    }

    return status;
}

static CpaStatus IntelQaGetEntropyInputFunc(
        IcpSalDrbgGetEntropyInputCbFunc pCb,
        void* pCallbackTag,
        icp_sal_drbg_get_entropy_op_data_t *pOpData,
        CpaFlatBuffer *pBuffer,
        Cpa32U *pLengthReturned)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    *pLengthReturned = pOpData->maxLength;

    status = IntelQaNrbg(pBuffer, pOpData->maxLength);
    if (status != CPA_STATUS_SUCCESS) {
        return CPA_STATUS_FAIL;
    }

    if (pCb != NULL) {
        pCb(pCallbackTag, CPA_STATUS_SUCCESS, pOpData,
                                    pOpData->maxLength, pBuffer);
    }

    return CPA_STATUS_SUCCESS;
}

static CpaStatus IntelQaGetNonceFunc(
        icp_sal_drbg_get_entropy_op_data_t *pOpData,
        CpaFlatBuffer *pBuffer,
        Cpa32U *pLengthReturned)
{

    CpaStatus status = CPA_STATUS_SUCCESS;

    status = IntelQaNrbg(pBuffer, pOpData->maxLength);
    if (status != CPA_STATUS_SUCCESS) {
        return CPA_STATUS_FAIL;
    }
    *pLengthReturned = pOpData->maxLength;

    return CPA_STATUS_SUCCESS;
}

static CpaBoolean IntelQaNotDFRequired(void)
{
    return CPA_FALSE;
}

static int IntelQaDrbgClose(WC_ASYNC_DEV* dev)
{
    CpaStatus status;

    if (dev == NULL)
        return BAD_FUNC_ARG;

#ifdef QAT_DEBUG
    printf("cpaCyDrbgRemoveSession dev %p\n", dev);
#endif

    if (dev->qat.op.drbg.handle) {
        CpaCyDrbgSessionHandle handle = dev->qat.op.drbg.handle;
        dev->qat.op.drbg.handle = NULL;

        status = cpaCyDrbgRemoveSession(dev->qat.handle, handle);
        if (status != CPA_STATUS_SUCCESS) {
            printf("cpaCyDrbgRemoveSession failed! status %d\n", status);
        }

        XFREE(handle, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA64);
    }

    return 0;
}

static void IntelQaDrbgFree(WC_ASYNC_DEV* dev)
{
    CpaCyDrbgGenOpData* opData = &dev->qat.op.drbg.opData;
    CpaFlatBuffer* pOut = &dev->qat.op.drbg.pOut;

    if (pOut) {
        if (pOut->pData) {
            XFREE(pOut->pData, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA);
            pOut->pData = NULL;
        }
        XMEMSET(pOut, 0, sizeof(CpaFlatBuffer));
    }

    if (opData) {
        XMEMSET(opData, 0, sizeof(CpaCyDrbgGenOpData));
    }

    /* clear temp pointers */
    dev->qat.out = NULL;
}

static void IntelQaDrbgCallback(void *pCallbackTag, CpaStatus status,
    void *pOpdata, CpaFlatBuffer *pOut)
{
    WC_ASYNC_DEV* dev = (WC_ASYNC_DEV*)pCallbackTag;
    CpaCyDrbgGenOpData* opData = (CpaCyDrbgGenOpData*)pOpdata;
    int ret = ASYNC_OP_E;

#ifdef QAT_DEBUG
    printf("IntelQaDrbgCallback: dev %p, status %d, len %d\n",
        dev, status, pOut->dataLenInBytes);
#endif

    if (status == CPA_STATUS_SUCCESS) {
        /* return data */
        if (dev->qat.out && dev->qat.out != pOut->pData) {
            XMEMCPY(dev->qat.out, pOut->pData, pOut->dataLenInBytes);
        }

        /* mark event result */
        ret = 0; /* success */
    }
    (void)opData;

    /* set return code to mark complete */
    dev->qat.ret = ret;
}

int IntelQaDrbg(WC_ASYNC_DEV* dev, byte* rngBuf, word32 rngSz)
{
    int ret = 0, retryCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyDrbgGenOpData* opData = NULL;
    CpaCyGenFlatBufCbFunc callback = IntelQaDrbgCallback;
    CpaFlatBuffer* pOut = NULL;
    word32 idx = 0, gen = 0;

    if (dev == NULL || rngBuf == NULL) {
        return BAD_FUNC_ARG;
    }

    /* This function can be called with rngSz == 0 */
    if (rngSz == 0) {
        return 0; /* no data to get */
    }

#ifdef QAT_DEBUG
    printf("IntelQaDrbg: dev %p, buf %p, sz %d\n", dev, rngBuf, rngSz);
#endif

    /* setup operation */
    opData = &dev->qat.op.drbg.opData;
    pOut = &dev->qat.op.drbg.pOut;

    /* init buffers */
    XMEMSET(opData, 0, sizeof(CpaCyDrbgGenOpData));
    XMEMSET(pOut, 0, sizeof(CpaFlatBuffer));

    if (dev->qat.op.drbg.handle == NULL) {
        CpaCyDrbgSessionSetupData setup;
        Cpa32U seedLen = 0;
        Cpa32U handleSize;

    #ifdef QAT_DEBUG
        printf("cpaCyDrbgInitSession dev %p\n", dev);
    #endif

        /* register required DRBG callback functions */
        icp_sal_drbgIsDFReqFuncRegister(IntelQaNotDFRequired);
        icp_sal_drbgGetEntropyInputFuncRegister(IntelQaGetEntropyInputFunc);
        icp_sal_drbgGetNonceFuncRegister(IntelQaGetNonceFunc);

        setup.predictionResistanceRequired = CPA_FALSE;
        setup.secStrength = CPA_CY_RBG_SEC_STRENGTH_128;
        setup.personalizationString.dataLenInBytes = 0;
        setup.personalizationString.pData = NULL;

        status = cpaCyDrbgSessionGetSize(dev->qat.handle, &setup, &handleSize);
        if (status != CPA_STATUS_SUCCESS) {
            ret = ASYNC_INIT_E; goto exit;
        }

        dev->qat.op.drbg.handle = (CpaCyDrbgSessionHandle)XMALLOC(
            handleSize, dev->heap, DYNAMIC_TYPE_ASYNC_NUMA64);
        if (dev->qat.op.drbg.handle == NULL) {
            ret = MEMORY_E; goto exit;
        }

        status = cpaCyDrbgInitSession(dev->qat.handle,
                    callback,    /* callback function for generate */
                    NULL,        /* callback function for reseed */
                    &setup,      /* session setup data */
                    dev->qat.op.drbg.handle,
                    &seedLen);
    }

    /* chunk into LAC_DRBG_MAX_NUM_OF_BYTES (0xFFFF) */
    while (ret == 0 && idx < rngSz) {
        /* setup operation data */
        gen = rngSz - gen;
        if (gen > 0xFFFF)
            gen = 0xFFFF;

        pOut->dataLenInBytes = gen;
        if (idx == 0 && pOut->pData == NULL) {
            pOut->pData = XREALLOC(rngBuf, gen, dev->heap,
                DYNAMIC_TYPE_ASYNC_NUMA);
            if (pOut->pData == NULL) {
                ret = MEMORY_E; goto exit;
            }
        }
        else {
            XMEMCPY(pOut->pData, &rngBuf[idx], gen);
        }

        opData->sessionHandle = dev->qat.op.drbg.handle;
        opData->lengthInBytes = gen;
        opData->secStrength = CPA_CY_RBG_SEC_STRENGTH_128;
        opData->predictionResistanceRequired = CPA_FALSE;
        opData->additionalInput.dataLenInBytes = 0;
        opData->additionalInput.pData = NULL;

        /* store info needed for output */
        dev->qat.out = &rngBuf[idx];
        IntelQaOpInit(dev, IntelQaDrbgFree);

        /* Perform DRBG generation */
        do {
            status = cpaCyDrbgGen(dev->qat.handle,
                dev,
                opData,
                pOut);
        } while (IntelQaHandleCpaStatus(dev, status, &ret, QAT_DRBG_ASYNC,
            callback, &retryCount));

        idx += gen;
    };

exit:

    if (ret != 0) {
        printf("cpaCyDrbgGen failed! dev %p, status %d, ret %d\n",
            dev, status, ret);
    }

    /* handle cleanup */
    IntelQaDrbgFree(dev);

    return ret;
}
#endif /* QAT_ENABLE_RNG */

#ifdef QAT_DEMO_MAIN

 /* RSA */
static const byte rsa_in[256] = {
    0x7e, 0xf5, 0x69, 0x11, 0x6f, 0x67, 0x81, 0x71, 0xa2, 0x3e, 0xe7, 0x0e,
    0xad, 0xb9, 0x5f, 0x20, 0xc8, 0x2d, 0x8b, 0xd3, 0xb1, 0x65, 0x27, 0x34,
    0x7a, 0x10, 0x2e, 0xf4, 0xe9, 0x6a, 0x69, 0x93, 0xc0, 0x3e, 0xad, 0xbe,
    0x2e, 0x35, 0x34, 0xeb, 0x64, 0x45, 0x09, 0xf4, 0x07, 0x33, 0x6f, 0xac,
    0x2f, 0xc8, 0x59, 0xca, 0x72, 0x99, 0x0b, 0x99, 0xb1, 0xf3, 0xda, 0x42,
    0xdb, 0x7b, 0xed, 0x4c, 0x22, 0x48, 0x08, 0x8a, 0x30, 0xd7, 0xdc, 0x99,
    0x0b, 0xb9, 0x1a, 0xc5, 0x40, 0xe5, 0x7d, 0xe9, 0xbf, 0x0a, 0x05, 0xea,
    0x07, 0x24, 0x7a, 0x1f, 0x54, 0xbf, 0x77, 0x71, 0x09, 0xec, 0x6d, 0xdf,
    0x87, 0xc2, 0x11, 0xda, 0x8c, 0x66, 0x46, 0x1d, 0x5a, 0x45, 0x23, 0x35,
    0x96, 0x48, 0xa7, 0x0e, 0x03, 0xe1, 0x02, 0x43, 0x76, 0x56, 0xae, 0xc3,
    0x6e, 0x61, 0x73, 0xba, 0x48, 0x6e, 0x8a, 0x58, 0x60, 0xdd, 0x0a, 0x81,
    0x46, 0xe4, 0xb4, 0x03, 0xf1, 0x63, 0xf4, 0xc1, 0xad, 0xd5, 0x4a, 0xda,
    0x25, 0xd9, 0x9d, 0x56, 0x1f, 0xb4, 0x7b, 0x2b, 0xdd, 0x90, 0x4e, 0xfd,
    0xa1, 0xd4, 0x5b, 0xd9, 0x17, 0x1a, 0x68, 0xd0, 0x3c, 0x95, 0x94, 0x64,
    0x6a, 0x4a, 0xad, 0x39, 0xe5, 0x5f, 0xd1, 0xe2, 0xb1, 0x1b, 0xad, 0x1d,
    0x2a, 0xc2, 0x12, 0xed, 0x47, 0xa1, 0xac, 0x0f, 0x3e, 0x3b, 0x44, 0x2f,
    0x61, 0xa5, 0xab, 0xa1, 0x03, 0xe9, 0x40, 0x62, 0x82, 0xc6, 0x33, 0xcf,
    0x12, 0xeb, 0x76, 0x73, 0x13, 0x61, 0xe5, 0x3b, 0xf9, 0x38, 0x24, 0xc0,
    0x24, 0xc7, 0x88, 0x2b, 0x4a, 0x3c, 0x42, 0x26, 0xd0, 0xe6, 0x4d, 0xc8,
    0x41, 0x58, 0x94, 0x77, 0x91, 0x1d, 0xfa, 0xbb, 0x9f, 0xa8, 0x43, 0xe0,
    0x33, 0x46, 0x7e, 0x8e, 0xcf, 0xfc, 0x3e, 0xd4, 0x72, 0x7b, 0xf9, 0xee,
    0xca, 0xfd, 0x96, 0xd4,
};
static const byte rsa_d[256] = {
    0xa2, 0xe6, 0xd8, 0x5f, 0x10, 0x71, 0x64, 0x08, 0x9e, 0x2e, 0x6d, 0xd1,
    0x6d, 0x1e, 0x85, 0xd2, 0x0a, 0xb1, 0x8c, 0x47, 0xce, 0x2c, 0x51, 0x6a,
    0xa0, 0x12, 0x9e, 0x53, 0xde, 0x91, 0x4c, 0x1d, 0x6d, 0xea, 0x59, 0x7b,
    0xf2, 0x77, 0xaa, 0xd9, 0xc6, 0xd9, 0x8a, 0xab, 0xd8, 0xe1, 0x16, 0xe4,
    0x63, 0x26, 0xff, 0xb5, 0x6c, 0x13, 0x59, 0xb8, 0xe3, 0xa5, 0xc8, 0x72,
    0x17, 0x2e, 0x0c, 0x9f, 0x6f, 0xe5, 0x59, 0x3f, 0x76, 0x6f, 0x49, 0xb1,
    0x11, 0xc2, 0x5a, 0x2e, 0x16, 0x29, 0x0d, 0xde, 0xb7, 0x8e, 0xdc, 0x40,
    0xd5, 0xa2, 0xee, 0xe0, 0x1e, 0xa1, 0xf4, 0xbe, 0x97, 0xdb, 0x86, 0x63,
    0x96, 0x14, 0xcd, 0x98, 0x09, 0x60, 0x2d, 0x30, 0x76, 0x9c, 0x3c, 0xcd,
    0xe6, 0x88, 0xee, 0x47, 0x92, 0x79, 0x0b, 0x5a, 0x00, 0xe2, 0x5e, 0x5f,
    0x11, 0x7c, 0x7d, 0xf9, 0x08, 0xb7, 0x20, 0x06, 0x89, 0x2a, 0x5d, 0xfd,
    0x00, 0xab, 0x22, 0xe1, 0xf0, 0xb3, 0xbc, 0x24, 0xa9, 0x5e, 0x26, 0x0e,
    0x1f, 0x00, 0x2d, 0xfe, 0x21, 0x9a, 0x53, 0x5b, 0x6d, 0xd3, 0x2b, 0xab,
    0x94, 0x82, 0x68, 0x43, 0x36, 0xd8, 0xf6, 0x2f, 0xc6, 0x22, 0xfc, 0xb5,
    0x41, 0x5d, 0x0d, 0x33, 0x60, 0xea, 0xa4, 0x7d, 0x7e, 0xe8, 0x4b, 0x55,
    0x91, 0x56, 0xd3, 0x5c, 0x57, 0x8f, 0x1f, 0x94, 0x17, 0x2f, 0xaa, 0xde,
    0xe9, 0x9e, 0xa8, 0xf4, 0xcf, 0x8a, 0x4c, 0x8e, 0xa0, 0xe4, 0x56, 0x73,
    0xb2, 0xcf, 0x4f, 0x86, 0xc5, 0x69, 0x3c, 0xf3, 0x24, 0x20, 0x8b, 0x5c,
    0x96, 0x0c, 0xfa, 0x6b, 0x12, 0x3b, 0x9a, 0x67, 0xc1, 0xdf, 0xc6, 0x96,
    0xb2, 0xa5, 0xd5, 0x92, 0x0d, 0x9b, 0x09, 0x42, 0x68, 0x24, 0x10, 0x45,
    0xd4, 0x50, 0xe4, 0x17, 0x39, 0x48, 0xd0, 0x35, 0x8b, 0x94, 0x6d, 0x11,
    0xde, 0x8f, 0xca, 0x59,
};
static const byte rsa_n[256] = {
    0xc3, 0x03, 0xd1, 0x2b, 0xfe, 0x39, 0xa4, 0x32, 0x45, 0x3b, 0x53, 0xc8,
    0x84, 0x2b, 0x2a, 0x7c, 0x74, 0x9a, 0xbd, 0xaa, 0x2a, 0x52, 0x07, 0x47,
    0xd6, 0xa6, 0x36, 0xb2, 0x07, 0x32, 0x8e, 0xd0, 0xba, 0x69, 0x7b, 0xc6,
    0xc3, 0x44, 0x9e, 0xd4, 0x81, 0x48, 0xfd, 0x2d, 0x68, 0xa2, 0x8b, 0x67,
    0xbb, 0xa1, 0x75, 0xc8, 0x36, 0x2c, 0x4a, 0xd2, 0x1b, 0xf7, 0x8b, 0xba,
    0xcf, 0x0d, 0xf9, 0xef, 0xec, 0xf1, 0x81, 0x1e, 0x7b, 0x9b, 0x03, 0x47,
    0x9a, 0xbf, 0x65, 0xcc, 0x7f, 0x65, 0x24, 0x69, 0xa6, 0xe8, 0x14, 0x89,
    0x5b, 0xe4, 0x34, 0xf7, 0xc5, 0xb0, 0x14, 0x93, 0xf5, 0x67, 0x7b, 0x3a,
    0x7a, 0x78, 0xe1, 0x01, 0x56, 0x56, 0x91, 0xa6, 0x13, 0x42, 0x8d, 0xd2,
    0x3c, 0x40, 0x9c, 0x4c, 0xef, 0xd1, 0x86, 0xdf, 0x37, 0x51, 0x1b, 0x0c,
    0xa1, 0x3b, 0xf5, 0xf1, 0xa3, 0x4a, 0x35, 0xe4, 0xe1, 0xce, 0x96, 0xdf,
    0x1b, 0x7e, 0xbf, 0x4e, 0x97, 0xd0, 0x10, 0xe8, 0xa8, 0x08, 0x30, 0x81,
    0xaf, 0x20, 0x0b, 0x43, 0x14, 0xc5, 0x74, 0x67, 0xb4, 0x32, 0x82, 0x6f,
    0x8d, 0x86, 0xc2, 0x88, 0x40, 0x99, 0x36, 0x83, 0xba, 0x1e, 0x40, 0x72,
    0x22, 0x17, 0xd7, 0x52, 0x65, 0x24, 0x73, 0xb0, 0xce, 0xef, 0x19, 0xcd,
    0xae, 0xff, 0x78, 0x6c, 0x7b, 0xc0, 0x12, 0x03, 0xd4, 0x4e, 0x72, 0x0d,
    0x50, 0x6d, 0x3b, 0xa3, 0x3b, 0xa3, 0x99, 0x5e, 0x9d, 0xc8, 0xd9, 0x0c,
    0x85, 0xb3, 0xd9, 0x8a, 0xd9, 0x54, 0x26, 0xdb, 0x6d, 0xfa, 0xac, 0xbb,
    0xff, 0x25, 0x4c, 0xc4, 0xd1, 0x79, 0xf4, 0x71, 0xd3, 0x86, 0x40, 0x18,
    0x13, 0xb0, 0x63, 0xb5, 0x72, 0x4e, 0x30, 0xc4, 0x97, 0x84, 0x86, 0x2d,
    0x56, 0x2f, 0xd7, 0x15, 0xf7, 0x7f, 0xc0, 0xae, 0xf5, 0xfc, 0x5b, 0xe5,
    0xfb, 0xa1, 0xba, 0xd3,
};


/* AES GCM */
static const byte aesgcm_k[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22
};

static const byte aesgcm_iv[] = {
    0xca, 0xfe, 0xca, 0xfe, 0xca, 0xfe, 0xca, 0xfe,
    0xca, 0xfe, 0xca, 0xfe
};

static const byte aesgcm_a[] = {
    0xde, 0xad, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad,
    0xde, 0xad, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad,
    0xde, 0xad, 0xde, 0xad
};

static const byte aesgcm_p[] = {
    0x79, 0x84, 0x86, 0x44, 0x68, 0x45, 0x15, 0x61,
    0x86, 0x54, 0x66, 0x56, 0x54, 0x54, 0x31, 0x54,
    0x64, 0x64, 0x68, 0x45, 0x15, 0x15, 0x61, 0x61,
    0x51, 0x51, 0x51, 0x51, 0x51, 0x56, 0x14, 0x11,
    0x72, 0x13, 0x51, 0x82, 0x84, 0x56, 0x74, 0x53,
    0x45, 0x34, 0x65, 0x15, 0x46, 0x14, 0x67, 0x55,
    0x16, 0x14, 0x67, 0x54, 0x65, 0x47, 0x14, 0x67,
    0x46, 0x74, 0x65, 0x46
};

static const byte aesgcm_c[] = {
    0x59, 0x85, 0x02, 0x97, 0xE0, 0x4D, 0xFC, 0x5C,
    0x03, 0xCC, 0x83, 0x64, 0xCE, 0x28, 0x0B, 0x95,
    0x78, 0xEC, 0x93, 0x40, 0xA1, 0x8D, 0x21, 0xC5,
    0x48, 0x6A, 0x39, 0xBA, 0x4F, 0x4B, 0x8C, 0x95,
    0x6F, 0x8C, 0xF6, 0x9C, 0xD0, 0xA5, 0x8D, 0x67,
    0xA1, 0x32, 0x11, 0xE7, 0x2E, 0xF6, 0x63, 0xAF,
    0xDE, 0xD4, 0x7D, 0xEC, 0x15, 0x01, 0x58, 0xCB,
    0xE3, 0x7B, 0xC6, 0x94,
};

static byte aesgcm_t[] = {
    0x5D, 0x10, 0x3F, 0xC7, 0x22, 0xC7, 0x21, 0x29
};


/* ecc curve */
static byte ecc_a[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
};
static byte ecc_b[] = {
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
    0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
    0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
};
static byte ecc_q[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
/* private key */
static byte ecc_k[] = {
    0x52, 0x2f, 0x27, 0xe3, 0x44, 0x3c, 0xa7, 0x92,
    0x9b, 0xdc, 0xe3, 0x00, 0x8a, 0x47, 0x0f, 0x28,
    0x5c, 0x0e, 0x2d, 0x87, 0xfd, 0x89, 0x56, 0xdd,
    0x83, 0x94, 0x6c, 0x48, 0x6c, 0x15, 0x59, 0xb7,
    0xf1, 0xc8, 0x13, 0x27, 0xe5, 0x80, 0xbd, 0x9c
};
/* public key */
static byte ecc_xg[] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};
static byte ecc_yg[] = {
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};


/* DH */
static byte dh_priv1[] = {
    0xbd, 0x64, 0xf6, 0xd2, 0xe9, 0xca, 0xd0, 0xda,
    0x41, 0x48, 0x95, 0x5d, 0xd3, 0xa7, 0x36, 0x47,
    0xb6, 0x28, 0xdf, 0x05, 0x7b, 0x9c, 0xcd, 0x34,
    0x79, 0x09, 0x7a, 0x06, 0x43,
};

static byte dh_pub1[] = {
    0xaa, 0x43, 0x2e, 0xfd, 0xc6, 0xbe, 0x40, 0xdc, 0xac, 0x64, 0xf2, 0x65,
    0x91, 0xae, 0x88, 0xa0, 0x7b, 0x71, 0x3d, 0x9f, 0xa7, 0x00, 0xbe, 0x82,
    0xbb, 0xb5, 0x27, 0x2a, 0x58, 0xce, 0xb5, 0xf9, 0x18, 0x6e, 0x0b, 0xaa,
    0x75, 0x91, 0x59, 0x30, 0x2b, 0x1e, 0xf3, 0x26, 0xa5, 0x6a, 0x22, 0x91,
    0x65, 0xad, 0x5f, 0xef, 0x53, 0x57, 0x76, 0x53, 0xe8, 0xc2, 0x93, 0x9d,
    0x21, 0x7e, 0x91, 0x27, 0x79, 0xe4, 0xa5, 0xa1, 0x8b, 0x20, 0x52, 0xa2,
    0xd6, 0x22, 0xef, 0x15, 0x2c, 0xa7, 0xf3, 0xfc, 0xce, 0xc7, 0x1b, 0x90,
    0xaa, 0x9b, 0xb3, 0x83, 0xff, 0x21, 0xa0, 0x20, 0xc7, 0x21, 0x93, 0xbd,
    0x1a, 0xf3, 0xae, 0xd9, 0x16, 0x02, 0xf0, 0x62, 0x07, 0x68, 0xea, 0x1a,
    0xe7, 0xa6, 0xb9, 0xa6, 0x3b, 0x9a, 0x23, 0x4c, 0x21, 0xec, 0xa1, 0xe0,
    0x8f, 0x16, 0x2a, 0x99, 0x36, 0xbf, 0x57, 0x89, 0xf0, 0x3d, 0x84, 0xca,
    0x99, 0xe8, 0xea, 0x79, 0x24, 0xc0, 0x93, 0x96, 0x70, 0x9a, 0xbb, 0x16,
    0xa3, 0xe9, 0x06, 0x59, 0xb4, 0x6c, 0xe7, 0x48, 0x59, 0xde, 0x75, 0x83,
    0xbb, 0xc2, 0xa7, 0xd7, 0x84, 0x1d, 0xf4, 0x27, 0xf1, 0x72, 0x04, 0x64,
    0x01, 0x6b, 0x7b, 0xac, 0xf2, 0xaf, 0x12, 0x4c, 0x22, 0x83, 0xae, 0x8f,
    0x6d, 0x50, 0xe8, 0x16, 0xdc, 0x4c, 0x25, 0xe4, 0x54, 0x5a, 0xf0, 0xb7,
    0x82, 0x4f, 0xdc, 0x2e, 0xb5, 0xfd, 0x24, 0x26, 0x22, 0x26, 0x4f, 0x20,
    0x76, 0xb4, 0x36, 0x9e, 0x62, 0xb8, 0xb9, 0x2c, 0x52, 0xaf, 0x58, 0xa8,
    0x90, 0xcd, 0x62, 0x06, 0x30, 0xcc, 0x93, 0x8b, 0x3d, 0xd4, 0xd1, 0x5f,
    0x60, 0x3b, 0x28, 0x15, 0xcc, 0x92, 0xc1, 0x70, 0xb7, 0x39, 0x8c, 0x73,
    0x01, 0x65, 0x2f, 0x19, 0xeb, 0xd0, 0xce, 0x3f, 0x84, 0x36, 0xea, 0x11,
    0x34, 0x0e, 0xce, 0x0b,
};

static byte dh_priv2[] = {
    0x5e, 0x49, 0x52, 0xb3, 0xc4, 0x8f, 0x3f, 0xde, 0x55, 0x9d, 0x87, 0xb3,
    0x21, 0xb8, 0x24, 0xb1, 0xb0, 0x35, 0x5e, 0xc7, 0xbb, 0x5a, 0x86, 0x9e,
    0xfb, 0xd3, 0x8f, 0x5b, 0x7e,
};

static byte dh_pub2[] = {
    0x9b, 0xc4, 0xdb, 0x33, 0xc4, 0x96, 0xf4, 0x43, 0xa0, 0x3b, 0x9d, 0x7c,
    0x7d, 0x81, 0x97, 0xf6, 0xb9, 0x94, 0x0f, 0x0f, 0x2e, 0xc1, 0x16, 0xdc,
    0xf6, 0xe3, 0xaf, 0xa1, 0xcd, 0x32, 0xdf, 0xd5, 0xdc, 0x12, 0x93, 0x99,
    0x1d, 0xfb, 0xff, 0x54, 0xdf, 0xf6, 0x24, 0x6a, 0xc2, 0x9e, 0xd0, 0x41,
    0xed, 0x28, 0x23, 0x8d, 0x68, 0x06, 0x57, 0xd6, 0xb6, 0xf1, 0x9a, 0x5d,
    0x41, 0xc7, 0x96, 0xf8, 0xc4, 0x7f, 0xd6, 0x92, 0x97, 0x56, 0x05, 0xd9,
    0x17, 0x46, 0x07, 0x19, 0x0b, 0x08, 0xd5, 0xba, 0x90, 0xd8, 0x40, 0x94,
    0x2d, 0x90, 0x75, 0x01, 0x77, 0xa7, 0x12, 0x82, 0x5b, 0x82, 0x9e, 0x7b,
    0x75, 0x46, 0xce, 0x07, 0x40, 0x9b, 0xbb, 0x10, 0x3d, 0xf7, 0x80, 0xaa,
    0x39, 0xa3, 0x67, 0xfa, 0xd8, 0x07, 0xda, 0x09, 0x92, 0x68, 0x6d, 0xa4,
    0xe2, 0xda, 0xde, 0x6e, 0x98, 0xcd, 0x1e, 0x6d, 0x68, 0x72, 0x0e, 0x68,
    0x1e, 0xaa, 0x72, 0x12, 0x92, 0xe6, 0x96, 0x3d, 0x6c, 0x57, 0xb8, 0x77,
    0x61, 0x6d, 0xb8, 0x6f, 0x1e, 0xbe, 0xd8, 0x2c, 0xdd, 0xc4, 0xe9, 0x38,
    0x77, 0xde, 0x5f, 0x2f, 0xb6, 0x40, 0xf0, 0x30, 0x5b, 0x33, 0x16, 0xd4,
    0xef, 0x74, 0x9f, 0x38, 0xbc, 0x4d, 0x2d, 0xf3, 0x14, 0x8f, 0x38, 0xcc,
    0x6c, 0x8b, 0xad, 0xef, 0x30, 0xee, 0xc0, 0x36, 0x31, 0x6b, 0xc8, 0xb0,
    0x55, 0x44, 0x62, 0xb0, 0x24, 0x70, 0x9f, 0x64, 0x5c, 0xb1, 0x70, 0x19,
    0xfa, 0xd4, 0x8d, 0x23, 0xa8, 0x24, 0x72, 0x49, 0xfd, 0x23, 0x90, 0x18,
    0x99, 0xc1, 0xd0, 0x96, 0x91, 0x5f, 0x62, 0xf9, 0xd7, 0x14, 0xfa, 0x8b,
    0xeb, 0x05, 0x97, 0x03, 0xe1, 0x51, 0xc9, 0x3b, 0x8d, 0x41, 0x86, 0x53,
    0x45, 0xdc, 0x6d, 0xe1, 0xc7, 0x94, 0xfd, 0xdd, 0x57, 0xed, 0xc6, 0xe7,
    0x38, 0x84, 0xf7, 0xeb,
};

/* dh1024 p */
static const byte dh_p[] = {
    0xb0, 0xa1, 0x08, 0x06, 0x9c, 0x08, 0x13, 0xba, 0x59, 0x06, 0x3c, 0xbc,
    0x30, 0xd5, 0xf5, 0x00, 0xc1, 0x4f, 0x44, 0xa7, 0xd6, 0xef, 0x4a, 0xc6,
    0x25, 0x27, 0x1c, 0xe8, 0xd2, 0x96, 0x53, 0x0a, 0x5c, 0x91, 0xdd, 0xa2,
    0xc2, 0x94, 0x84, 0xbf, 0x7d, 0xb2, 0x44, 0x9f, 0x9b, 0xd2, 0xc1, 0x8a,
    0xc5, 0xbe, 0x72, 0x5c, 0xa7, 0xe7, 0x91, 0xe6, 0xd4, 0x9f, 0x73, 0x07,
    0x85, 0x5b, 0x66, 0x48, 0xc7, 0x70, 0xfa, 0xb4, 0xee, 0x02, 0xc9, 0x3d,
    0x9a, 0x4a, 0xda, 0x3d, 0xc1, 0x46, 0x3e, 0x19, 0x69, 0xd1, 0x17, 0x46,
    0x07, 0xa3, 0x4d, 0x9f, 0x2b, 0x96, 0x17, 0x39, 0x6d, 0x30, 0x8d, 0x2a,
    0xf3, 0x94, 0xd3, 0x75, 0xcf, 0xa0, 0x75, 0xe6, 0xf2, 0x92, 0x1f, 0x1a,
    0x70, 0x05, 0xaa, 0x04, 0x83, 0x57, 0x30, 0xfb, 0xda, 0x76, 0x93, 0x38,
    0x50, 0xe8, 0x27, 0xfd, 0x63, 0xee, 0x3c, 0xe5, 0xb7, 0xc8, 0x09, 0xae,
    0x6f, 0x50, 0x35, 0x8e, 0x84, 0xce, 0x4a, 0x00, 0xe9, 0x12, 0x7e, 0x5a,
    0x31, 0xd7, 0x33, 0xfc, 0x21, 0x13, 0x76, 0xcc, 0x16, 0x30, 0xdb, 0x0c,
    0xfc, 0xc5, 0x62, 0xa7, 0x35, 0xb8, 0xef, 0xb7, 0xb0, 0xac, 0xc0, 0x36,
    0xf6, 0xd9, 0xc9, 0x46, 0x48, 0xf9, 0x40, 0x90, 0x00, 0x2b, 0x1b, 0xaa,
    0x6c, 0xe3, 0x1a, 0xc3, 0x0b, 0x03, 0x9e, 0x1b, 0xc2, 0x46, 0xe4, 0x48,
    0x4e, 0x22, 0x73, 0x6f, 0xc3, 0x5f, 0xd4, 0x9a, 0xd6, 0x30, 0x07, 0x48,
    0xd6, 0x8c, 0x90, 0xab, 0xd4, 0xf6, 0xf1, 0xe3, 0x48, 0xd3, 0x58, 0x4b,
    0xa6, 0xb9, 0xcd, 0x29, 0xbf, 0x68, 0x1f, 0x08, 0x4b, 0x63, 0x86, 0x2f,
    0x5c, 0x6b, 0xd6, 0xb6, 0x06, 0x65, 0xf7, 0xa6, 0xdc, 0x00, 0x67, 0x6b,
    0xbb, 0xc3, 0xa9, 0x41, 0x83, 0xfb, 0xc7, 0xfa, 0xc8, 0xe2, 0x1e, 0x7e,
    0xaf, 0x00, 0x3f, 0x93,
};


/* simple example of using RSA encrypt with Intel QA */
int main(int argc, char** argv)
{
    int ret;
    WC_ASYNC_DEV dev;
    byte out[256];
    word32 outLen = sizeof(out);
    byte tmp[256];
    word32 tmpLen = sizeof(tmp);
#ifndef NO_RSA
    WC_BIGINT d, n;
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
    WC_BIGINT k, xG, yG, xR, yR, a, b, q;
#endif
#ifndef NO_DH
    WC_BIGINT p;
#endif

#ifdef QAT_DEBUG
    wolfSSL_Debugging_ON();
#endif

    IntelQaInit(NULL);

#ifdef QAT_ENABLE_RNG
    /* DRBG Test */
    IntelQaOpen(&dev, 0);
    ret = IntelQaDrbg(&dev, out, sizeof(out));
    printf("RNG1: Ret=%d\n", ret);

    /* call again using same session */
    ret = IntelQaDrbg(&dev, out, sizeof(out));
    printf("RNG2: Ret=%d\n", ret);
    IntelQaClose(&dev);
#endif

#ifndef NO_RSA
    IntelQaOpen(&dev, 0);
    /* RSA Test */
    dev.event.ret = WC_PENDING_E;
    XMEMSET(out, 0, sizeof(out));
    wc_bigint_init(&d);
    wc_bigint_init(&n);
    wc_bigint_from_unsigned_bin(&d, rsa_d, sizeof(rsa_d));
    wc_bigint_from_unsigned_bin(&n, rsa_n, sizeof(rsa_n));
    ret = IntelQaRsaPrivate(&dev, (byte*)rsa_in, sizeof(rsa_in), &d, &n, out,
        &outLen);
    if (ret == 0 || ret == WC_PENDING_E) {
        ret = IntelQaPollBlockRet(&dev, WC_PENDING_E);
    }
    printf("RSA Private: Ret=%d, Out Len=%d\n", ret, outLen);
    IntelQaClose(&dev);
#endif /* !NO_RSA */

#ifndef NO_AES
#ifdef HAVE_AESGCM
    /* AES Test */
    IntelQaOpen(&dev, 0);
    dev.event.ret = WC_PENDING_E;
    tmpLen = sizeof(aesgcm_t);
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(tmp, 0, sizeof(tmp));

    ret = IntelQaSymAesGcmEncrypt(&dev, out, aesgcm_p, sizeof(aesgcm_p),
        aesgcm_k, sizeof(aesgcm_k), aesgcm_iv, sizeof(aesgcm_iv),
        tmp, tmpLen, aesgcm_a, sizeof(aesgcm_a));
    if (ret == 0 || ret == WC_PENDING_E) {
        ret = IntelQaPollBlockRet(&dev, WC_PENDING_E);
    }
    printf("AES GCM Encrypt: Ret=%d, Tag Len=%d\n", ret, tmpLen);
    IntelQaClose(&dev);
#endif /* HAVE_AESGCM */
#endif /* NO_AES */

#ifdef HAVE_ECC
#ifdef HAVE_ECC_DHE
    /* ECDHE Test */
    IntelQaOpen(&dev, 0);
    dev.event.ret = WC_PENDING_E;
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(tmp, 0, sizeof(tmp));
    wc_bigint_init(&xG);
    wc_bigint_init(&yG);
    wc_bigint_init(&k);
    wc_bigint_init(&a);
    wc_bigint_init(&b);
    wc_bigint_init(&q);
    wc_bigint_from_unsigned_bin(&xG, ecc_xg, sizeof(ecc_xg));
    wc_bigint_from_unsigned_bin(&yG, ecc_yg, sizeof(ecc_yg));
    wc_bigint_from_unsigned_bin(&k, ecc_k, sizeof(ecc_k));
    wc_bigint_from_unsigned_bin(&a, ecc_a, sizeof(ecc_a));
    wc_bigint_from_unsigned_bin(&b, ecc_b, sizeof(ecc_b));
    wc_bigint_from_unsigned_bin(&q, ecc_q, sizeof(ecc_q));

    ret = IntelQaEcdh(&dev, &k, &xG, &yG, out, &outLen, &a, &b, &q, 1);
    if (ret == 0 || ret == WC_PENDING_E) {
        ret = IntelQaPollBlockRet(&dev, WC_PENDING_E);
    }
    printf("ECDH: Ret=%d, Result: X Len=%d, Y Len=%d\n", ret, xR.len, yR.len);
    IntelQaClose(&dev);
#endif /* HAVE_ECC_DHE */
#endif /* HAVE_ECC */

#ifndef NO_DH
    /* DH Test */
    IntelQaOpen(&dev, 0);
    dev.event.ret = WC_PENDING_E;
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(tmp, 0, sizeof(tmp));
    wc_bigint_init(&p);
    wc_bigint_from_unsigned_bin(&p, dh_p, sizeof(dh_p));

    outLen = 0;
    ret = IntelQaDhAgree(&dev, &p, out, &outLen, dh_priv1, sizeof(dh_priv1),
        dh_pub2, sizeof(dh_pub2));
    if (ret == 0 || ret == WC_PENDING_E) {
        ret = IntelQaPollBlockRet(&dev, WC_PENDING_E);
    }
    printf("DH Agree1: Ret=%d, Out Len=%d\n", ret, outLen);

    tmpLen = 0;
    ret = IntelQaDhAgree(&dev, &p, tmp, &tmpLen, dh_priv2, sizeof(dh_priv2),
        dh_pub1, sizeof(dh_pub1));
    if (ret == 0 || ret == WC_PENDING_E) {
        ret = IntelQaPollBlockRet(&dev, WC_PENDING_E);
    }
    printf("DH Agree2: Ret=%d, Out Len=%d\n", ret, tmpLen);

    /* compare results */
    if (ret != 0 || outLen != tmpLen || memcmp(out, tmp, outLen) != 0) {
        printf("DH Agree Failed!\n");
    }
    else {
        printf("DH Agree Match\n");
    }
    IntelQaClose(&dev);
#endif /* !NO_DH */

    (void)tmp;
    (void)tmpLen;

    IntelQaDeInit(0);

    return 0;
}

#endif

#endif /* HAVE_INTEL_QA */
