/* async.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_ASYNC_CRYPT

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>

#include <wolfssl/wolfcrypt/async.h>


static WC_ASYNC_DEV* wolfAsync_GetDev(WOLF_EVENT* event)
{
    WC_ASYNC_DEV* dev = NULL;

    if (event && event->context) {
        switch (event->type) {
            /* context is WOLFSSL* */
            case WOLF_EVENT_TYPE_ASYNC_WOLFSSL:
            {
                WOLFSSL* ssl = (WOLFSSL*)event->context;
                dev = ssl->asyncDev;
                break;
            }

            /* context is WC_ASYNC_DEV */
            case WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT:
            {
                dev = (WC_ASYNC_DEV*)event->context;
                break;
            }

            case WOLF_EVENT_TYPE_NONE:
            default:
                WOLFSSL_MSG("Unhandled event->type context!");
                dev = NULL;
                break;
        }
    }

    return dev;
}


#if defined(WOLFSSL_ASYNC_CRYPT_SW)

/* Allow way to have async SW code included, and disabled at run-time */
static int wolfAsyncSwDisabled = 0; /* default off */


static int wolfAsync_DoSw(WC_ASYNC_DEV* asyncDev)
{
    int ret = 0;
    WC_ASYNC_SW* sw;

    if (asyncDev == NULL) {
        return BAD_FUNC_ARG;
    }
    sw = &asyncDev->sw;

    switch (sw->type) {
#ifdef HAVE_ECC
        case ASYNC_SW_ECC_MAKE:
        {
            ret = wc_ecc_make_key_ex(
                (WC_RNG*)sw->eccMake.rng,
                sw->eccMake.size,
                (ecc_key*)sw->eccMake.key,
                sw->eccMake.curve_id
            );
            break;
        }
    #ifdef HAVE_ECC_SIGN
        case ASYNC_SW_ECC_SIGN:
        {
            ret = wc_ecc_sign_hash_ex(
                sw->eccSign.in,
                sw->eccSign.inSz,
                (WC_RNG*)sw->eccSign.rng,
                (ecc_key*)sw->eccSign.key,
                (mp_int*)sw->eccSign.r,
                (mp_int*)sw->eccSign.s
            );
            break;
        }
    #endif /* HAVE_ECC_SIGN */
    #ifdef HAVE_ECC_VERIFY
        case ASYNC_SW_ECC_VERIFY:
        {
            ret = wc_ecc_verify_hash_ex(
                (mp_int*)sw->eccVerify.r,
                (mp_int*)sw->eccVerify.s,
                sw->eccVerify.hash,
                sw->eccVerify.hashlen,
                sw->eccVerify.stat,
                (ecc_key*)sw->eccVerify.key
            );
            break;
        }
    #endif /* HAVE_ECC_VERIFY */
    #ifdef HAVE_ECC_DHE
        case ASYNC_SW_ECC_SHARED_SEC:
        {
            ret = wc_ecc_shared_secret_gen_sync(
                (ecc_key*)sw->eccSharedSec.private_key,
                (ecc_point*)sw->eccSharedSec.public_point,
                sw->eccSharedSec.out,
                sw->eccSharedSec.outLen
            );
            break;
        }
    #endif /* HAVE_ECC_DHE */
#endif /* HAVE_ECC */
#ifndef NO_RSA
    #ifdef WOLFSSL_KEY_GEN
        case ASYNC_SW_RSA_MAKE:
        {
            ret = wc_MakeRsaKey(
                (RsaKey*)sw->rsaMake.key,
                sw->rsaMake.size,
                sw->rsaMake.e,
                (WC_RNG*)sw->rsaMake.rng
            );
            break;
        }
    #endif /* WOLFSSL_KEY_GEN */
        case ASYNC_SW_RSA_FUNC:
        {
            ret = wc_RsaFunction(
                sw->rsaFunc.in,
                sw->rsaFunc.inSz,
                sw->rsaFunc.out,
                sw->rsaFunc.outSz,
                sw->rsaFunc.type,
                (RsaKey*)sw->rsaFunc.key,
                (WC_RNG*)sw->rsaFunc.rng
            );
            break;
        }
#endif /* !NO_RSA */
#ifndef NO_DH
        case ASYNC_SW_DH_AGREE:
        {
            ret = wc_DhAgree(
                (DhKey*)sw->dhAgree.key,
                sw->dhAgree.agree,
                sw->dhAgree.agreeSz,
                sw->dhAgree.priv,
                sw->dhAgree.privSz,
                sw->dhAgree.otherPub,
                sw->dhAgree.pubSz
            );
            break;
        }
        case ASYNC_SW_DH_GEN:
        {
            ret = wc_DhGenerateKeyPair(
                (DhKey*)sw->dhGen.key,
                (WC_RNG*)sw->dhGen.rng,
                sw->dhGen.priv,
                sw->dhGen.privSz,
                sw->dhGen.pub,
                sw->dhGen.pubSz
            );
            break;
        }
#endif /* !NO_DH */
#ifndef NO_AES
        case ASYNC_SW_AES_CBC_ENCRYPT:
        {
            ret = wc_AesCbcEncrypt(
                (Aes*)sw->aes.aes,
                sw->aes.out,
                sw->aes.in,
                sw->aes.sz
            );
            break;
        }
    #ifdef HAVE_AES_DECRYPT
        case ASYNC_SW_AES_CBC_DECRYPT:
        {
            ret = wc_AesCbcDecrypt(
                (Aes*)sw->aes.aes,
                sw->aes.out,
                sw->aes.in,
                sw->aes.sz
            );
            break;
        }
    #endif /* HAVE_AES_DECRYPT */

    #ifdef HAVE_AESGCM
        case ASYNC_SW_AES_GCM_ENCRYPT:
        {
            ret = wc_AesGcmEncrypt(
                (Aes*)sw->aes.aes,
                sw->aes.out,
                sw->aes.in,
                sw->aes.sz,
                sw->aes.iv,
                sw->aes.ivSz,
                sw->aes.authTag,
                sw->aes.authTagSz,
                sw->aes.authIn,
                sw->aes.authInSz
            );
            break;
        }
        #ifdef HAVE_AES_DECRYPT
        case ASYNC_SW_AES_GCM_DECRYPT:
        {
            ret = wc_AesGcmDecrypt(
                (Aes*)sw->aes.aes,
                sw->aes.out,
                sw->aes.in,
                sw->aes.sz,
                sw->aes.iv,
                sw->aes.ivSz,
                sw->aes.authTag,
                sw->aes.authTagSz,
                sw->aes.authIn,
                sw->aes.authInSz
            );
            break;
        }
        #endif /* HAVE_AES_DECRYPT */
    #endif /* HAVE_AESGCM */
#endif /* !NO_AES */
#ifndef NO_DES3
        case ASYNC_SW_DES3_CBC_ENCRYPT:
        {
            ret = wc_Des3_CbcEncrypt(
                (Des3*)sw->des.des,
                sw->des.out,
                sw->des.in,
                sw->des.sz
            );
            break;
        }
        case ASYNC_SW_DES3_CBC_DECRYPT:
        {
            ret = wc_Des3_CbcDecrypt(
                (Des3*)sw->des.des,
                sw->des.out,
                sw->des.in,
                sw->des.sz
            );
            break;
        }
#endif /* !NO_DES3 */
#ifdef HAVE_CURVE25519
        case ASYNC_SW_X25519_MAKE:
        {
            ret = wc_curve25519_make_key(
                (WC_RNG*)sw->x25519Make.rng,
                sw->x25519Make.size,
                (curve25519_key*)sw->x25519Make.key
            );
            break;
        }
        case ASYNC_SW_X25519_SHARED_SEC:
        {
            ret = wc_curve25519_shared_secret_ex(
                (curve25519_key*)sw->x25519SharedSec.priv,
                (curve25519_key*)sw->x25519SharedSec.pub,
                sw->x25519SharedSec.out,
                sw->x25519SharedSec.outLen,
                sw->x25519SharedSec.endian
            );
            break;
        }
#endif /* HAVE_CURVE25519 */
        default:
            WOLFSSL_MSG("Invalid async crypt SW type!");
            ret = BAD_FUNC_ARG;
            break;
    };

    /* Reset test type */
    if (ret == FP_WOULDBLOCK) {
        ret = WC_PENDING_E;
    }
    else if (ret == 0) {
        sw->type = ASYNC_SW_NONE;
    }

    return ret;
}

int wc_AsyncSwInit(WC_ASYNC_DEV* dev, int type)
{
    if (dev) {
        WC_ASYNC_SW* sw = &dev->sw;
        if (sw->type == ASYNC_SW_NONE) {
            sw->type = type;
            return 1;
        }
    }
    return 0;
}

#endif /* WOLFSSL_ASYNC_CRYPT_SW */

int wolfAsync_DevOpenThread(int *pDevId, void* threadId)
{
    int ret = 0;
    int devId = INVALID_DEVID;

#ifdef HAVE_CAVIUM
    ret = NitroxOpenDeviceDefault();
    if (ret >= 0)
        devId = ret;
    else
        ret = ASYNC_INIT_E;
#elif defined(HAVE_INTEL_QA)
    ret = IntelQaInit(threadId);
    if (ret >= 0)
        devId = ret;
    else
        ret = ASYNC_INIT_E;
#elif defined(WOLFSSL_ASYNC_CRYPT_SW)
    if (!wolfAsyncSwDisabled) {
        /* For SW use any value 0 or greater */
        devId = 0;
    }
#endif

    (void)threadId;

    /* return devId if requested */
    if (*pDevId)
        *pDevId = devId;

    return ret;
}

int wolfAsync_HardwareStart(void)
{
    int ret = 0;

    #ifdef HAVE_CAVIUM
        /* nothing to do */
    #elif defined(HAVE_INTEL_QA)
        ret = IntelQaHardwareStart(QAT_PROCESS_NAME, QAT_LIMIT_DEV_ACCESS);
    #endif

    return ret;
}

void wolfAsync_HardwareStop(void)
{
    #ifdef HAVE_CAVIUM
        /* nothing to do */
    #elif defined(HAVE_INTEL_QA)
        IntelQaHardwareStop();
    #endif
}

int wolfAsync_DevOpen(int *devId)
{
    return wolfAsync_DevOpenThread(devId, NULL);
}

void wolfAsync_DevClose(int *devId)
{
    if (devId && *devId != INVALID_DEVID) {
    #ifdef HAVE_CAVIUM
        NitroxCloseDevice(*devId);
    #elif defined(HAVE_INTEL_QA)
        IntelQaDeInit(*devId);
    #endif
        *devId = INVALID_DEVID;
    }
}

int wolfAsync_DevCtxInit(WC_ASYNC_DEV* asyncDev, word32 marker, void* heap,
    int devId)
{
    int ret = 0;

    if (asyncDev == NULL) {
        return BAD_FUNC_ARG;
    }

    /* always clear async device context */
    XMEMSET(asyncDev, 0, sizeof(WC_ASYNC_DEV));

    /* negative device Id's are invalid */
    if (devId >= 0) {
        asyncDev->marker = marker;
        asyncDev->heap = heap;

    #ifdef HAVE_CAVIUM
        ret = NitroxAllocContext(asyncDev, devId, CONTEXT_SSL);
    #elif defined(HAVE_INTEL_QA)
        ret = IntelQaOpen(asyncDev, devId);
    #endif
    }

    return ret;
}

void wolfAsync_DevCtxFree(WC_ASYNC_DEV* asyncDev, word32 marker)
{
    if (asyncDev && asyncDev->marker == marker) {
    #ifdef HAVE_CAVIUM
        NitroxFreeContext(asyncDev);
    #elif defined(HAVE_INTEL_QA)
        IntelQaClose(asyncDev);
    #endif
        asyncDev->marker = WOLFSSL_ASYNC_MARKER_INVALID;
    }
}

int wolfAsync_DevCopy(WC_ASYNC_DEV* src, WC_ASYNC_DEV* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

    /* make sure we aren't copying to self */
    if (src == dst)
        return ret;

#ifdef HAVE_CAVIUM
    /* nothing to do here */
#elif defined(HAVE_INTEL_QA)
    ret = IntelQaDevCopy(src, dst);
#endif

    return ret;
}

/* called from `wolfSSL_AsyncPop` to check if event is done and deliver
 * async return code */
int wolfAsync_EventPop(WOLF_EVENT* event, enum WOLF_EVENT_TYPE event_type)
{
    int ret;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    if (event->type == event_type) {
        /* Trap the scenario where event is not done */
        if (event->state == WOLF_EVENT_STATE_PENDING) {
            return WC_PENDING_E;
        }

        /* Get async return code */
        ret = event->ret;

        /* Reset state */
        event->state = WOLF_EVENT_STATE_READY;
    }
    else {
        ret = WC_NO_PENDING_E;
    }

    return ret;
}

int wolfAsync_EventQueuePush(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event)
{
    if (queue == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Setup event and push to event queue */
    event->dev.async = wolfAsync_GetDev(event);
    return wolfEventQueue_Push(queue, event);
}

#ifdef HAVE_CAVIUM
static int wolfAsync_NitroxCheckReq(WC_ASYNC_DEV* asyncDev, WOLF_EVENT* event)
{
    int ret;

    /* populate event requestId */
    event->reqId = asyncDev->nitrox.reqId;
    if (event->reqId == 0)
        return WC_INIT_E;

    /* poll specific request */
    ret = NitroxCheckRequest(asyncDev, event);

#ifdef WOLFSSL_NITROX_DEBUG
    if (event->ret == WC_NO_ERR_TRACE(WC_PENDING_E))
        event->pendCount++;
    else
        printf("NitroxCheckRequest: ret %x, req %lx, count %u\n",
            ret,
            event->reqId,
            event->pendCount);
#else
    (void)ret;
#endif

    /* if not pending then clear requestId */
    if (event->ret != WC_NO_ERR_TRACE(WC_PENDING_E)) {
        event->reqId = 0;
    }

    return 0;
}
#endif /* HAVE_CAVIUM */

int wolfAsync_EventPoll(WOLF_EVENT* event, WOLF_EVENT_FLAG flags)
{
    int ret = 0;
    WC_ASYNC_DEV* asyncDev;

    (void)flags;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }
    asyncDev = event->dev.async;
    if (asyncDev == NULL) {
        return WC_INIT_E;
    }

    if (flags & WOLF_POLL_FLAG_CHECK_HW) {
    #if defined(HAVE_CAVIUM)
        ret = wolfAsync_NitroxCheckReq(asyncDev, event);
    #elif defined(HAVE_INTEL_QA)
        /* poll QAT hardware, callback returns data, IntelQaPoll sets event */
        ret = IntelQaPoll(asyncDev);
    #elif defined(WOLFSSL_ASYNC_CRYPT_SW)
        event->ret = wolfAsync_DoSw(asyncDev);
    #endif

        /* If not pending then mark as done */
        if (event->ret != WC_NO_ERR_TRACE(WC_PENDING_E)) {
            event->state = WOLF_EVENT_STATE_DONE;
        }
    }

    return ret;
}


#ifdef HAVE_CAVIUM
static int wolfAsync_NitroxCheckMultiReqBuf(WC_ASYNC_DEV* asyncDev,
    WOLF_EVENT_QUEUE* queue, void* context_filter,
    CspMultiRequestStatusBuffer* multi_req, int req_count)
{
    WOLF_EVENT* event;
    int ret = 0, i;

    if (asyncDev == NULL || queue == NULL || multi_req == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Perform multi hardware poll */
    ret = NitroxCheckRequests(asyncDev, multi_req);
    if (ret != 0) {
        return ret;
    }

    /* Iterate event queue */
    for (event = queue->head; event != NULL; event = event->next) {
        if (event->type >= WOLF_EVENT_TYPE_ASYNC_FIRST &&
            event->type <= WOLF_EVENT_TYPE_ASYNC_LAST)
        {
            /* optional filter based on context */
            if (context_filter == NULL || event->context == context_filter) {
                /* find request */
                for (i = 0; i < req_count; i++) {
                    if (event->reqId == multi_req->req[i].request_id) {

                        event->ret = NitroxTranslateResponseCode(
                            multi_req->req[i].status);

                    #ifdef WOLFSSL_NITROX_DEBUG
                        if (event->ret == WC_NO_ERR_TRACE(WC_PENDING_E))
                            event->pendCount++;
                        else
                            printf("NitroxCheckRequests: "
                                "ret %x, req %lx, count %u\n",
                                multi_req->req[i].status,
                                multi_req->req[i].request_id,
                                event->pendCount);
                    #endif

                        /* If not pending then mark as done */
                        if (event->ret != WC_NO_ERR_TRACE(WC_PENDING_E)) {
                            event->state = WOLF_EVENT_STATE_DONE;
                            event->reqId = 0;
                        }
                        break;
                    }
                }
            }
        }
    }

    /* reset multi request buffer */
    XMEMSET(multi_req, 0, sizeof(CspMultiRequestStatusBuffer));
    multi_req->count = CAVIUM_MAX_POLL;

    return ret;
}
#endif /* HAVE_CAVIUM */

int wolfAsync_EventQueuePoll(WOLF_EVENT_QUEUE* queue, void* context_filter,
    WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount)
{
    WOLF_EVENT* event;
    int ret = 0, count = 0;
    WC_ASYNC_DEV* asyncDev = NULL;
#if defined(HAVE_CAVIUM)
    CspMultiRequestStatusBuffer multi_req;
    int req_count = 0;

    /* reset multi request buffer */
    XMEMSET(&multi_req, 0, sizeof(CspMultiRequestStatusBuffer));
    multi_req.count = CAVIUM_MAX_POLL;
#endif

    /* possible un-used variable */
    (void)asyncDev;

    if (queue == NULL) {
        return BAD_FUNC_ARG;
    }

#ifndef SINGLE_THREADED
    /* In single threaded mode "event_queue.lock" doesn't exist */
    if ((ret = wc_LockMutex(&queue->lock)) != 0) {
        return ret;
    }
#endif

    if (flags & WOLF_POLL_FLAG_CHECK_HW) {
        /* check event queue */
        for (event = queue->head; event != NULL; event = event->next) {
            if (event->type >= WOLF_EVENT_TYPE_ASYNC_FIRST &&
                event->type <= WOLF_EVENT_TYPE_ASYNC_LAST)
            {
                /* optional filter based on context */
                if (context_filter == NULL ||
                    event->context == context_filter) {
                    asyncDev = event->dev.async;

                    if (asyncDev == NULL) {
                        ret = WC_INIT_E;
                        break;
                    }

                    count++;

            #if defined(HAVE_CAVIUM)
                    /* populate event requestId */
                    event->reqId = asyncDev->nitrox.reqId;

                    /* add entry to multi-request buffer for polling */
                    if (event->reqId > 0) {
                        multi_req.req[req_count++].request_id = event->reqId;
                    }
                    /* submit filled multi-request query */
                    if (req_count == CAVIUM_MAX_POLL) {
                        ret = wolfAsync_NitroxCheckMultiReqBuf(asyncDev,
                                queue, context_filter, &multi_req, req_count);
                        if (ret != 0) {
                            break;
                        }
                    }
            #else
                #if defined(HAVE_INTEL_QA)
                    /* poll QAT hardware, callback returns data,
                     * IntelQaPoll sets event */
                    ret = IntelQaPoll(asyncDev);
                    if (ret != 0) {
                        break;
                    }

                #elif defined(WOLFSSL_ASYNC_CRYPT_SW)
                    #ifdef WOLF_ASYNC_SW_SKIP_MOD
                        /* Simulate random hardware not done */
                        if (count % WOLF_ASYNC_SW_SKIP_MOD)
                    #endif
                        {
                            event->ret = wolfAsync_DoSw(asyncDev);
                        }
                #elif defined(WOLF_CRYPTO_CB) || defined(HAVE_PK_CALLBACKS)
                    /* Use crypto or PK callbacks */

                #else
                    #warning No async crypt device defined!
                #endif

                    /* If not pending then mark as done */
                    if (event->ret != WC_NO_ERR_TRACE(WC_PENDING_E)) {
                        event->state = WOLF_EVENT_STATE_DONE;
                    }
            #endif
                }
            }
        } /* for */

    #if defined(HAVE_CAVIUM)
        /* submit partial multi-request query (if no prev errors) */
        if (ret == 0 && req_count > 0) {
            ret = wolfAsync_NitroxCheckMultiReqBuf(asyncDev,
                            queue, context_filter, &multi_req, req_count);
        }
    #endif
    } /* flag  WOLF_POLL_FLAG_CHECK_HW */

    /* process event queue */
    count = 0;
    for (event = queue->head; event != NULL; event = event->next) {
        if (event->type >= WOLF_EVENT_TYPE_ASYNC_FIRST &&
            event->type <= WOLF_EVENT_TYPE_ASYNC_LAST)
        {
            /* optional filter based on context */
            if (context_filter == NULL || event->context == context_filter) {
                /* If event is done then process */
                if (event->state == WOLF_EVENT_STATE_DONE) {
                    /* remove from queue */
                    ret = wolfEventQueue_Remove(queue, event);
                    if (ret < 0) break; /* exit for */

                    /* return pointer in 'events' arg */
                    if (events) {
                        events[count] = event; /* return pointer */
                    }
                    count++;

                    /* check to make sure our event list isn't full */
                    if (events && count >= maxEvents) {
                        break; /* exit for */
                    }
                }
            }
        }
    }

#ifndef SINGLE_THREADED
    wc_UnLockMutex(&queue->lock);
#endif

    /* Return number of properly populated events */
    if (eventCount) {
        *eventCount = count;
    }

    return ret;
}

int wolfAsync_EventInit(WOLF_EVENT* event, WOLF_EVENT_TYPE type, void* context,
    word32 flags)
{
    int ret = 0;
    WC_ASYNC_DEV* asyncDev;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    event->type = type;
    event->context = context;
#ifndef WC_NO_ASYNC_THREADING
    event->threadId = wc_AsyncThreadId();
#endif
    event->ret = WC_PENDING_E;
    event->state = WOLF_EVENT_STATE_PENDING;

    asyncDev = wolfAsync_GetDev(event);
    event->dev.async = asyncDev;
    event->flags = flags;
#ifdef HAVE_CAVIUM
    event->reqId = 0;
#endif

    return ret;
}

int wolfAsync_EventWait(WOLF_EVENT* event)
{
    int ret = 0;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    /* wait for completion */
    while (ret == 0 && event->ret == WC_NO_ERR_TRACE(WC_PENDING_E)) {
        ret = wolfAsync_EventPoll(event, WOLF_POLL_FLAG_CHECK_HW);
    }

    return ret;
}

int wc_AsyncHandle(WC_ASYNC_DEV* asyncDev, WOLF_EVENT_QUEUE* queue,
    word32 event_flags)
{
    int ret;
    WOLF_EVENT* event;

    if (asyncDev == NULL || queue == NULL) {
        return BAD_FUNC_ARG;
    }

    /* setup the event and push to queue */
    event = &asyncDev->event;
    ret = wolfAsync_EventInit(event, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT,
                                                        asyncDev, event_flags);
    if (ret == 0) {
        ret = wolfEventQueue_Push(queue, event);
    }

    /* check for error (helps with debugging) */
    if (ret != 0) {
        WOLFSSL_MSG("wc_AsyncHandle failed");
    }

    return ret;
}

int wc_AsyncWait(int ret, WC_ASYNC_DEV* asyncDev, word32 event_flags)
{
    if (ret == WC_NO_ERR_TRACE(WC_PENDING_E)) {
        WOLF_EVENT* event;

        if (asyncDev == NULL)
            return BAD_FUNC_ARG;

        event = &asyncDev->event;
        ret = wolfAsync_EventInit(event, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT,
                                                        asyncDev, event_flags);
        if (ret == 0) {
            ret = wolfAsync_EventWait(event);
            if (ret == 0) {
                ret = event->ret;

                /* clear event */
                event->state = WOLF_EVENT_STATE_READY;
            }
        }
    }
    return ret;
}

#ifndef WC_NO_ASYNC_SLEEP
int wc_AsyncSleep(word32 ms)
{
    int ret = 0;
    struct timespec resTime, remTime;
    resTime.tv_sec = ms/1000;
    resTime.tv_nsec = (ms%1000)*1000000;
    do {
        ret = nanosleep(&resTime, &remTime);
        resTime = remTime;
    } while ((ret!=0) && (errno == EINTR));

    if (ret != 0) {
        fprintf(stderr, "nanoSleep failed with code %d\n", ret);
        return BAD_FUNC_ARG;
    }

   return ret;
}
#endif

/* Pthread Helpers */
#ifndef WC_NO_ASYNC_THREADING

int wc_AsyncGetNumberOfCpus(void)
{
    int numCpus;

    numCpus = (int)sysconf(_SC_NPROCESSORS_ONLN);

    return numCpus;
}

int wc_AsyncThreadCreate_ex(pthread_t *thread,
    word32 priority, int policy,
    AsyncThreadFunc_t function, void* params)
{
    int status = 1;
    pthread_attr_t attr;
    struct sched_param param;

    status = pthread_attr_init(&attr);
    if (status !=0) {
        fprintf(stderr, "pthread_attr_init error: %d\n", status);
        return ASYNC_OP_E;
    }

    /* Setting scheduling parameter will fail for non root user,
     * as the default value of inheritsched is PTHREAD_EXPLICIT_SCHED in
     * POSIX. It is not required to set it explicitly before setting the
     * scheduling policy */

    /* Set scheduling policy based on values provided */
    if ((policy != SCHED_RR) &&
        (policy != SCHED_FIFO) &&
        (policy != SCHED_OTHER))
    {
        policy = SCHED_OTHER;
    }

    status = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    if (status != 0) {
        goto exit_fail;
    }

    status = pthread_attr_setschedpolicy(&attr, policy);
    if (status != 0) {
        goto exit_fail;
    }

    /* Set priority based on value in threadAttr */
    memset(&param, 0, sizeof(param));
    param.sched_priority = priority;
    if (policy != SCHED_OTHER) {
        status = pthread_attr_setschedparam(&attr, &param);
        if (status != 0) {
            goto exit_fail;
        }
    }

    status = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (status != 0) {
        goto exit_fail;
    }

    status = pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    if (status != 0) {
        goto exit_fail;
    }

    status = pthread_create(thread, &attr, function, params);
    if (status != 0) {
        goto exit_fail;
    }

    /*destroy the thread attributes as they are no longer required, this does
    * not affect the created thread*/
    status = pthread_attr_destroy(&attr);
    if (status != 0) {
        fprintf(stderr, "AsyncThreadCreate error: %d\n", status);
        return ASYNC_OP_E;
    } else {
        return 0;
    }

exit_fail:

    fprintf(stderr, "AsyncThreadCreate error: %d\n", status);
    status = pthread_attr_destroy(&attr);
    if (status != 0)
        fprintf(stderr, "AsyncThreadCreate cleanup error: %d\n", status);
    return ASYNC_OP_E;
}

int wc_AsyncThreadCreate(pthread_t *thread,
    AsyncThreadFunc_t function, void* params)
{
    return wc_AsyncThreadCreate_ex(thread, THREAD_DEFAULT_PRIORITY,
        THREAD_DEFAULT_POLICY, function, params);
}

#ifdef __MACH__
    #include <mach/mach.h>
    #include <mach/thread_policy.h>

    /* native MACH API wrappers */
    #define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"

    typedef struct cpu_set {
        uint32_t count;
    } cpu_set_t;

    static WC_INLINE void CPU_ZERO(cpu_set_t *cs) {
        cs->count = 0;
    }
    static WC_INLINE void CPU_SET(int num, cpu_set_t *cs) {
        cs->count |= (1 << num);
    }
    static WC_INLINE int CPU_ISSET(int num, cpu_set_t *cs) {
        return (cs->count & (1 << num));
    }

    static int pthread_setaffinity_np(pthread_t thread, size_t cpu_size,
                               cpu_set_t *cpu_set)
    {
        thread_port_t mach_thread;
        thread_affinity_policy_data_t policy;
        int core = 0;

        for (core = 0; core < 8 * (int)cpu_size; core++) {
            if (CPU_ISSET(core, cpu_set))
                break;
        }

        policy.affinity_tag = core;
        mach_thread = pthread_mach_thread_np(thread);
        thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
            (thread_policy_t)&policy, 1);

        return 0;
    }
#endif /* __MACH__ */

int wc_AsyncThreadBind(pthread_t *thread, word32 logicalCore)
{
    int status = 0;
    cpu_set_t cpuset;

    if (!thread) return BAD_FUNC_ARG;

    CPU_ZERO(&cpuset);
    CPU_SET(logicalCore, &cpuset);

    status = pthread_setaffinity_np(*thread, sizeof(cpu_set_t), &cpuset);
    if (status != 0) {
        fprintf(stderr, "pthread_setaffinity_np error: %d\n", status);
    }

    return status;
}

int wc_AsyncThreadStart(pthread_t *thread)
{
    (void)thread;
    return 0;
}

__attribute__((noreturn))
void wc_AsyncThreadExit(void *retval)
{
    pthread_exit(retval);
}

int wc_AsyncThreadKill(pthread_t *thread)
{
    int status;

    if (!thread) return BAD_FUNC_ARG;

    status = pthread_cancel(*thread);
    if (status != 0) {
        fprintf(stderr, "pthread_cancel fail with status %d\n", status);
    }

    return status;
}


int wc_AsyncThreadPrioritySet(pthread_t *thread, word32 priority)
{
    int status;
    struct sched_param param;
    int policy;
    word32 minPrio;
    word32 maxPrio;

    if (!thread) return BAD_FUNC_ARG;

    status = pthread_getschedparam(*thread, &policy, &param);
    if (status != 0) {
        fprintf(stderr, "pthread_getschedparam, failed with status %d\n",
            status);
        return status;
    }

    minPrio = sched_get_priority_min(policy);
    maxPrio =  sched_get_priority_max(policy);

    if ((priority < minPrio) || (priority > maxPrio)) {
        fprintf(stderr, "priority %u outside valid range\n", priority);
        return BAD_FUNC_ARG;
    }

    param.sched_priority = priority;

    status = pthread_setschedparam(*thread, policy, &param);
    if (status != 0) {
        fprintf(stderr, "pthread_setschedparam, failed with status %d\n",
            status);
        return status;
    }

    return status;
}

int wc_AsyncThreadSetPolicyAndPriority(pthread_t *thread, word32 policy,
    word32 priority)
{
    int status;
    struct sched_param  param;
    word32 minPrio, maxPrio;
    int policy1;

    if (!thread) return BAD_FUNC_ARG;

    /* check for a valid value for 'policy' */
    if ((policy != SCHED_RR) &&
        (policy != SCHED_FIFO) &&
        (policy != SCHED_OTHER))
    {
        fprintf(stderr, "wc_AsyncThreadSetPolicyAndPriority: "
            "invalid policy %u\n", policy);
        return BAD_FUNC_ARG;
    }

    memset(&param, 0, sizeof(param));

    status = pthread_getschedparam(*thread, &policy1, &param);
    if (status != 0) {
        fprintf(stderr, "pthread_getschedparam error: %d\n", status);
        return status;
    }

    minPrio = sched_get_priority_min(policy);
    maxPrio =  sched_get_priority_max(policy);

    if ((priority < minPrio) || (priority > maxPrio)) {
        return BAD_FUNC_ARG;
    }

    param.sched_priority = priority;

    status = pthread_setschedparam(*thread, policy, &param);
    if (status != 0) {
        fprintf(stderr, "pthread_setschedparam error: %d\n", status);
        return status;
    }

    return 0;
}

int wc_AsyncThreadJoin(pthread_t *thread)
{
    int status;
    status = pthread_join(*thread, NULL);
    if (status != 0) {
        fprintf(stderr, "pthread_join failed, status: %d\n", status);
    }
    return status;
}

void wc_AsyncThreadYield(void)
{
    sched_yield();
}

pthread_t wc_AsyncThreadId(void)
{
    return pthread_self();
}

#endif /* WC_NO_ASYNC_THREADING */

#endif /* WOLFSSL_ASYNC_CRYPT */
