/* altera_fcs_glue.c
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

/* Session management for the Agilex 5 Secure Device Manager, via libfcs.
 *
 * The SDM grants only a handful of crypto sessions and a leaked one cannot be
 * reclaimed without a board power cycle, so this file keeps exactly one session
 * for the life of the process, reference counted, and closes it from an atexit
 * handler as well as the normal path.
 *
 * A file lock guards the session across processes: the kernel driver serialises
 * on a single global context (hal_get_fcs_cmd_ctx) with an uninterruptible
 * mutex, so a second process entering at the wrong moment blocks unkillably.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_ALTERA_FCS

#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <libfcs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/file.h>
#include <errno.h>
#ifndef SINGLE_THREADED
    #include <pthread.h>
#endif

#ifndef WOLFSSL_ALTERA_FCS_LOCKFILE
    #define WOLFSSL_ALTERA_FCS_LOCKFILE "/sys/kernel/fcs_sysfs"
#endif
#ifndef WOLFSSL_ALTERA_FCS_LOCK_OPEN_FLAGS
    #define WOLFSSL_ALTERA_FCS_LOCK_OPEN_FLAGS \
        (O_RDONLY | O_DIRECTORY | O_CLOEXEC)
#endif

/* FCS_OSAL_UUID is a plain char, so a session id is a 16 byte buffer the
 * library writes into, never a scalar. */
static FCS_OSAL_UUID g_sessionId[FCS_OSAL_UUID_SIZE];
/* The device grants exactly one session, so it is opened on first use and held
 * until cleanup. Releasing the last reference must NOT close it: a re-open
 * would be refused with 0x84 and every later request would fall back to
 * software. */
static int  g_sessionOpen = 0;
static int  g_refCount   = 0;
static int  g_cleanupPending = 0;
static int  g_libReady   = 0;
static int  g_atexitDone = 0;
static int  g_lockFd     = -1;
static pid_t g_ownerPid  = 0;
static pid_t g_processPid = 0;
static int  g_forkChild = 0;
static wolfSSL_Mutex g_lock;
static int  g_lockInit   = 0;
#ifndef SINGLE_THREADED
static int  g_atforkDone = 0;
static int  g_atforkLocked = 0;
#endif
static wolfSSL_Atomic_Int g_testHwOperations = 0;
#define WC_ALTERA_FCS_ORPHAN_MAX 32
static word32 g_orphanKeys[WC_ALTERA_FCS_ORPHAN_MAX];
static int g_orphanRetrying = 0;
/* Status 0x85 means the device is not provisioned for crypto services, which
 * cannot change while the process runs. Remembering it keeps every later
 * fallback from paying for a mailbox round trip first. */
static int  g_sessionDenied = 0;
/* Key ids only have to be unique within the session, and the session is
 * process wide, so a counter is enough. Zero is rejected by the device. */
static word32 g_nextKeyId = WOLFSSL_ALTERA_FCS_KEY_ID_BASE;

static void wc_AlteraFcs_AtExit(void)
{
    (void)wc_AlteraFcs_Cleanup();
}

static void wc_AlteraFcs_ResetForkChild(void)
{
    if (g_lockFd >= 0) {
        (void)close(g_lockFd);
        g_lockFd = -1;
    }
    XMEMSET(g_sessionId, 0, sizeof(g_sessionId));
    g_sessionOpen = 0;
    g_refCount = 0;
    g_cleanupPending = 0;
    g_ownerPid = 0;
    g_processPid = 0;
    g_forkChild = 1;
    g_libReady = 0;
    g_sessionDenied = 0;
    XMEMSET(g_orphanKeys, 0, sizeof(g_orphanKeys));
    g_orphanRetrying = 0;
    wc_AlteraFcs_StateForkChildReset();
}

#ifndef SINGLE_THREADED
static void wc_AlteraFcs_AtForkPrepare(void)
{
    wc_AlteraFcs_StateAtForkPrepare();
    if (g_lockInit && wc_LockMutex(&g_lock) == 0) {
        g_atforkLocked = 1;
    }
}

static void wc_AlteraFcs_AtForkParent(void)
{
    if (g_atforkLocked) {
        g_atforkLocked = 0;
        wc_UnLockMutex(&g_lock);
    }
    wc_AlteraFcs_StateAtForkParent();
}

static void wc_AlteraFcs_AtForkChild(void)
{
    wc_AlteraFcs_ResetForkChild();
    if (g_atforkLocked) {
        g_atforkLocked = 0;
        wc_UnLockMutex(&g_lock);
    }
    wc_AlteraFcs_StateAtForkChild();
}
#endif

/* Translate a libfcs return into a wolfCrypt error. libfcs returns negative
 * errno values for transport problems and positive SDM status codes for device
 * refusals; both must stay distinguishable so callers can decide whether to
 * fall back to software. */
int wc_AlteraFcs_MapError(int fcsRet)
{
    int ret;

    if (fcsRet == 0) {
        return 0;
    }

    switch (fcsRet) {
        case 0x84:  /* no more sessions may be opened */
        case 0x1FF: /* device busy */
        case -EAGAIN:
        case -EBUSY:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        case 0x85:  /* not allowed under current security settings */
        case -EACCES:
        case -EPERM:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        case 0x0F:  /* function not supported on this device */
        case -ENOTSUP:
        case -ENXIO:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        case 0x04:  /* invalid command parameters */
        case 0x06:
        case 0x81:  /* cryptographic parameter error */
        case 0x86:  /* invalid context id */
        case -EINVAL:
            ret = BAD_FUNC_ARG;
            break;
        case 0x83:  /* invalid session id */
            ret = WC_HW_E;
            break;
        case -ETIMEDOUT:
            ret = WC_HW_E;
            break;
        default:
            ret = WC_HW_E;
            break;
    }

    WOLFSSL_MSG_EX("Altera FCS error %d mapped to %d", fcsRet, ret);
    return ret;
}

int wc_AlteraFcs_Init(void)
{
    int ret = 0;

    if (g_processPid != 0 && g_processPid != getpid()) {
        wc_AlteraFcs_ResetForkChild();
    }
    /* Session-scoped ECC and HMAC handles cannot be reconstructed safely in
     * an inherited process. The child may use software, or exec a fresh image
     * to initialize an independent FCS process state. */
    if (g_forkChild) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (g_lockInit == 0) {
        if (wc_InitMutex(&g_lock) != 0) {
            return BAD_MUTEX_E;
        }
        g_lockInit = 1;
    }

#ifndef SINGLE_THREADED
    if (g_atforkDone == 0) {
        if (pthread_atfork(wc_AlteraFcs_AtForkPrepare,
                           wc_AlteraFcs_AtForkParent,
                           wc_AlteraFcs_AtForkChild) != 0) {
            return WC_INIT_E;
        }
        g_atforkDone = 1;
    }
#endif

    if (wc_LockMutex(&g_lock) != 0) {
        return BAD_MUTEX_E;
    }

    if (g_libReady == 0) {
        ret = libfcs_init((FCS_OSAL_CHAR*)"error");
        if (ret != 0) {
            WOLFSSL_MSG("libfcs_init failed");
            ret = wc_AlteraFcs_MapError(ret);
        }
        else {
            g_libReady = 1;
            g_processPid = getpid();
        }
    }

    if (ret == 0 && g_atexitDone == 0) {
        if (atexit(wc_AlteraFcs_AtExit) == 0) {
            g_atexitDone = 1;
        }
    }

    wc_UnLockMutex(&g_lock);
    return ret;
}

/* Acquire the process wide session, opening it on first use. On success
 * *sessionId points at the 16 byte session id and the caller must pair this
 * with wc_AlteraFcs_SessionRelease(). */
int wc_AlteraFcs_SessionAcquire(void** sessionId)
{
    int ret = 0;

    if (sessionId == NULL) {
        return BAD_FUNC_ARG;
    }

    /* pthread_atfork protects threaded builds from inheriting a locked mutex.
     * The PID check also covers SINGLE_THREADED builds. */
    if (g_ownerPid != 0 && g_ownerPid != getpid()) {
        wc_AlteraFcs_ResetForkChild();
    }

    ret = wc_AlteraFcs_Init();
    if (ret != 0) {
        return ret;
    }

    if (wc_LockMutex(&g_lock) != 0) {
        return BAD_MUTEX_E;
    }

    if (g_sessionDenied) {
        wc_UnLockMutex(&g_lock);
        return CRYPTOCB_UNAVAILABLE;
    }

    if (g_sessionOpen == 0) {
        if (g_lockFd < 0) {
            g_lockFd = open(WOLFSSL_ALTERA_FCS_LOCKFILE,
                            WOLFSSL_ALTERA_FCS_LOCK_OPEN_FLAGS);
        }
        /* Fail closed, and never block: the driver serialises on one
         * uninterruptible global mutex, so entering it unlocked can wedge
         * unrelated processes, while waiting here would stall this one behind
         * whoever holds the lock. Declining lets wolfSSL use software. */
        if (g_lockFd < 0 || flock(g_lockFd, LOCK_EX | LOCK_NB) != 0) {
            WOLFSSL_MSG("Altera FCS cross-process lock unavailable");
            if (g_lockFd >= 0) {
                (void)close(g_lockFd);
                g_lockFd = -1;
            }
            wc_UnLockMutex(&g_lock);
            return CRYPTOCB_UNAVAILABLE;
        }

        ret = fcs_open_service_session(g_sessionId);
        if (ret != 0) {
            WOLFSSL_MSG("fcs_open_service_session failed");
            if (ret == 0x85) {
                g_sessionDenied = 1;
            }
            if (g_lockFd >= 0) {
                (void)flock(g_lockFd, LOCK_UN);
                (void)close(g_lockFd);
                g_lockFd = -1;
            }
            XMEMSET(g_sessionId, 0, sizeof(g_sessionId));
            ret = wc_AlteraFcs_MapError(ret);
        }
        else {
            g_sessionOpen = 1;
            g_ownerPid = getpid();
        }
    }

    if (ret == 0) {
        g_refCount++;
        *sessionId = (void*)g_sessionId;
    }

    wc_UnLockMutex(&g_lock);
    return ret;
}

int wc_AlteraFcs_KeyIdNew(word32* keyId)
{
    int ret;

    if (keyId == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AlteraFcs_OrphanKey(0);
    if (ret != 0) {
        return ret;
    }
    if (g_lockInit == 0) {
        return BAD_MUTEX_E;
    }
    if (wc_LockMutex(&g_lock) != 0) {
        return BAD_MUTEX_E;
    }

    *keyId = g_nextKeyId++;
    if (g_nextKeyId == 0) {
        g_nextKeyId = WOLFSSL_ALTERA_FCS_KEY_ID_BASE;
    }

    wc_UnLockMutex(&g_lock);
    return 0;
}

int wc_AlteraFcs_RemoveServiceKey(word32 keyId)
{
    void* session = NULL;
    int   ret;

    if (keyId == 0) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret != 0) {
        return ret;
    }
    ret = fcs_remove_service_key((FCS_OSAL_UUID*)session,
                                 (FCS_OSAL_U32)keyId);
    wc_AlteraFcs_SessionRelease();
    if (ret != 0) {
        WOLFSSL_MSG("Altera FCS service key removal failed");
        ret = wc_AlteraFcs_MapError(ret);
    }
    return ret;
}

/* keyId == 0 retries every orphan before a new key is allocated. A teardown
 * failure records the otherwise unreachable handle here; confirmed session
 * close reclaims all such slots even if individual deletion keeps failing. */
int wc_AlteraFcs_OrphanKey(word32 keyId)
{
    word32 retry[WC_ALTERA_FCS_ORPHAN_MAX];
    int count = 0;
    int firstErr = 0;
    int i;

    if (g_lockInit == 0 || wc_LockMutex(&g_lock) != 0) {
        return BAD_MUTEX_E;
    }
    if (keyId != 0) {
        for (i = 0; i < WC_ALTERA_FCS_ORPHAN_MAX; i++) {
            if (g_orphanKeys[i] == keyId) {
                wc_UnLockMutex(&g_lock);
                return 0;
            }
            if (g_orphanKeys[i] == 0) {
                g_orphanKeys[i] = keyId;
                wc_UnLockMutex(&g_lock);
                return 0;
            }
        }
        wc_UnLockMutex(&g_lock);
        return MEMORY_E;
    }
    if (g_orphanRetrying) {
        wc_UnLockMutex(&g_lock);
        return 0;
    }
    g_orphanRetrying = 1;
    for (i = 0; i < WC_ALTERA_FCS_ORPHAN_MAX; i++) {
        if (g_orphanKeys[i] != 0) {
            retry[count++] = g_orphanKeys[i];
        }
    }
    wc_UnLockMutex(&g_lock);

    for (i = 0; i < count; i++) {
        int ret = wc_AlteraFcs_RemoveServiceKey(retry[i]);

        if (ret == 0) {
            int j;
            if (wc_LockMutex(&g_lock) == 0) {
                for (j = 0; j < WC_ALTERA_FCS_ORPHAN_MAX; j++) {
                    if (g_orphanKeys[j] == retry[i]) {
                        g_orphanKeys[j] = 0;
                        break;
                    }
                }
                wc_UnLockMutex(&g_lock);
            }
        }
        else if (firstErr == 0) {
            firstErr = ret;
        }
    }

    if (wc_LockMutex(&g_lock) == 0) {
        g_orphanRetrying = 0;
        wc_UnLockMutex(&g_lock);
    }
    return firstErr;
}

void wc_AlteraFcs_DiscardServiceKey(word32 keyId)
{
    if (wc_AlteraFcs_RemoveServiceKey(keyId) != 0) {
        (void)wc_AlteraFcs_OrphanKey(keyId);
    }
}

int wc_AlteraFcs_HardwareAvailable(void)
{
    void* session = NULL;
    int ret;

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret == 0) {
        wc_AlteraFcs_SessionRelease();
    }
    return (ret == 0);
}

void wc_AlteraFcs_TestHwReset(void)
{
    int operations = wolfSSL_Atomic_Int_FetchAdd(&g_testHwOperations, 0);

    if (operations != 0)
        (void)wolfSSL_Atomic_Int_FetchSub(&g_testHwOperations, operations);
}

word32 wc_AlteraFcs_TestHwGet(void)
{
    return (word32)wolfSSL_Atomic_Int_FetchAdd(&g_testHwOperations, 0);
}

void wc_AlteraFcs_TestHwMark(word32 operation)
{
    int old;

    do {
        old = wolfSSL_Atomic_Int_FetchAdd(&g_testHwOperations, 0);
        if ((old & (int)operation) != 0)
            return;
    } while (!wolfSSL_Atomic_Int_CompareExchange(&g_testHwOperations, &old,
                                                  old | (int)operation));
}

static int wc_AlteraFcs_CloseLocked(void)
{
    int ret = 0;

    if (g_sessionOpen != 0) {
        if (fcs_close_service_session(g_sessionId) != 0) {
            WOLFSSL_MSG("fcs_close_service_session failed; retry required");
            g_cleanupPending = 1;
            return WC_HW_E;
        }
        g_sessionOpen = 0;
    }

    XMEMSET(g_sessionId, 0, sizeof(g_sessionId));
    XMEMSET(g_orphanKeys, 0, sizeof(g_orphanKeys));
    g_orphanRetrying = 0;
    g_cleanupPending = 0;
    g_ownerPid = 0;
    if (g_lockFd >= 0) {
        (void)flock(g_lockFd, LOCK_UN);
        (void)close(g_lockFd);
        g_lockFd = -1;
    }
    g_libReady = 0;
    g_sessionDenied = 0;
    return ret;
}

void wc_AlteraFcs_SessionRelease(void)
{
    int cleanupDone = 0;

    if (g_lockInit == 0) {
        return;
    }
    if (wc_LockMutex(&g_lock) != 0) {
        return;
    }

    if (g_refCount > 0) {
        g_refCount--;
    }
    if (g_refCount == 0 && g_cleanupPending) {
        cleanupDone = (wc_AlteraFcs_CloseLocked() == 0);
    }

    wc_UnLockMutex(&g_lock);
    if (cleanupDone) {
        wc_AlteraFcsCryptoCb_UnRegisterPending();
    }
}

int wc_AlteraFcs_Cleanup(void)
{
    int ret;

    if (g_lockInit == 0) {
        return 0;
    }
    if (wc_LockMutex(&g_lock) != 0) {
        return BAD_MUTEX_E;
    }

    /* A child owns only duplicated descriptors. It must never close the
     * parent's device session or explicitly release the shared flock. */
    if (g_ownerPid != 0 && g_ownerPid != getpid()) {
        if (g_lockFd >= 0) {
            (void)close(g_lockFd);
            g_lockFd = -1;
        }
        g_sessionOpen = 0;
        g_refCount = 0;
        g_cleanupPending = 0;
        g_ownerPid = 0;
        g_libReady = 0;
        XMEMSET(g_sessionId, 0, sizeof(g_sessionId));
        XMEMSET(g_orphanKeys, 0, sizeof(g_orphanKeys));
        wc_UnLockMutex(&g_lock);
        return 0;
    }

    if (g_refCount != 0) {
        g_cleanupPending = 1;
        wc_UnLockMutex(&g_lock);
        return BUSY_E;
    }

    ret = wc_AlteraFcs_CloseLocked();
    wc_UnLockMutex(&g_lock);
    return ret;
}

#endif /* WOLFSSL_ALTERA_FCS */
