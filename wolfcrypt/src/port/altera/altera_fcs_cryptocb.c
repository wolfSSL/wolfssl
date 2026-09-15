/* altera_fcs_cryptocb.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_ALTERA_FCS

#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_ALTERA_FCS requires WOLF_CRYPTO_CB"
#endif
#ifndef WOLF_CRYPTO_CB_CMD
    #error "WOLFSSL_ALTERA_FCS requires WOLF_CRYPTO_CB_CMD for device setup"
#endif

static void wc_AlteraFcsCryptoCb_UnRegisterAll(void);

/* Set at registration; operations outside the mask are declined so wolfSSL
 * uses its software path. */
static word32 g_algoMask = WC_ALTERA_FCS_ALGO_ALL;
/* Mask requested by the registration in progress, read by the REGISTER
 * command handler. */
static word32 g_pendingMask = WC_ALTERA_FCS_ALGO_ALL;
static int    g_devId    = INVALID_DEVID;
static int    g_unregisterPending = 0;
static int    g_callbackCount = 0;
static int    g_resourceCount = 0;
static wolfSSL_Mutex g_stateLock;
static int    g_stateLockInit = 0;
#ifndef SINGLE_THREADED
static int    g_stateAtForkLocked = 0;
#endif

static int wc_AlteraFcs_StateInit(void)
{
    if (g_stateLockInit == 0) {
        if (wc_InitMutex(&g_stateLock) != 0) {
            return BAD_MUTEX_E;
        }
        g_stateLockInit = 1;
    }
    return 0;
}

static int wc_AlteraFcs_CallbackBegin(word32* algoMask)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    if (g_stateLockInit == 0 || wc_LockMutex(&g_stateLock) != 0) {
        return ret;
    }
    if (g_devId == WOLFSSL_ALTERA_FCS_DEVID &&
        (!g_unregisterPending || g_resourceCount > 0)) {
        g_callbackCount++;
        *algoMask = g_algoMask;
        ret = 0;
    }
    wc_UnLockMutex(&g_stateLock);
    return ret;
}

static void wc_AlteraFcs_CallbackEnd(void)
{
    int finish = 0;

    if (g_stateLockInit == 0 || wc_LockMutex(&g_stateLock) != 0) {
        return;
    }
    if (g_callbackCount > 0) {
        g_callbackCount--;
    }
    if (g_callbackCount == 0 && g_resourceCount == 0 &&
        g_unregisterPending && g_devId != INVALID_DEVID) {
        finish = 1;
    }
    wc_UnLockMutex(&g_stateLock);
    if (finish) {
        wc_AlteraFcsCryptoCb_UnRegisterAll();
    }
}

int wc_AlteraFcs_UnregisterPending(void)
{
    int pending = 0;

    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        pending = g_unregisterPending;
        wc_UnLockMutex(&g_stateLock);
    }
    return pending;
}

int wc_AlteraFcs_RegisterActive(void)
{
    int active = 0;

    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        active = (g_devId == WOLFSSL_ALTERA_FCS_DEVID &&
                  !g_unregisterPending);
        wc_UnLockMutex(&g_stateLock);
    }
    return active;
}

/* Device setup for the REGISTER command, so a failure unwinds the
 * registration inside wc_CryptoCb_RegisterDevice() itself. */
static int wc_AlteraFcsCryptoCb_Register(int devId)
{
    int ret;

    ret = wc_AlteraFcs_Init();
    if (ret != 0) {
        /* The framework reads "unavailable" as "not implemented" and would
         * register anyway, so an absent device has to be a hard error here. */
        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE) ||
            ret == WC_NO_ERR_TRACE(NOT_COMPILED_IN)) {
            ret = WC_HW_E;
        }
        return ret;
    }
    if (wc_LockMutex(&g_stateLock) != 0) {
        (void)wc_AlteraFcs_Cleanup();
        return BAD_MUTEX_E;
    }
    g_algoMask = g_pendingMask;
    g_devId = devId;
    g_unregisterPending = 0;
    wc_UnLockMutex(&g_stateLock);
    return 0;
}

#ifdef WOLFSSL_ALTERA_FCS_AES
/* The key generation id accepts one request, an AES SETKEY with a NULL key.
 * Anything else on it is a caller error and must not quietly do something
 * else. Free and copy are declined so wolfSSL runs its own teardown. */
static int wc_AlteraFcsCryptoDevCbKeyGen(wc_CryptoInfo* info)
{
    int ret = WC_HW_E;

    switch (info->algo_type) {
        case WC_ALGO_TYPE_SETKEY:
            ret = wc_AlteraFcs_Aes(info);
            break;
        case WC_ALGO_TYPE_FREE:
        case WC_ALGO_TYPE_COPY:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    #ifdef WOLF_CRYPTO_CB_AES_SETKEY
        case WC_ALGO_TYPE_CIPHER:
            /* The per-algorithm key setup runs ahead of SETKEY and must be
             * declined for the NULL key request to reach it. */
            if (info->cipher.type == WC_CIPHER_AES) {
                ret = CRYPTOCB_UNAVAILABLE;
            }
            break;
    #endif
        default:
            WOLFSSL_MSG("Altera FCS AES key devId only generates keys");
            break;
    }
    return ret;
}
#endif

/* Dispatcher. Returning CRYPTOCB_UNAVAILABLE lets wolfCrypt fall back to
 * software, which is the required behaviour whenever the SDM is busy: the one
 * chip-wide session means a hard failure here would stall unrelated callers. */
static int wc_AlteraFcsCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;
    word32 algoMask;

    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB_CMD
    if (info->algo_type == WC_ALGO_TYPE_NONE) {
        if (info->cmd.type == WC_CRYPTOCB_CMD_TYPE_UNREGISTER) {
            return wc_AlteraFcsCryptoCb_UnRegisterDeviceEx(devId);
        }
        if (info->cmd.type == WC_CRYPTOCB_CMD_TYPE_REGISTER &&
            devId == WOLFSSL_ALTERA_FCS_DEVID) {
            return wc_AlteraFcsCryptoCb_Register(devId);
        }
        return CRYPTOCB_UNAVAILABLE;
    }
#endif

    if (wc_AlteraFcs_CallbackBegin(&algoMask) != 0) {
        return ret;
    }

#ifdef WOLFSSL_ALTERA_FCS_AES
    if (devId == WOLFSSL_ALTERA_FCS_AES_KEY_DEVID) {
        ret = wc_AlteraFcsCryptoDevCbKeyGen(info);
        wc_AlteraFcs_CallbackEnd();
        return ret;
    }
#endif

    switch (info->algo_type) {
        case WC_ALGO_TYPE_SEED:
        case WC_ALGO_TYPE_RNG:
        #ifdef WOLFSSL_ALTERA_FCS_RNG
            if (algoMask & WC_ALTERA_FCS_ALGO_RNG) {
                ret = wc_AlteraFcs_Rng(info);
            }
        #endif
            break;
        case WC_ALGO_TYPE_HASH:
        #ifdef WOLFSSL_ALTERA_FCS_HASH
            if (algoMask & WC_ALTERA_FCS_ALGO_HASH) {
                ret = wc_AlteraFcs_Hash(info);
            }
        #endif
            break;
        case WC_ALGO_TYPE_COPY:
        #ifdef WOLFSSL_ALTERA_FCS_HASH
            if (info->copy.algo == WC_ALGO_TYPE_HASH) {
                ret = wc_AlteraFcs_Hash(info);
            }
        #endif
            break;
        case WC_ALGO_TYPE_FREE:
        #ifdef WOLFSSL_ALTERA_FCS_HASH
            if (info->free.algo == WC_ALGO_TYPE_HASH) {
                ret = wc_AlteraFcs_Hash(info);
            }
        #endif
        #ifdef WOLFSSL_ALTERA_FCS_AES
            if (info->free.algo == WC_ALGO_TYPE_CIPHER) {
                ret = wc_AlteraFcs_Aes(info);
            }
        #endif
        #ifdef WC_ALTERA_FCS_HAVE_ECC
            if (info->free.algo == WC_ALGO_TYPE_PK) {
                ret = wc_AlteraFcs_Ecc(info);
            }
        #endif
            break;
        #ifdef WOLFSSL_ALTERA_FCS_AES
        case WC_ALGO_TYPE_SETKEY:
            ret = wc_AlteraFcs_Aes(info);
            break;
        #endif
        case WC_ALGO_TYPE_CIPHER:
        #ifdef WOLFSSL_ALTERA_FCS_AES
            if (algoMask & WC_ALTERA_FCS_ALGO_AES) {
                ret = wc_AlteraFcs_Aes(info);
            }
        #endif
            break;
        case WC_ALGO_TYPE_PK:
        #ifdef WC_ALTERA_FCS_HAVE_ECC
            if (algoMask & WC_ALTERA_FCS_ALGO_ECC) {
                ret = wc_AlteraFcs_Ecc(info);
            }
        #endif
            break;
        case WC_ALGO_TYPE_KDF:    /* step 6: hkdf             */
        case WC_ALGO_TYPE_HMAC:   /* step 7: mac_verify       */
        default:
            break;
    }

    wc_AlteraFcs_CallbackEnd();
    return ret;
}

/* Both ids are dropped together; the framework clears the key generation
 * slot silently since its UNREGISTER handler has nothing to release. */
static void wc_AlteraFcsCryptoCb_UnRegisterAll(void)
{
#ifdef WOLFSSL_ALTERA_FCS_AES
    wc_CryptoCb_UnRegisterDevice(WOLFSSL_ALTERA_FCS_AES_KEY_DEVID);
#endif
    wc_CryptoCb_UnRegisterDevice(WOLFSSL_ALTERA_FCS_DEVID);
}

int wc_AlteraFcsCryptoCb_RegisterDeviceMask(int devId, word32 algoMask)
{
    int ret;
    int wasPending;

    if (devId != WOLFSSL_ALTERA_FCS_DEVID ||
        (algoMask & ~WC_ALTERA_FCS_ALGO_ALL) != 0) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AlteraFcs_StateInit();
    if (ret != 0) {
        return ret;
    }
    if (wc_LockMutex(&g_stateLock) != 0) {
        return BAD_MUTEX_E;
    }
    wasPending = g_unregisterPending;
    if (g_devId != INVALID_DEVID && !wasPending &&
        algoMask != g_algoMask) {
        wc_UnLockMutex(&g_stateLock);
        return ALREADY_E;
    }
    if (wasPending && (g_resourceCount != 0 || g_callbackCount != 0)) {
        wc_UnLockMutex(&g_stateLock);
        return BUSY_E;
    }
    g_pendingMask = algoMask;
    wc_UnLockMutex(&g_stateLock);

    /* The REGISTER command brings the device up and records the mask. A
     * deferred unregister keeps the slot, so ALREADY_E there means the
     * callback is still registered and only the state needs reviving. */
    ret = wc_CryptoCb_RegisterDevice(devId, wc_AlteraFcsCryptoDevCb, NULL);
    if (ret == ALREADY_E) {
        if (wc_LockMutex(&g_stateLock) != 0) {
            return BAD_MUTEX_E;
        }
        if (g_devId == devId || wasPending) {
            g_algoMask = algoMask;
            g_devId = devId;
            g_unregisterPending = 0;
            ret = 0;
        }
        wc_UnLockMutex(&g_stateLock);
    }
#ifdef WOLFSSL_ALTERA_FCS_AES
    if (ret == 0 && (algoMask & WC_ALTERA_FCS_ALGO_AES) != 0) {
        ret = wc_CryptoCb_RegisterDevice(WOLFSSL_ALTERA_FCS_AES_KEY_DEVID,
                                         wc_AlteraFcsCryptoDevCb, NULL);
        if (ret == ALREADY_E) {
            ret = 0;
        }
        if (ret != 0) {
            wc_AlteraFcsCryptoCb_UnRegisterAll();
        }
    }
#endif
    return ret;
}

int wc_AlteraFcsCryptoCb_RegisterDevice(int devId)
{
    return wc_AlteraFcsCryptoCb_RegisterDeviceMask(devId,
                                                   WC_ALTERA_FCS_ALGO_ALL);
}

int wc_AlteraFcsCryptoCb_UnRegisterDeviceEx(int devId)
{
    int ret;

    if (g_stateLockInit == 0) {
        return 0;
    }
    /* The key generation id owns no device state of its own. */
    if (devId == WOLFSSL_ALTERA_FCS_AES_KEY_DEVID) {
        return 0;
    }
    if (wc_LockMutex(&g_stateLock) != 0) {
        return BAD_MUTEX_E;
    }
    if (devId != g_devId) {
        wc_UnLockMutex(&g_stateLock);
        return 0;
    }
    g_unregisterPending = 1;
    if (g_resourceCount != 0 || g_callbackCount != 0) {
        WOLFSSL_MSG("Altera FCS unregister deferred by active resource");
        wc_UnLockMutex(&g_stateLock);
        return BUSY_E;
    }

    /* Pending prevents new admission while cleanup closes the session. The
     * generic registry clears its slot only after this callback reports
     * success, so a caller that already looked up the callback is also forced
     * through the same admission check. */
    ret = wc_AlteraFcs_Cleanup();
    if (ret != 0) {
        wc_UnLockMutex(&g_stateLock);
        return ret;
    }
    g_devId = INVALID_DEVID;
    g_algoMask = WC_ALTERA_FCS_ALGO_ALL;
    wc_UnLockMutex(&g_stateLock);
    return 0;
}

void wc_AlteraFcsCryptoCb_UnRegisterDevice(int devId)
{
    if (devId == WOLFSSL_ALTERA_FCS_DEVID) {
        wc_AlteraFcsCryptoCb_UnRegisterAll();
    }
    else {
        wc_CryptoCb_UnRegisterDevice(devId);
    }
}

void wc_AlteraFcsCryptoCb_UnRegisterPending(void)
{
    int finish = 0;

    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        finish = (g_devId != INVALID_DEVID && g_unregisterPending &&
                  g_resourceCount == 0 && g_callbackCount == 0);
        wc_UnLockMutex(&g_stateLock);
    }
    if (finish) {
        wc_AlteraFcsCryptoCb_UnRegisterAll();
    }
}

int wc_AlteraFcs_AlgoEnabled(word32 algoMask)
{
    int enabled = 0;

    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        enabled = (g_devId == WOLFSSL_ALTERA_FCS_DEVID &&
                   !g_unregisterPending &&
                   (g_algoMask & algoMask) == algoMask);
        wc_UnLockMutex(&g_stateLock);
    }
    return enabled;
}

void wc_AlteraFcs_ResourceAdd(void)
{
    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        g_resourceCount++;
        wc_UnLockMutex(&g_stateLock);
    }
}

int wc_AlteraFcs_ResourceAcquire(void)
{
    int ret = BUSY_E;

    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        if (g_devId == WOLFSSL_ALTERA_FCS_DEVID &&
            !g_unregisterPending) {
            g_resourceCount++;
            ret = 0;
        }
        wc_UnLockMutex(&g_stateLock);
    }
    return ret;
}

void wc_AlteraFcs_ResourceRemove(void)
{
    int finish = 0;

    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        if (g_resourceCount > 0) {
            g_resourceCount--;
        }
        if (g_resourceCount == 0 && g_callbackCount == 0 &&
            g_unregisterPending && g_devId != INVALID_DEVID) {
            finish = 1;
        }
        wc_UnLockMutex(&g_stateLock);
    }
    if (finish) {
        wc_AlteraFcsCryptoCb_UnRegisterAll();
    }
}

void wc_AlteraFcs_StateAtForkPrepare(void)
{
#ifndef SINGLE_THREADED
    if (g_stateLockInit != 0 && wc_LockMutex(&g_stateLock) == 0) {
        g_stateAtForkLocked = 1;
    }
#endif
}

void wc_AlteraFcs_StateAtForkParent(void)
{
#ifndef SINGLE_THREADED
    if (g_stateAtForkLocked) {
        g_stateAtForkLocked = 0;
        wc_UnLockMutex(&g_stateLock);
    }
#endif
}

void wc_AlteraFcs_StateAtForkChild(void)
{
#ifndef SINGLE_THREADED
    if (g_stateAtForkLocked) {
        g_stateAtForkLocked = 0;
        wc_UnLockMutex(&g_stateLock);
    }
#endif
}

void wc_AlteraFcs_StateForkChildReset(void)
{
    g_callbackCount = 0;
    g_resourceCount = 0;
    g_unregisterPending = 0;
}

#endif /* WOLFSSL_ALTERA_FCS */
