/* swdev_loader.c
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

/* main-side loader for wc_swdev. */

#include "swdev_loader.h"

#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef WOLF_CRYPTO_CB
#error "wc_swdev loader requires WOLF_CRYPTO_CB"
#endif

/* resolved at link time from swdev.o */
extern int  wc_SwDev_Callback(int devId, wc_CryptoInfo* info, void* ctx);
extern void wc_SwDev_InternalCleanup(void);

/* Init always (re)registers because wolfCrypt_Cleanup wipes the cryptocb
 * table; only the final Cleanup unregisters. */
static wolfSSL_Atomic_Int swdev_refCount = WOLFSSL_ATOMIC_INITIALIZER(0);

int wc_SwDev_Init(void)
{
    int ret;

    ret = wc_CryptoCb_RegisterDevice(WC_SWDEV_ID, wc_SwDev_Callback, NULL);
    if (ret != 0)
        return ret;

#ifdef WOLF_CRYPTO_CB_FIND
    wc_CryptoCb_SetDeviceFindCb(wc_SwDev_FindCb);
#endif

    (void)wolfSSL_Atomic_Int_FetchAdd(&swdev_refCount, 1);
    return 0;
}

void wc_SwDev_Cleanup(void)
{
    int my_refCount = wolfSSL_Atomic_Int_SubFetch(&swdev_refCount, 1);

    if (my_refCount == 0) {
    #ifdef WOLF_CRYPTO_CB_FIND
        wc_CryptoCb_SetDeviceFindCb(NULL);
    #endif
        wc_CryptoCb_UnRegisterDevice(WC_SWDEV_ID);
        wc_SwDev_InternalCleanup();
    }
    else if (my_refCount < 0) {
        /* called more times than Init; restore floor */
        (void)wolfSSL_Atomic_Int_AddFetch(&swdev_refCount, 1);
    }
}

#ifdef WOLF_CRYPTO_CB_FIND
int wc_SwDev_FindCb(int currentId, int algoType)
{
    (void)algoType;

    /* only redirect ops with no bound device; let others pass through */
    if (currentId == INVALID_DEVID)
        return WC_SWDEV_ID;

    return currentId;
}
#endif
