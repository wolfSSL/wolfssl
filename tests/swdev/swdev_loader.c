/* tests/swdev/swdev_loader.c -- main-side loader for wc_swdev. */

#include "swdev_loader.h"

#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef WOLF_CRYPTO_CB
#error "wc_swdev loader requires WOLF_CRYPTO_CB"
#endif

/* resolved at link time from swdev.o */
extern int wc_SwDev_Callback(int devId, wc_CryptoInfo* info, void* ctx);

static int swdev_registered = 0;

int wc_SwDev_Init(void)
{
    int ret;

    /* always re-register: cryptocb table is wiped by wolfCrypt_Cleanup */
    ret = wc_CryptoCb_RegisterDevice(WC_SWDEV_ID, wc_SwDev_Callback, NULL);
    if (ret != 0)
        return ret;

#ifdef WOLF_CRYPTO_CB_FIND
    wc_CryptoCb_SetDeviceFindCb(wc_SwDev_FindCb);
#endif

    swdev_registered = 1;
    return 0;
}

void wc_SwDev_Cleanup(void)
{
    if (!swdev_registered)
        return;

#ifdef WOLF_CRYPTO_CB_FIND
    wc_CryptoCb_SetDeviceFindCb(NULL);
#endif

    wc_CryptoCb_UnRegisterDevice(WC_SWDEV_ID);
    swdev_registered = 0;
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
