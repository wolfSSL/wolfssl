/* tests/swdev/swdev_loader.h -- test harness interface to register wc_swdev. */

#ifndef WC_SWDEV_LOADER_H
#define WC_SWDEV_LOADER_H

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_SWDEV_ID 0x77736465 /* 'w' 's' 'd' 'e' */

int  wc_SwDev_Init(void);
void wc_SwDev_Cleanup(void);

#ifdef WOLF_CRYPTO_CB_FIND
int  wc_SwDev_FindCb(int currentId, int algoType);
#endif

#ifdef __cplusplus
}
#endif

#endif /* WC_SWDEV_LOADER_H */
