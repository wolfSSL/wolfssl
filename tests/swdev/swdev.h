/* tests/swdev/swdev.h -- sole exported interface. */

#ifndef WC_SWDEV_H
#define WC_SWDEV_H

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_SWDEV_ID 0x77736465 /* 'w' 's' 'd' 'e' */

#if defined(__GNUC__) || defined(__clang__)
#define WC_SWDEV_EXPORT __attribute__((visibility("default")))
#else
#define WC_SWDEV_EXPORT
#endif

WC_SWDEV_EXPORT int wc_SwDev_Callback(int devId, wc_CryptoInfo* info,
    void* ctx);

#ifdef __cplusplus
}
#endif

#endif /* WC_SWDEV_H */
