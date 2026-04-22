/* tests/swdev/swdev.c -- wc_swdev callback. */

#include "swdev.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

static int swdev_initialized = 0;

static int swdev_ensure_init(void)
{
    if (!swdev_initialized) {
        int ret = wolfCrypt_Init();
        if (ret != 0)
            return ret;
        swdev_initialized = 1;
    }
    return 0;
}

WC_SWDEV_EXPORT int wc_SwDev_Callback(int devId, wc_CryptoInfo* info,
    void* ctx)
{
    int ret;

    (void)devId;
    (void)ctx;

    if (info == NULL)
        return BAD_FUNC_ARG;

    ret = swdev_ensure_init();
    if (ret != 0)
        return ret;

    (void)ret;
    return CRYPTOCB_UNAVAILABLE;
}
