/** @file
 * @brief wolfSSL initialization
 *
 * Initialize the wolfSSL library.
 */

#include <init.h>

#include "user_settings.h"
#include "wolfssl/ssl.h"

static int _wolfssl_init(struct device *device)
{
    ARG_UNUSED(device);

    return 0;
}

SYS_INIT(_wolfssl_init, POST_KERNEL, 0);
