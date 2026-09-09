/* zephyr_init.c
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

/* Only a port that brings up a peripheral needs a boot-time hook. */

#ifdef CONFIG_WOLFSSL_SYS_INIT

#include <errno.h>

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include <wolfssl/wolfcrypt/settings.h>
#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/wolfcrypt/wc_port.h>
#else
    #include <wolfssl/ssl.h>
#endif

LOG_MODULE_REGISTER(wolfssl, CONFIG_WOLFSSL_LOG_LEVEL);

static int wolfssl_module_init(void)
{
    int ret;

    /* Zephyr hands a non-device SYS_INIT return only to a trace hook, so the
     * failure would otherwise leave no evidence. */
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        LOG_ERR("wolfCrypt_Init failed: %d", ret);
        return -EIO;
    }
#else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        LOG_ERR("wolfSSL_Init failed: %d", ret);
        return -EIO;
    }
#endif

    return 0;
}

/* POST_KERNEL because initialization takes mutexes and may allocate, late
 * within it because a port needs the SoC and clock init that runs there. */
SYS_INIT(wolfssl_module_init, POST_KERNEL, 99);

#endif /* CONFIG_WOLFSSL_SYS_INIT */
