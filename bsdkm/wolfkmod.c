/* wolfkmod.c -- wolfssl FreeBSD kernel module.
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifdef WOLFSSL_BSDKM

/* freebsd system includes */
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>

/* wolf includes */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/version.h>
#else
    #include <wolfssl/ssl.h>
#endif
#if !defined(NO_CRYPT_TEST)
    #include <wolfcrypt/test/test.h>
#endif

MALLOC_DEFINE(M_WOLFSSL, "libwolfssl", "wolfSSL kernel memory");

static int wolfkmod_init(void);
static int wolfkmod_cleanup(void);
static int wolfkmod_load(void);
static int wolfkmod_unload(void);

static int wolfkmod_init(void)
{
    int ret = 0;

    #ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("error: wolfCrypt_Init failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
    #else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Init failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
    #endif

    return ret;
}

static int wolfkmod_cleanup(void)
{
    int ret = 0;

    #ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0) {
        printf("error: wolfCrypt_Cleanup failed: %s\n", wc_GetErrorString(ret));
    }
    else {
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("info: wolfCrypt " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    }
    #else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Cleanup failed: %s\n", wc_GetErrorString(ret));
    }
    else {
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("info: wolfSSL " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    }
    #endif

    return ret;
}

static int wolfkmod_load(void)
{
    int ret = 0;

    ret = wolfkmod_init();
    if (ret != 0) {
        return -ECANCELED;
    }

    #ifndef NO_CRYPT_TEST
    ret = wolfcrypt_test(NULL);
    if (ret != 0) {
        printf("error: wolfcrypt test failed with return code: %d\n", ret);
        (void)wolfkmod_cleanup();
        return -ECANCELED;
    }
    else {
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("wolfCrypt self-test passed.\n");
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    }
    #endif /* NO_CRYPT_TEST */

    /**
     * todo: register wolfcrypt algs here with crypto_get_driverid
     * and related.
     * */

    if (ret == 0) {
        printf("info: libwolfssl loaded\n");
    }

    return ret;
}

static int wolfkmod_unload(void)
{
    int ret = 0;

    ret = wolfkmod_cleanup();

    /**
     * todo: unregister wolfcrypt algs here with crypto_unregister_all
     * and related.
     * */

    if (ret == 0) {
        printf("info: libwolfssl unloaded\n");
    }

    return ret;
}

/* see /usr/include/sys/module.h for more info. */
static int
wolfkmod_event(struct module * m, int what, void * arg)
{
    int ret = 0;

    switch (what) {
    case MOD_LOAD:
        ret = wolfkmod_load();
        break;
    case MOD_UNLOAD:
        ret = wolfkmod_unload();
        break;
    case MOD_SHUTDOWN:
    case MOD_QUIESCE:
    default:
        #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
        printf("info: not implemented: %d\n", what);
        #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
        ret = EOPNOTSUPP;
    }

    (void)m;
    (void)arg;

    return ret;
}

static moduledata_t libwolfmod = {
    "libwolfssl",   /* module name */
    wolfkmod_event, /* module event handler */
    NULL            /* extra data, unused */
};

MODULE_VERSION(libwolfssl, 1);
DECLARE_MODULE(libwolfssl, libwolfmod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
#endif /* WOLFSSL_BSDKM */
