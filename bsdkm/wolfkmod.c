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

#ifdef HAVE_FIPS
    #ifdef USE_CONTESTMUTEX
        #error USE_CONTESTMUTEX is incompatible with WOLFSSL_BSDKM
    #endif
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif /* HAVE_FIPS */

#if !defined(NO_CRYPT_TEST)
    #include <wolfcrypt/test/test.h>
#endif

#include <wolfssl/wolfcrypt/random.h>

MALLOC_DEFINE(M_WOLFSSL, "libwolfssl", "wolfSSL kernel memory");

static int wolfkmod_init(void);
static int wolfkmod_cleanup(void);
static int wolfkmod_load(void);
static int wolfkmod_unload(void);

#ifdef HAVE_FIPS
    #define WOLFKMOD_FIPS_ERR_MSG(hash) ({                                   \
        printf("In-core integrity hash check failure.\n");                   \
        if ((hash))                                                          \
            printf("Rebuild with \"WOLFCRYPT_FIPS_CORE_HASH_VALUE=%s\".\n",  \
                   hash);                                                    \
        else                                                                 \
            printf("error: could not compute new hash. "                     \
                   "Contact customer support.\n");                           \
    })

    static void wolfkmod_fips_cb(int ok, int err, const char * hash)
    {
        if ((!ok) || (err != 0)) {
            printf("error: libwolfssl FIPS error: %s\n",
                   wc_GetErrorString(err));
        }

        if (err == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
            WOLFKMOD_FIPS_ERR_MSG(hash);
        }
    }
#endif /* HAVE_FIPS */

static int wolfkmod_init(void)
{
    int error = 0;

    #ifdef HAVE_FIPS
    error = wolfCrypt_SetCb_fips(wolfkmod_fips_cb);
    if (error != 0) {
        printf("error: wolfCrypt_SetCb_fips failed: %s\n",
               wc_GetErrorString(error));
        return (ECANCELED);
    }

    fipsEntry();

    error = wolfCrypt_GetStatus_fips();
    if (error != 0) {
        printf("error: wolfCrypt_GetStatus_fips failed: %d: %s\n",
               error, wc_GetErrorString(error));
        if (error == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
            const char *newhash = wolfCrypt_GetCoreHash_fips();
            WOLFKMOD_FIPS_ERR_MSG(newhash);
        }
        return (ECANCELED);
    }
    #endif /* HAVE_FIPS */

    #ifdef WC_RNG_SEED_CB
    error = wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT);
    if (error < 0) {
        printf("error: wc_SetSeed_Cb failed: %d\n", error);
        return (ECANCELED);
    }
    #endif /* WC_RNG_SEED_CB */

    #ifdef WOLFCRYPT_ONLY
    error = wolfCrypt_Init();
    if (error != 0) {
        printf("error: wolfCrypt_Init failed: %s\n", wc_GetErrorString(error));
        return (ECANCELED);
    }
    #else
    error = wolfSSL_Init();
    if (error != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Init failed: %s\n", wc_GetErrorString(error));
        return (ECANCELED);
    }
    #endif /* WOLFCRYPT_ONLY */

    #ifdef HAVE_FIPS
    error = wc_RunAllCast_fips();
    if (error != 0) {
        printf("error: wc_RunAllCast_fips failed with "
               "return value %d\n", error);
        return (ECANCELED);
    }
    else {
        printf("info: FIPS 140-3 wolfCrypt-fips v%d.%d.%d%s%s startup "
               "self-test succeeded.\n",
    #ifdef HAVE_FIPS_VERSION_MAJOR
            HAVE_FIPS_VERSION_MAJOR,
    #else
            HAVE_FIPS_VERSION,
    #endif
    #ifdef HAVE_FIPS_VERSION_MINOR
            HAVE_FIPS_VERSION_MINOR,
    #else
            0,
    #endif
    #ifdef HAVE_FIPS_VERSION_PATCH
            HAVE_FIPS_VERSION_PATCH,
    #else
            0,
    #endif
    #ifdef HAVE_FIPS_VERSION_PORT
            "-",
            HAVE_FIPS_VERSION_PORT
    #else
            "",
            ""
    #endif
        );
    }
    #endif /* HAVE_FIPS */

    return (0);
}

static int wolfkmod_cleanup(void)
{
    int error = 0;

    #ifdef WOLFCRYPT_ONLY
    error = wolfCrypt_Cleanup();
    if (error != 0) {
        printf("error: wolfCrypt_Cleanup failed: %s\n",
               wc_GetErrorString(error));
        return (ECANCELED);
    }
    #else
    error = wolfSSL_Cleanup();
    if (error != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Cleanup failed: %s\n",
               wc_GetErrorString(error));
        return (ECANCELED);
    }
    #endif /* WOLFCRYPT_ONLY */

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    printf("info: libwolfssl " LIBWOLFSSL_VERSION_STRING
           " cleanup complete.\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (0);
}

static int wolfkmod_load(void)
{
    int error = 0;

    error = wolfkmod_init();
    if (error != 0) {
        return (ECANCELED);
    }

    #ifndef NO_CRYPT_TEST
    error = wolfcrypt_test(NULL);
    if (error != 0) {
        printf("error: wolfcrypt test failed: %d\n", error);
        (void)wolfkmod_cleanup();
        return (ECANCELED);
    }
    printf("info: wolfCrypt self-test passed.\n");
    #endif /* NO_CRYPT_TEST */

    /**
     * todo: register wolfcrypt algs here with crypto_get_driverid
     * and related.
     * */

    printf("info: libwolfssl loaded\n");

    return (0);
}

static int wolfkmod_unload(void)
{
    int error = 0;

    #ifdef HAVE_FIPS
    error = wc_RunAllCast_fips();
    if (error != 0) {
        printf("error: wc_RunAllCast_fips failed at shutdown with "
               "return value %d\n", error);
    }
    else
        printf("info: wolfCrypt FIPS re-self-test succeeded at unload: "
               "all algorithms re-verified.\n");
    #endif

    error = wolfkmod_cleanup();

    /**
     * todo: unregister wolfcrypt algs here with crypto_unregister_all
     * and related.
     * */

    if (error == 0) {
        printf("info: libwolfssl unloaded\n");
    }

    return (error);
}

#if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
static const char * wolfkmod_event_to_str(modeventtype_t what)
{
    switch (what) {
    case MOD_LOAD:
        return "MOD_LOAD";
    case MOD_UNLOAD:
        return "MOD_UNLOAD";
    case MOD_SHUTDOWN:
        return "MOD_SHUTDOWN";
    case MOD_QUIESCE:
        return "MOD_QUIESCE";
    }
}
#endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

/* see /usr/include/sys/module.h for more info. */
static int
wolfkmod_event(struct module * m, int what, void * arg)
{
    int error = 0;
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    printf("info: wolfkmod_event: %s\n", wolfkmod_event_to_str(what));
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    switch (what) {
    case MOD_LOAD:
        error = wolfkmod_load();
        break;
    case MOD_UNLOAD:
        error = wolfkmod_unload();
        break;
    case MOD_SHUTDOWN:
    case MOD_QUIESCE:
    default:
        error = EOPNOTSUPP;
    }

    (void)m;
    (void)arg;

    return (error);
}

static moduledata_t libwolfmod = {
    #ifdef HAVE_FIPS
    "libwolfssl_fips",   /* module name */
    #else
    "libwolfssl",   /* module name */
    #endif /* HAVE_FIPS */
    wolfkmod_event, /* module event handler */
    NULL            /* extra data, unused */
};

MODULE_VERSION(libwolfssl, 1);
DECLARE_MODULE(libwolfssl, libwolfmod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
#endif /* WOLFSSL_BSDKM */
