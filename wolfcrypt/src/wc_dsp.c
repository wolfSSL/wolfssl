/* wc_dsp.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/sp.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_DSP)
#include "remote.h"
#include "rpcmem.h"
static wolfSSL_DSP_Handle_cb handle_function = NULL;
static remote_handle64 defaultHandle;
static wolfSSL_Mutex handle_mutex; /* mutex for access to single default handle */

#define WOLFSSL_HANDLE_DONE 1
#define WOLFSSL_HANDLE_GET 0

/* callback function for setting the default handle in single threaded
 * use cases */
static int default_handle_cb(remote_handle64 *handle, int finished, void *ctx)
{
    (void)ctx;
    if (finished == WOLFSSL_HANDLE_DONE) {
        if (wc_UnLockMutex(&handle_mutex) != 0) {
            WOLFSSL_MSG("Unlock handle mutex failed");
            return -1;
        }
    }
    else {
        if (wc_LockMutex(&handle_mutex) != 0) {
            WOLFSSL_MSG("Lock handle mutex failed");
            return -1;
        }
        *handle = defaultHandle;
    }
    return 0;
}


/* Set global callback for getting handle to use
 * return 0 on success */
int wolfSSL_SetHandleCb(wolfSSL_DSP_Handle_cb in)
{
    handle_function = in;
    return 0;
}


/* returns 1 if global handle callback is set and 0 if not */
int wolfSSL_GetHandleCbSet()
{
    return (handle_function != NULL)? 1: 0;
}


/* Local function for setting up default handle
 * returns 0 on success */
int wolfSSL_InitHandle()
{
    char *sp_URI_value;
    int ret;

    sp_URI_value = wolfSSL_URI "&_dom=adsp";
    ret = wolfSSL_open(sp_URI_value, &defaultHandle);
    if (ret != 0) {
        WOLFSSL_MSG("Unable to open aDSP?");
        return -1;
    }
    wolfSSL_SetHandleCb(default_handle_cb);
    ret = wc_InitMutex(&handle_mutex);
    if (ret != 0) {
        WOLFSSL_MSG("Unable to init handle mutex");
        return -1;
    }

    return 0;
}


int wolfSSL_DSPInit()
{
    int ret;

    rpcmem_init();
    ret = wolfSSL_InitHandle();
    if (ret != 0) {
        return ret;
    }

    return ret;
}


/* internal function that closes default handle and frees mutex */
void wolfSSL_CleanupHandle()
{
    wolfSSL_close(defaultHandle);
    wc_FreeMutex(&handle_mutex);
}

void wolfSSL_DSPCleanup()
{
    wolfSSL_CleanupHandle();

    rpcmem_deinit();
}
#if defined(WOLFSSL_HAVE_SP_ECC)

#ifndef WOLFSSL_SP_NO_256

#ifdef HAVE_ECC_VERIFY
/* Used to assign a handle to an ecc_key structure.
 * returns 0 on success */
int wc_ecc_set_handle(ecc_key* key, remote_handle64 handle)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    key->handle = handle;
    return 0;
}
#endif /* HAVE_ECC_VERIFY */
#endif /* !WOLFSSL_SP_NO_256 */
#endif /* WOLFSSL_HAVE_SP_ECC */

#ifdef HAVE_ECC_VERIFY
/* Generic ECC verify the signature values with the hash and public key.
 *
 * handleIn The DSP handle to use
 * hash     Hash to sign.
 * hashLen  Length of the hash data.
 * key      ECC key to use for verify
 * r        First part of result as an mp_int.
 * s        Sirst part of result as an mp_int.
 * res      Set to 1 if verify success and 0 if verify fail
 * heap     Heap to use for allocation.
 * returns  0 on success (note that for verify state res should be checked)
 */
int wc_dsp_ecc_verify(remote_handle64 handleIn, const byte* hash,
        word32 hashLen, ecc_key *key, mp_int* r, mp_int* s, int* res,
        void* heap)
{
    remote_handle64 handle;
    int ret, sSz, rSz, curveId, cacheSz = 0;
    word32 keySz;
    uint8 *x963 = NULL;
    uint8 *sdsp = NULL;
    uint8 *rdsp = NULL;
    uint8 *cache = NULL;

    if (hash == NULL || key == NULL || r == NULL || s == NULL || res == NULL) {
        return BAD_FUNC_ARG;
    }

    handle = handleIn;
    ret = wc_ecc_export_x963(key, NULL, &keySz);
    if (ret != LENGTH_ONLY_E) {
        return BAD_FUNC_ARG;
    }

    sSz = mp_unsigned_bin_size(s);
    rSz = mp_unsigned_bin_size(r);

    x963 = (uint8*)XMALLOC(keySz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    sdsp = (uint8*)XMALLOC(sSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    rdsp = (uint8*)XMALLOC(rSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (x963 == NULL || sdsp == NULL || rdsp == NULL) {
        XFREE(x963, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(sdsp, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(rdsp, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    if (handle_function != NULL) {
        handle_function(&handle, WOLFSSL_HANDLE_GET, NULL);
    }

    ret = wc_ecc_export_x963(key, x963, &keySz);
    if (ret != MP_OKAY) {
        return ret;
    }

    mp_to_unsigned_bin(s, sdsp);
    mp_to_unsigned_bin(r, rdsp);

    *res = 0;
    curveId = wc_ecc_get_curve_id_from_dp_params(key->dp);
#if defined(FP_ECC) && defined(FP_ECC_CONTROL)
    cache = (uint8*)sp_ecc_get_cache_entry_256(&(key->pubkey), curveId,
                    key->fpIdx, key->fpBuild, key->heap);
    if (cache != NULL) {
        cacheSz = sp_ecc_get_cache_size_256();
    }
#endif
    ret = wolfSSL_DSP_ECC_Verify(handle, hash, hashLen, x963, keySz,
            rdsp, rSz, sdsp, sSz, curveId, res, cache, cacheSz);
    if (handle_function != NULL) {
        handle_function(&handle, WOLFSSL_HANDLE_DONE, NULL);
    }

    XFREE(x963, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sdsp, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(rdsp, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* HAVE_ECC_VERIFY */
#endif /* WOLFSSL_DSP */
