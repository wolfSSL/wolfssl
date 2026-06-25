/* hwpuf.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_HWPUF

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hwpuf.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* The various supported device ports...  One must be defined. */
#ifdef WOLFSSL_NXP_HWPUF
    #include <wolfssl/wolfcrypt/port/nxp/hwpuf_port.h>
#endif

static int hwpuf_registered = 0;

WOLFSSL_API int wc_HWPUF_Register(wc_HWPUF* hwpuf, void* heap, int devId)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (hwpuf_registered)
        return HWPUF_REGISTER_E;

    ForceZero(hwpuf, sizeof(wc_HWPUF));
    hwpuf->heap = heap;
    hwpuf->devId = devId;

#ifdef WOLFSSL_NXP_HWPUF
    ret = nxp_hwpuf_RegisterDevice(hwpuf);
#endif
    if (ret != 0) {
        if (ret != CRYPTOCB_UNAVAILABLE) {
            ret = HWPUF_REGISTER_E;
        }
        ForceZero(hwpuf, sizeof(wc_HWPUF));
        return ret;
    }
    hwpuf_registered = 1;
    return ret;
}

WOLFSSL_API int wc_HWPUF_Unregister(wc_HWPUF* hwpuf)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (!hwpuf_registered)
        return 0;

#ifdef WOLFSSL_NXP_HWPUF
    ret = nxp_hwpuf_UnregisterDevice(hwpuf);
#endif

    ForceZero(hwpuf, sizeof(wc_HWPUF));
    hwpuf_registered = 0;
    return ret;
}

WOLFSSL_API int wc_HWPUF_Init(wc_HWPUF* hwpuf)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (!hwpuf_registered)
        return HWPUF_REGISTER_E;
    if ((hwpuf->flags & WC_HWPUF_FLAG_INITED) != 0)
        return 0;

    ret = wc_CryptoCb_HwpufInit(hwpuf);
    if (ret == 0)
        hwpuf->flags |= WC_HWPUF_FLAG_INITED;

    return ret;
}

WOLFSSL_API int wc_HWPUF_Deinit(wc_HWPUF* hwpuf)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (!hwpuf_registered)
        return HWPUF_REGISTER_E;

    ret = wc_CryptoCb_HwpufDeinit(hwpuf);
    hwpuf->flags = 0;

    return ret;
}

WOLFSSL_API int wc_HWPUF_Enroll(wc_HWPUF* hwpuf,
                                byte* actCode, word32 actCodeSz)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (actCode == NULL || actCodeSz != HWPUF_ACTIVATION_CODE_SIZE)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_INITED) == 0)
        return HWPUF_INIT_E;
    if ((hwpuf->flags & WC_HWPUF_FLAG_ENROLLED) != 0)
        return HWPUF_ENROLL_E;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) != 0)
        return HWPUF_ENROLL_E;

    ret = wc_CryptoCb_HwpufEnroll(hwpuf, actCode, actCodeSz);
    if (ret == 0)
        hwpuf->flags |= WC_HWPUF_FLAG_ENROLLED;

    return ret;
}

WOLFSSL_API int wc_HWPUF_Start(wc_HWPUF* hwpuf,
                               byte* actCode, word32 actCodeSz)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (actCode == NULL || actCodeSz != HWPUF_ACTIVATION_CODE_SIZE)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_INITED) == 0)
        return HWPUF_INIT_E;
    if ((hwpuf->flags & WC_HWPUF_FLAG_ENROLLED) != 0)
        return HWPUF_START_E;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) != 0)
        return HWPUF_START_E;

    ret = wc_CryptoCb_HwpufStart(hwpuf, actCode, actCodeSz);
    if (ret == 0)
        hwpuf->flags |= WC_HWPUF_FLAG_READY;

    return ret;
}

WOLFSSL_API int wc_HWPUF_GenerateKey(wc_HWPUF* hwpuf,
                                     byte keyIdx, word32 keySz,
                                     byte* keyCode, word32 keyCodeSz)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) == 0)
        return HWPUF_START_E;

    ret = wc_CryptoCb_HwpufGenerateKey(hwpuf, keyIdx, keySz,
                                       keyCode, keyCodeSz);
    return ret;
}

WOLFSSL_API int wc_HWPUF_GetKey(wc_HWPUF* hwpuf,
                                byte* keyCode, word32 keyCodeSz,
                                byte* key, word32 keySz)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) == 0)
        return HWPUF_START_E;

    ret = wc_CryptoCb_HwpufGetKey(hwpuf, keyCode, keyCodeSz, key, keySz);
    return ret;
}

WOLFSSL_API int wc_HWPUF_Zeroize(wc_HWPUF* hwpuf)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    ret = wc_CryptoCb_HwpufZeroize(hwpuf);
    hwpuf->flags = 0;

    return ret;
}
#endif /* WOLFSSL_HWPUF */
