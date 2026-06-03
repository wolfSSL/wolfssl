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

#ifdef WOLFSSL_HWPUF

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hwpuf.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_NXP_HWPUF
    #include <wolfssl/wolfcrypt/port/nxp/hwpuf_port.h>
#endif


WOLFSSL_API int wc_HWPUF_Register(wc_HWPUF* hwpuf, void* heap, int devId)
{
    int ret = 0;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (devId == INVALID_DEVID)
        return BAD_FUNC_ARG;

    ForceZero(hwpuf, sizeof(wc_HWPUF));
    hwpuf->heap = heap;
    hwpuf->devId = devId;

#ifdef WOLFSSL_NXP_HWPUF
    if (devId == WOLFSSL_NXP_HWPUF_DEVID) {
        ret = nxp_hwpuf_RegisterDevice(hwpuf);
    }
#else
    #error No hwpuf device defined
#endif
 
    return ret;
}

WOLFSSL_API int wc_HWPUF_Unregister(wc_HWPUF* hwpuf)
{
    int ret = 0;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_NXP_HWPUF
    if (hwpuf->devId == WOLFSSL_NXP_HWPUF_DEVID) {
        ret = nxp_hwpuf_UnregisterDevice(hwpuf);
    }
#else
    #error No hwpuf device defined
#endif
 
    ForceZero(hwpuf, sizeof(wc_HWPUF));

    return ret;
}

WOLFSSL_API int wc_HWPUF_Init(wc_HWPUF* hwpuf)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_INITED) != 0)
        return HWPUF_INIT_E;

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

    ret = wc_CryptoCb_HwpufDeinit(hwpuf);
    hwpuf->flags = 0;

    return ret;
}

WOLFSSL_API int wc_HWPUF_Enroll(wc_HWPUF* hwpuf)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_ENROLLED) != 0)
        return HWPUF_ENROLL_E;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) != 0)
        return HWPUF_ENROLL_E;

    ret = wc_CryptoCb_HwpufEnroll(hwpuf);
    if (ret == 0)
        hwpuf->flags |= WC_HWPUF_FLAG_ENROLLED;

    return ret;
}

WOLFSSL_API int wc_HWPUF_Start(wc_HWPUF* hwpuf)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_ENROLLED) != 0)
        return HWPUF_START_E;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) != 0)
        return HWPUF_START_E;

    ret = wc_CryptoCb_HwpufStart(hwpuf);
    if (ret == 0)
        hwpuf->flags |= WC_HWPUF_FLAG_READY;

    return ret;
}

WOLFSSL_API int wc_HWPUF_GenerateKey(wc_HWPUF* hwpuf,
                                     byte keyIdx, word32 keySz,
                                     byte* keycode, word32 keycodeSz)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) == 0)
        return HWPUF_GENERATE_KEY_E;

    ret = wc_CryptoCb_HwpufGenerateKey(hwpuf, keyIdx, keySz,
                                       keycode, keycodeSz);
    return ret;
}

WOLFSSL_API int wc_HWPUF_SetKey(wc_HWPUF* hwpuf, byte keyIdx,
                                byte* key, word32 keySz,
                                byte* keycode, word32 keycodeSz)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) == 0)
        return HWPUF_SET_KEY_E;

    ret = wc_CryptoCb_HwpufSetKey(hwpuf, keyIdx, key, keySz,
                                  keycode, keycodeSz);
    return ret;
}

WOLFSSL_API int wc_HWPUF_GetKey(wc_HWPUF* hwpuf,
                                byte* keycode, word32 keycodeSz,
                                byte* key, word32 keySz)
{
    int ret;

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if ((hwpuf->flags & WC_HWPUF_FLAG_READY) == 0)
        return HWPUF_GET_KEY_E;

    ret = wc_CryptoCb_HwpufGetKey(hwpuf, keycode, keycodeSz, key, keySz);
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
