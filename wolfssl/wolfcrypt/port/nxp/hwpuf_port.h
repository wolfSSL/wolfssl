/* hwpuf_port.h
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
#ifndef _NXP_HWPUF_PORT_H_
#define _NXP_HWPUF_PORT_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_NXP_HWPUF)

#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int nxp_hwpuf_Init(void);
WOLFSSL_API int nxp_hwpuf_Deinit(void);
WOLFSSL_API int nxp_hwpuf_Enroll(byte* actCode, word32 actCodeSz);
WOLFSSL_API int nxp_hwpuf_Start(byte* actCode, word32 actCodeSz);
WOLFSSL_API int nxp_hwpuf_GenerateKey(byte keyIdx, word32 keySz,
                                      byte* keyCode, word32 keyCodeSz);
WOLFSSL_API int nxp_hwpuf_GetKey(byte* keyCode, word32 keyCodeSz,
                                 byte* key, word32 keySz);
WOLFSSL_API int nxp_hwpuf_Zeroize(void);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_NXP_HWPUF */

#endif /* _NXP_HWPUF_PORT_H_ */
