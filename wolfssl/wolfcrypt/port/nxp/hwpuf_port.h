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

#if defined(WOLFSSL_HWPUF) && defined(WOLFSSL_NXP_HWPUF)

#include <wolfssl/wolfcrypt/hwpuf.h>

#define WOLFSSL_NXP_HWPUF_DEVID 5569

#define HWPUF_KEY_SIZE_IS_VALID(keysz) \
    (keysz == 16 || keysz == 24 || keysz == 32)

/* keycode size is 52 for key sizes of 16, 24, or 32 */
#define HWPUF_KEY_SIZE_TO_KEYCODE_SIZE(keysz)   52

WOLFSSL_API int nxp_hwpuf_RegisterDevice(wc_HWPUF* hwpuf);
WOLFSSL_API int nxp_hwpuf_UnregisterDevice(wc_HWPUF* hwpuf);

#endif /* WOLFSSL_HWPUF && WOLFSSL_NXP_HWPUF */

#endif /* _NXP_HWPUF_PORT_H_ */
