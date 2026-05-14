/* swdev.h
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

/* sole exported interface. */

#ifndef WC_SWDEV_H
#define WC_SWDEV_H

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_SWDEV_ID 0x77736465 /* 'w' 's' 'd' 'e' */

#if defined(__GNUC__) || defined(__clang__)
#define WC_SWDEV_EXPORT __attribute__((visibility("default")))
#else
#define WC_SWDEV_EXPORT
#endif

WC_SWDEV_EXPORT int  wc_SwDev_Callback(int devId, wc_CryptoInfo* info,
    void* ctx);
WC_SWDEV_EXPORT void wc_SwDev_InternalCleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WC_SWDEV_H */
