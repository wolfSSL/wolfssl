/* swdev_loader.h
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

/* test harness interface to register wc_swdev. */

#ifndef WC_SWDEV_LOADER_H
#define WC_SWDEV_LOADER_H

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_SWDEV_ID 0x77736465 /* 'w' 's' 'd' 'e' */

int  wc_SwDev_Init(void);
void wc_SwDev_Cleanup(void);

#ifdef WOLF_CRYPTO_CB_FIND
int  wc_SwDev_FindCb(int currentId, int algoType);
#endif

#ifdef __cplusplus
}
#endif

#endif /* WC_SWDEV_LOADER_H */
