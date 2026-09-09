/* els_pkc_port.h
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

#ifndef WOLF_CRYPT_ELS_PKC_PORT_H
#define WOLF_CRYPT_ELS_PKC_PORT_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ELS_PKC

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_ELS_PKC requires WOLF_CRYPTO_CB"
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* WOLFSSL_ELS_PKC_DEVID comes from settings.h. */

#ifndef WOLFSSL_ELS_PKC_IRQ_PRIO
    #define WOLFSSL_ELS_PKC_IRQ_PRIO 2
#endif

/* wolfCrypt_Init() already calls this; call it again only after
 * wolfCrypt_Cleanup(). */
WOLFSSL_API int wc_ElsPkc_Init(void);

/* Unregister the callback and close the port; the mutex is kept for reuse.
 * Finish every context the port holds state for first. */
WOLFSSL_API int wc_ElsPkc_Cleanup(void);

/* The callback, for registering under another devId. A context opts in by
 * being initialised with that devId. */
WOLFSSL_API int wc_ElsPkc_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_ELS_PKC */
#endif /* WOLF_CRYPT_ELS_PKC_PORT_H */
