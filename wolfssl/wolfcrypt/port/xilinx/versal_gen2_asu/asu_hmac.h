/* asu_hmac.h
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

/* ASU HMAC for the wolfSSL crypto callback: HMAC over SHA2 256/384/512 and SHA3
 * 256/384/512. The message is accumulated per HMAC context and the whole HMAC is
 * produced in a single ASU operation at finalize. See asu_hmac.c for why. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_HMAC_H
#define WOLFSSL_VERSAL_GEN2_ASU_HMAC_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_HMAC

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the HMAC engine. The crypto callback dispatcher routes
 * every HMAC related operation here and this handler decides which it is: update
 * and final (WC_ALGO_TYPE_HMAC), context copy (WC_ALGO_TYPE_COPY) or context
 * free (WC_ALGO_TYPE_FREE). The message is accumulated per context and the HMAC
 * is computed in one ASU operation at final using the raw key wolfSSL keeps on
 * the context. Supports HMAC over SHA2 256/384/512 and SHA3 256/384/512. Returns
 * 0 on success, CRYPTOCB_UNAVAILABLE for an unsupported MAC type or key (software
 * fallback), or a negative error. */
WOLFSSL_LOCAL int wc_AsuHmac(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_HMAC */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_HMAC_H */
