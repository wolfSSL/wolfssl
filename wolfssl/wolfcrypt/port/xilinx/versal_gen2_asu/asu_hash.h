/* asu_hash.h
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

/* ASU hashing for the wolfSSL crypto callback: SHA2 256/384/512 and SHA3
 * 256/384/512. The message is accumulated per hash context and hashed in a
 * single ASU operation at finalize. See asu_hash.c for why. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_HASH_H
#define WOLFSSL_VERSAL_GEN2_ASU_HASH_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the SHA2/SHA3 engine. The crypto callback dispatcher
 * routes every hash related operation here and this handler decides which it is:
 * update and final (WC_ALGO_TYPE_HASH), context copy (WC_ALGO_TYPE_COPY), or
 * context release (WC_ALGO_TYPE_FREE). Supports SHA2 256/384/512 and SHA3
 * 256/384/512. Returns 0 on success, CRYPTOCB_UNAVAILABLE for an unsupported
 * operation or hash type (software fallback), or a negative error. */
WOLFSSL_LOCAL int wc_AsuHash(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_HASH */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_HASH_H */
