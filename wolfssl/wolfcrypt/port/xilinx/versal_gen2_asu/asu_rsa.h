/* asu_rsa.h
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

/* ASU RSA public-key offload for the wolfSSL crypto callback. wolfSSL's
 * WOLF_CRYPTO_CB_RSA_PAD path routes the padded RSA operations here so the ASU
 * performs the whole operation (PSS/OAEP padding + hash + modexp), with the key
 * marshalled big-endian into the ASU fixed-width key structs. See asu_rsa.c. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_RSA_H
#define WOLFSSL_VERSAL_GEN2_ASU_RSA_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_RSA

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the RSA engine (WC_ALGO_TYPE_PK). Dispatches on the
 * pk sub-type to the matching ASU RSA command, keys 2048/3072/4096 only. Returns
 * 0 on success, CRYPTOCB_UNAVAILABLE to defer to software, or a negative error. */
WOLFSSL_LOCAL int wc_AsuRsa(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RSA */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RSA_H */
