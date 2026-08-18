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

/* Match asu_rsa.c: engine is inert when NO_RSA is set (even late, via a size
 * profile) so wc_AsuRsa is neither declared nor referenced in that build. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_RSA) && !defined(NO_RSA)

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry (WC_ALGO_TYPE_PK): dispatch pk sub-type to the ASU RSA command,
 * keys 2048/3072/4096 only. 0, CRYPTOCB_UNAVAILABLE (defer to SW), or <0. */
WOLFSSL_LOCAL int wc_AsuRsa(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RSA && !NO_RSA */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RSA_H */
