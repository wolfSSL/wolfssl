/* asu_cipher.h
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

/* ASU symmetric cipher engine for the wolfSSL crypto callback: AES-CBC, ECB,
 * CTR, CFB, OFB, GCM and CCM offload (128/256 bit keys). AES-192 uses software. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_CIPHER_H
#define WOLFSSL_VERSAL_GEN2_ASU_CIPHER_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_CIPHER

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the cipher engine. Returns 0 on success,
 * CRYPTOCB_UNAVAILABLE for software fallback, or a negative error. */
WOLFSSL_LOCAL int wc_AsuCipher(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CIPHER */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CIPHER_H */
