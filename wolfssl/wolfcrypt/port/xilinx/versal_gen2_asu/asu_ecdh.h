/* asu_ecdh.h
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

/* ECDH shared secret on the ASU. Curves we do not support run in software.
 * See asu_ecdh.c. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_ECDH_H
#define WOLFSSL_VERSAL_GEN2_ASU_ECDH_H

#include <wolfssl/wolfcrypt/settings.h>

/* Turned on from the ECC macros, and compiles to nothing without them. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_ECDH) && defined(HAVE_ECC) && \
    !defined(NO_ECC) && defined(HAVE_ECC_DHE)
    #define WC_ASU_ECDH_ENABLED
#endif

#ifdef WC_ASU_ECDH_ENABLED

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ECDH entry point. Returns 0, CRYPTOCB_UNAVAILABLE to use software, or a
 * negative error. */
WOLFSSL_LOCAL int wc_AsuEcdh(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WC_ASU_ECDH_ENABLED */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECDH_H */
