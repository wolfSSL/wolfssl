/* asu_ecc.h
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

/* ECDSA and EdDSA on the ASU. Curves we do not support run in software.
 * See asu_ecc.c. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_ECC_H
#define WOLFSSL_VERSAL_GEN2_ASU_ECC_H

#include <wolfssl/wolfcrypt/settings.h>

/* Nothing here exists in a build without ECC. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_ECC) && defined(HAVE_ECC) && \
    !defined(NO_ECC)

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ECC entry point. Returns 0, CRYPTOCB_UNAVAILABLE to use software, or a
 * negative error. */
WOLFSSL_LOCAL int wc_AsuEcc(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECC && HAVE_ECC && !NO_ECC */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECC_H */
