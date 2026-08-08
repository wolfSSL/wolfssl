/* asu_cmac.h
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

/* ASU AES-CMAC for the wolfSSL crypto callback: the message is accumulated per
 * Cmac context and the whole CMAC is produced in one ASU operation at finalize. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_CMAC_H
#define WOLFSSL_VERSAL_GEN2_ASU_CMAC_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_CMAC

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the CMAC engine (WC_ALGO_TYPE_CMAC): single-call and
 * init/update/final. Returns 0, CRYPTOCB_UNAVAILABLE for software, or an error. */
WOLFSSL_LOCAL int wc_AsuCmac(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CMAC */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CMAC_H */
