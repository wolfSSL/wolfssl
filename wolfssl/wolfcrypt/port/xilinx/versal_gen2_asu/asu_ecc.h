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

/* ASU ECDSA offload for the wolfSSL crypto callback. wolfSSL's ECDSA sign and
 * verify callbacks route here; the ASU performs the elliptic-curve operation on
 * the supplied digest. Keys and r||s are marshalled big-endian, fixed-width into
 * the ASU structs, and the DER<->raw signature conversion uses wolfSSL helpers.
 * NIST P-192/256/384/521 and Brainpool P-256/320/384/512; other curves decline to
 * software. Plain Ed25519 and Ed448 sign/verify also route here (ASU hashes the
 * message). See asu_ecc.c. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_ECC_H
#define WOLFSSL_VERSAL_GEN2_ASU_ECC_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECC

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the ECC engine (WC_ALGO_TYPE_PK). Dispatches ECDSA sign
 * and verify to the matching ASU command for the supported NIST curves. Returns 0
 * on success, CRYPTOCB_UNAVAILABLE to defer to software, or a negative error. */
WOLFSSL_LOCAL int wc_AsuEcc(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECC */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECC_H */
