/* casper_port.h
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
#ifndef _CASPER_PORT_H_
#define _CASPER_PORT_H_

#include <wolfssl/wolfcrypt/settings.h>

int wc_casper_init(void);

#if !defined(NO_RSA) && defined(WOLFSSL_NXP_CASPER_RSA_PUB_EXPTMOD)

#include <wolfssl/wolfcrypt/rsa.h>

int casper_rsa_public_exptmod(
    const byte* in, word32 inLen, byte* out, word32* outLen, RsaKey* key
);
#endif


#if defined(HAVE_ECC)
#include <wolfssl/wolfcrypt/ecc.h>

#ifdef WOLFSSL_NXP_CASPER_ECC_MULMOD
int casper_ecc_mulmod(
    const mp_int *m, ecc_point *P, ecc_point *R, int curve_id
);
#endif

#ifdef WOLFSSL_NXP_CASPER_ECC_MUL2ADD
int casper_ecc_mul2add(
    const mp_int *m, ecc_point *P, const mp_int *n, ecc_point *Q,
    ecc_point *R, int curve_id
);
#endif
#endif

#endif
