/* psa.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/**
 * Platform Security Architecture (PSA) header
 *
 * If WOLFSSL_HAVE_PSA is defined, wolfSSL can use the cryptographic primitives
 * exported by a PSA Crypto API.
 *
 * Defines:
 *
 * WOLFSSL_HAVE_PSA: Global switch to enable PSA
 * WOLFSSL_PSA_NO_RNG: disable PSA random generator support
 */

#ifndef WOLFSSL_PSA_H
#define WOLFSSL_PSA_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_HAVE_PSA)

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/types.h>


int wc_psa_init(void);

#if !defined(WOLFSSL_PSA_NO_RNG)

WOLFSSL_API int wc_psa_get_random(unsigned char *out, word32 sz);
#ifndef HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wc_psa_get_random
#else
#define CUSTOM_RAND_GENERATE_SEED wc_psa_get_random
#endif

#endif

#endif
#endif /* WOLFSSL_PSA_H */
