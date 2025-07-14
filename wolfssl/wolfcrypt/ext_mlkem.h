/* ext_mlkem.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef EXT_KYBER_H
#define EXT_KYBER_H

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef WOLFSSL_HAVE_MLKEM
#include <wolfssl/wolfcrypt/mlkem.h>

#if !defined(HAVE_LIBOQS)
#error "This code requires liboqs"
#endif

#if defined(WOLFSSL_WC_MLKEM)
#error "This code is incompatible with wolfCrypt's implementation of Kyber."
#endif

#if defined (HAVE_LIBOQS)
    #include <oqs/kem.h>

    #ifndef WOLFSSL_NO_ML_KEM
        #define EXT_KYBER_MAX_PRIV_SZ OQS_KEM_ml_kem_1024_length_secret_key
        #define EXT_KYBER_MAX_PUB_SZ  OQS_KEM_ml_kem_1024_length_public_key
    #elif defined(WOLFSSL_MLKEM_KYBER)
        #define EXT_KYBER_MAX_PRIV_SZ OQS_KEM_kyber_1024_length_secret_key
        #define EXT_KYBER_MAX_PUB_SZ  OQS_KEM_kyber_1024_length_public_key
    #endif
#endif

struct KyberKey {
    /* Type of key: KYBER_LEVEL1
     *              KYBER_LEVEL3
     *              KYBER_LEVEL5
     *
     * Note we don't save the variant (SHAKE vs AES) as that is decided at
     * configuration time. */
    int type;

#ifdef WOLF_CRYPTO_CB
    void* devCtx;
    int   devId;
#endif

    byte priv[EXT_KYBER_MAX_PRIV_SZ];
    byte pub[EXT_KYBER_MAX_PUB_SZ];
};

#if defined (HAVE_LIBOQS)
WOLFSSL_LOCAL int ext_mlkem_enabled(int id);
#endif
#endif /* WOLFSSL_HAVE_MLKEM */
#endif /* EXT_KYBER_H */
