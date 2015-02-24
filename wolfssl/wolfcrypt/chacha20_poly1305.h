/* chacha20_poly1305.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if( defined( HAVE_CHACHA ) && defined( HAVE_POLY1305 ) )

#ifndef WOLF_CRYPT_CHACHA20_POLY1305_H
#define WOLF_CRYPT_CHACHA20_POLY1305_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
extern "C" {
#endif
    
#define CHACHA20_POLY1305_AEAD_KEYSIZE      32
#define CHACHA20_POLY1305_AEAD_IV_SIZE      12
#define CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE 16
    
    enum {
        CHACHA20_POLY_1305_ENC_TYPE = 8    /* cipher unique type */
    };
    
    WOLFSSL_API int wc_ChaCha20Poly1305_Encrypt(const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                                                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                                                const byte* inAAD, const word32 inAADLen,
                                                const byte* inPlaintext, const word32 inPlaintextLen,
                                                byte* outCiphertext,
                                                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);
    
    WOLFSSL_API int wc_ChaCha20Poly1305_Decrypt(const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                                                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                                                const byte* inAAD, const word32 inAADLen,
                                                const byte* inCiphertext, const word32 inCiphertextLen,
                                                const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                                                byte* outPlaintext);
    
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WOLF_CRYPT_CHACHA20_POLY1305_H */
#endif /* HAVE_CHACHA && HAVE_POLY1305 */