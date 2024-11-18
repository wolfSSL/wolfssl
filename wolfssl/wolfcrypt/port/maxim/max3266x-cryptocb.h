/* max3266x-cryptocb.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifndef _WOLFPORT_MAX3266X_CRYPTO_CB_H_
#define _WOLFPORT_MAX3266X_CRYPTO_CB_H_

#if (defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)) && \
    defined(WOLF_CRYPTO_CB)
#ifndef WOLFSSL_MAX3266X_DEVID
    #define WOLFSSL_MAX3266X_DEVID 9
#endif
#define WC_USE_DEVID WOLFSSL_MAX3266X_DEVID
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef __cplusplus
    extern "C" {
#endif

    WOLFSSL_LOCAL int wc_MxcCryptoCb(int devIdArg, wc_CryptoInfo* info,
                                        void* ctx);
#ifdef HAVE_AES_ECB
    WOLFSSL_LOCAL int wc_MxcCb_AesEcbEncrypt(Aes* aes, byte* out,
                                        const byte* in, word32 sz);
#endif
#ifdef HAVE_AES_CBC
    WOLFSSL_LOCAL int wc_MxcCb_AesCbcEncrypt(Aes* aes, byte* out,
                                        const byte* in, word32 sz);
#endif

#ifdef HAVE_AES_DECRYPT
#ifdef HAVE_AES_ECB
    WOLFSSL_LOCAL int wc_MxcCb_AesEcbDecrypt(Aes* aes, byte* out,
                                        const byte* in, word32 sz);
#endif
#ifdef HAVE_AES_CBC
    WOLFSSL_LOCAL int wc_MxcCb_AesCbcDecrypt(Aes* aes, byte* out,
                                        const byte* in, word32 sz);
#endif
#endif /* HAVE_AES_DECRYPT */


    WOLFSSL_LOCAL int wc_MXC_Sha256Update(wc_MXC_Sha* sha256,
                                            const unsigned char* data,
                                            unsigned int len);
    WOLFSSL_LOCAL int wc_MXC_Sha256Final(wc_MXC_Sha* sha256,
                                            unsigned char* hash);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* (WOLFSSL_MAX3266X || WOLFSSL_MAX3266X_OLD) && WOLF_CRYPTO_CB) */
#endif /* _WOLFPORT_MAX3266X_CRYPTO_CB_H_ */
