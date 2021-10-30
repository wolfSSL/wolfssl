/* renesas_cmn.h
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
#ifndef __RENESAS_CMN_H__
#define __RENESAS_CMN_H__

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

/* Common Callback and Method */
int Renesas_cmn_genMasterSecret(WOLFSSL* ssl, void* ctx);
int Renesas_cmn_generatePremasterSecret(WOLFSSL* ssl, byte *premaster, 
                                                  word32 preSz, void* ctx);
int Renesas_cmn_RsaEnc(WOLFSSL* ssl, const unsigned char* in, 
       unsigned int inSz, unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz, void* ctx);
int Renesas_cmn_VerifyHmac(WOLFSSL *ssl, const byte* message, 
                    word32 messageSz, word32 macSz, word32 content);
int wc_CryptoCb_CryptInitRenesascmn(WOLFSSL* ssl, void* ctx);
int Renesas_cmn_EccVerify(WOLFSSL* ssl, const uint8_t* sig, uint32_t sigSz,
        const uint8_t* hash, uint32_t hashSz, const uint8_t* key, uint32_t keySz,
        int* result, void* ctx);
int Renesas_cmn_RsaVerify(WOLFSSL* ssl, byte* sig, uint32_t sigSz,
        uint8_t** out, const byte* key, uint32_t keySz, void* ctx);

#endif /* __RENESAS_CMN_H__ */