/* chacha.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef CTAO_CRYPT_CHACHA_H
#define CTAO_CRYPT_CHACHA_H

#include "types.h"

#ifdef __cplusplus
    extern "C" {
#endif


enum {
	CHACHA_ENC_TYPE = 7     /* cipher unique type */
};

typedef struct ChaCha {
    word32 X[16];           /* state of cipher */
} ChaCha;

CYASSL_API int Chacha_Process(ChaCha* ctx, byte* cipher, const byte* plain,
                              word32 msglen);
CYASSL_API int Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz);

/**
  * IV(nonce) changes with each record 
  * counter is for what value the block counter should start ... usually 0
  */
CYASSL_API int Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif

