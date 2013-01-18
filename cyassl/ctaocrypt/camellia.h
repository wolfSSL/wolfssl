/* camellia.h
 *
 * Copyright (C) 2006-2013 Sawtooth Consulting Ltd.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CAMELLIA

#ifndef CTAO_CRYPT_CAMELLIA_H
#define CTAO_CRYPT_CAMELLIA_H


#include <cyassl/ctaocrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif


enum {
    CAMELLIA_ENCRYPTION = 0,
    CAMELLIA_DECRYPTION = 1,
    CAMELLIA_BLOCK_SIZE = 16,
    CAMELLIA_KEY_128_BITS = 16,
    CAMELLIA_KEY_192_BITS = 24,
    CAMELLIA_KEY_256_BITS = 32
};


typedef struct Camellia {
    word32 keySz;
    word32 reg[CAMELLIA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
    word32 tmp[CAMELLIA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
} Camellia;


CYASSL_API int  CamelliaSetKey(Camellia* cam,
                          const byte* key, word32 len, const byte* iv, int dir);
CYASSL_API int  CamelliaSetIV(Camellia* cam, const byte* iv);
CYASSL_API void CamelliaEncryptDirect(Camellia* cam, byte* out, const byte* in);
CYASSL_API void CamelliaDecryptDirect(Camellia* cam, byte* out, const byte* in);
CYASSL_API void CamelliaCbcEncrypt(Camellia* cam,
                                          byte* out, const byte* in, word32 sz);
CYASSL_API void CamelliaCbcDecrypt(Camellia* cam,
                                          byte* out, const byte* in, word32 sz);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_AES_H */
#endif /* HAVE_CAMELLIA */

