/* crypto.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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


/* Defines Microchip CRYPTO API layer */


#ifndef MC_CRYPTO_API_H
#define MC_CRYPTO_API_H


#ifdef __cplusplus
    extern "C" {
#endif

/* MD5 */
typedef struct CRYPT_MD5_CTX {
    int holder[24];   /* big enough to hold internal, but check on init */
} CRYPT_MD5_CTX;

int CRYPT_MD5_Initialize(CRYPT_MD5_CTX*);
int CRYPT_MD5_DataAdd(CRYPT_MD5_CTX*, const unsigned char*, unsigned int);
int CRYPT_MD5_Finalize(CRYPT_MD5_CTX*, unsigned char*);

enum {
    CRYPT_MD5_DIGEST_SIZE = 16 
};


/* SHA */
typedef struct CRYPT_SHA_CTX {
    int holder[24];   /* big enough to hold internal, but check on init */
} CRYPT_SHA_CTX;

int CRYPT_SHA_Initialize(CRYPT_SHA_CTX*);
int CRYPT_SHA_DataAdd(CRYPT_SHA_CTX*, const unsigned char*, unsigned int);
int CRYPT_SHA_Finalize(CRYPT_SHA_CTX*, unsigned char*);

enum {
    CRYPT_SHA_DIGEST_SIZE = 20
};


/* SHA-256 */
typedef struct CRYPT_SHA256_CTX {
    int holder[28];   /* big enough to hold internal, but check on init */
} CRYPT_SHA256_CTX;

int CRYPT_SHA256_Initialize(CRYPT_SHA256_CTX*);
int CRYPT_SHA256_DataAdd(CRYPT_SHA256_CTX*, const unsigned char*, unsigned int);
int CRYPT_SHA256_Finalize(CRYPT_SHA256_CTX*, unsigned char*);

enum {
    CRYPT_SHA256_DIGEST_SIZE = 32 
};


/* SHA-384 */
typedef struct CRYPT_SHA384_CTX {
    long long holder[32];   /* big enough to hold internal, but check on init */
} CRYPT_SHA384_CTX;

int CRYPT_SHA384_Initialize(CRYPT_SHA384_CTX*);
int CRYPT_SHA384_DataAdd(CRYPT_SHA384_CTX*, const unsigned char*, unsigned int);
int CRYPT_SHA384_Finalize(CRYPT_SHA384_CTX*, unsigned char*);

enum {
    CRYPT_SHA384_DIGEST_SIZE = 48
};


/* SHA-512 */
typedef struct CRYPT_SHA512_CTX {
    long long holder[36];   /* big enough to hold internal, but check on init */
} CRYPT_SHA512_CTX;

int CRYPT_SHA512_Initialize(CRYPT_SHA512_CTX*);
int CRYPT_SHA512_DataAdd(CRYPT_SHA512_CTX*, const unsigned char*, unsigned int);
int CRYPT_SHA512_Finalize(CRYPT_SHA512_CTX*, unsigned char*);

enum {
    CRYPT_SHA512_DIGEST_SIZE = 64 
};




#ifdef __cplusplus
    }  /* extern "C" */ 
#endif


#endif /* MC_CRYPTO_API_H */

