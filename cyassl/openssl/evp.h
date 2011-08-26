/* evp.h
 *
 * Copyright (C) 2011 Sawtooth Consulting Ltd.
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


/*  evp.h defines mini evp openssl compatibility layer 
 *
 */


#ifndef CYASSL_EVP_H_
#define CYASSL_EVP_H_

#ifdef YASSL_PREFIX
#include "prefix_evp.h"
#endif

#include <cyassl/openssl/md5.h>
#include <cyassl/openssl/sha.h>


#ifdef __cplusplus
    extern "C" {
#endif

typedef char CYASSL_EVP_MD;
typedef char CYASSL_EVP_CIPHER;

CYASSL_API const CYASSL_EVP_MD* CyaSSL_EVP_md5(void);
CYASSL_API const CYASSL_EVP_MD* CyaSSL_EVP_sha1(void);


typedef union {
    CYASSL_MD5_CTX md5;
    CYASSL_SHA_CTX sha;
} CYASSL_Hasher;


typedef struct CYASSL_EVP_MD_CTX {
    unsigned char macType;               /* md5 or sha for now */
    CYASSL_Hasher hash;
} CYASSL_EVP_MD_CTX;


CYASSL_API void CyaSSL_EVP_MD_CTX_init(CYASSL_EVP_MD_CTX* ctx);
CYASSL_API int  CyaSSL_EVP_MD_CTX_cleanup(CYASSL_EVP_MD_CTX* ctx);

CYASSL_API int CyaSSL_EVP_DigestInit(CYASSL_EVP_MD_CTX* ctx,
                                     const CYASSL_EVP_MD* type);
CYASSL_API int CyaSSL_EVP_DigestUpdate(CYASSL_EVP_MD_CTX* ctx, const void* data,
                                       unsigned long sz);
CYASSL_API int CyaSSL_EVP_DigestFinal(CYASSL_EVP_MD_CTX* ctx, unsigned char* md,
                                      unsigned int* s);
CYASSL_API int CyaSSL_EVP_DigestFinal_ex(CYASSL_EVP_MD_CTX* ctx,
                                            unsigned char* md, unsigned int* s);
CYASSL_API int CyaSSL_EVP_BytesToKey(const CYASSL_EVP_CIPHER*,
                              const CYASSL_EVP_MD*, const unsigned char*,
                              const unsigned char*, int, int, unsigned char*,
                              unsigned char*);

typedef CYASSL_EVP_MD      EVP_MD;
typedef CYASSL_EVP_CIPHER  EVP_CIPHER;
typedef CYASSL_EVP_MD_CTX  EVP_MD_CTX;

#define EVP_md5 CyaSSL_EVP_md5
#define EVP_sha1 CyaSSL_EVP_sha1

#define EVP_MD_CTX_init CyaSSL_EVP_MD_CTX_init
#define EVP_MD_CTX_cleanup CyaSSL_EVP_MD_CTX_cleanup
#define EVP_DigestInit CyaSSL_EVP_DigestInit
#define EVP_DigestUpdate CyaSSL_EVP_DigestUpdate
#define EVP_DigestFinal CyaSSL_EVP_DigestFinal
#define EVP_DigestFinal_ex CyaSSL_EVP_DigestFinal_ex
#define EVP_BytesToKey CyaSSL_EVP_BytesToKey


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* CYASSL_EVP_H_ */
