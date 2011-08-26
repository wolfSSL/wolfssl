/* hmac.h
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


/*  hmac.h defines mini hamc openssl compatibility layer 
 *
 */


#ifndef CYASSL_HMAC_H_
#define CYASSL_HMAC_H_

#ifdef YASSL_PREFIX
#include "prefix_hmac.h"
#endif

#include <cyassl/openssl/evp.h>

#ifdef __cplusplus
    extern "C" {
#endif


CYASSL_API unsigned char* CyaSSL_HMAC(const CYASSL_EVP_MD* evp_md,
                               const void* key, int key_len,
                               const unsigned char* d, int n, unsigned char* md,
                               unsigned int* md_len);


#define HMAC(a,b,c,d,e,f,g) CyaSSL_HMAC((a),(b),(c),(d),(e),(f),(g))

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* CYASSL_HMAC_H_ */
