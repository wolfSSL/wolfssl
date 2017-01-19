/* objects.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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


#ifndef WOLFSSL_OBJECTS_H_
#define WOLFSSL_OBJECTS_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>

#ifdef __cplusplus
    extern "C" {
#endif


WOLFSSL_API const char *  wolfSSL_OBJ_nid2sn(int n);
WOLFSSL_API int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o);
WOLFSSL_API int wolfSSL_OBJ_sn2nid(const char *sn);

WOLFSSL_API char* wolfSSL_OBJ_nid2ln(int n);
WOLFSSL_API int wolfSSL_OBJ_txt2nid(const char *sn);

WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj(int n);
WOLFSSL_API int wolfSSL_OBJ_obj2txt(char *buf, int buf_len, WOLFSSL_ASN1_OBJECT *a, int no_name);

WOLFSSL_API void wolfSSL_OBJ_cleanup(void);


#define OBJ_nid2sn  wolfSSL_OBJ_nid2sn
#define OBJ_obj2nid wolfSSL_OBJ_obj2nid
#define OBJ_sn2nid  wolfSSL_OBJ_sn2nid
#define OBJ_nid2ln  wolfSSL_OBJ_nid2ln
#define OBJ_txt2nid wolfSSL_OBJ_txt2nid
#define OBJ_nid2obj wolfSSL_OBJ_nid2obj
#define OBJ_obj2txt wolfSSL_OBJ_obj2txt
#define OBJ_cleanup wolfSSL_OBJ_cleanup


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_OBJECTS_H_ */
