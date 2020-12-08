/* tlsx_sni.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
/*!
    \file ../wolfssl/tlsx_sni.h
    \brief Header file containing wolfSSL API for TLS extension SNI
*/

/* wolfSSL API for TLS extension SNI */

#ifndef WOLFSSL_TLSX_SNI_H
#define WOLFSSL_TLSX_SNI_H


/* for users not using preprocessor flags*/
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_PREFIX
    #include "prefix_ssl.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif

struct WOLFSSL;
struct WOLFSSL_CTX;
#ifndef WOLFSSL_WOLFSSL_TYPE_DEFINED
#define WOLFSSL_WOLFSSL_TYPE_DEFINED
typedef struct WOLFSSL          WOLFSSL;
#endif
#ifndef WOLFSSL_WOLFSSL_CTX_TYPE_DEFINED
#define WOLFSSL_WOLFSSL_CTX_TYPE_DEFINED
typedef struct WOLFSSL_CTX      WOLFSSL_CTX;
#endif

#ifdef WOLFCRYPT_ONLY
#undef HAVE_TLS_EXTENSIONS
#endif
#ifndef HAVE_TLS_EXTENSIONS
#undef HAVE_SNI
#endif

/* Server Name Indication */
#ifdef HAVE_SNI

/* SNI types */
enum {
    WOLFSSL_SNI_HOST_NAME = 0
};

WOLFSSL_ABI WOLFSSL_API int wolfSSL_UseSNI(WOLFSSL*, unsigned char,
                                                   const void*, unsigned short);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_UseSNI(WOLFSSL_CTX*, unsigned char,
                                                   const void*, unsigned short);

#ifndef NO_WOLFSSL_SERVER

/* SNI received callback type */
typedef int (*CallbackSniRecv)(WOLFSSL *ssl, int *ret, void* exArg);

#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_CTX_set_tlsext_servername_callback(WOLFSSL_CTX *,
        CallbackSniRecv);
#endif
WOLFSSL_API void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX *,
        CallbackSniRecv);
WOLFSSL_API int  wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX *, void*);

/* SNI options */
enum {
    /* Do not abort the handshake if the requested SNI didn't match. */
    WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01,

    /* Behave as if the requested SNI matched in a case of mismatch.  */
    /* In this case, the status will be set to WOLFSSL_SNI_FAKE_MATCH. */
    WOLFSSL_SNI_ANSWER_ON_MISMATCH   = 0x02,

    /* Abort the handshake if the client didn't send a SNI request. */
    WOLFSSL_SNI_ABORT_ON_ABSENCE     = 0x04,
};

WOLFSSL_API void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, unsigned char type,
                                                         unsigned char options);
WOLFSSL_API void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx,
                                     unsigned char type, unsigned char options);
WOLFSSL_API int wolfSSL_SNI_GetFromBuffer(
                 const unsigned char* clientHello, unsigned int helloSz,
                 unsigned char type, unsigned char* sni, unsigned int* inOutSz);

#endif /* NO_WOLFSSL_SERVER */

/* SNI status */
enum {
    WOLFSSL_SNI_NO_MATCH   = 0,
    WOLFSSL_SNI_FAKE_MATCH = 1, /**< @see WOLFSSL_SNI_ANSWER_ON_MISMATCH */
    WOLFSSL_SNI_REAL_MATCH = 2,
    WOLFSSL_SNI_FORCE_KEEP = 3  /** Used with -DWOLFSSL_ALWAYS_KEEP_SNI */
};

WOLFSSL_API unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type);

WOLFSSL_API unsigned short wolfSSL_SNI_GetRequest(WOLFSSL *ssl,
                                               unsigned char type, void** data);

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA)

WOLFSSL_API int wolfSSL_set_tlsext_host_name(WOLFSSL *, const char *);

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_API const char* wolfSSL_get_servername(WOLFSSL *, unsigned char);
#endif

#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

#endif /* HAVE_SNI */

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_TLSX_SNI_H */
