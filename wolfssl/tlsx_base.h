/* tlsx_base.h
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



#ifndef WOLFSSL_TLSX_BASE_H
#define WOLFSSL_TLSX_BASE_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

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
#undef HAVE_SNI
#undef HAVE_MAX_FRAGMENT
#undef HAVE_TRUSTED_CA
#undef HAVE_TRUNCATED_HMAC
#undef HAVE_CERTIFICATE_STATUS_REQUEST
#undef HAVE_CERTIFICATE_STATUS_REQUEST_V2
#undef HAVE_SUPPORTED_CURVES
#undef HAVE_ALPN
#undef HAVE_QSH
#undef HAVE_SESSION_TICKET
#undef HAVE_SECURE_RENEGOTIATION
#undef HAVE_SERVER_RENEGOTIATION_INFO
#endif

/** TLS Extensions - RFC 6066 */
#ifdef HAVE_TLS_EXTENSIONS
typedef enum {
#ifdef HAVE_SNI
    TLSX_SERVER_NAME                = 0x0000, /* a.k.a. SNI  */
#endif
    TLSX_MAX_FRAGMENT_LENGTH        = 0x0001,
    TLSX_TRUSTED_CA_KEYS            = 0x0003,
    TLSX_TRUNCATED_HMAC             = 0x0004,
    TLSX_STATUS_REQUEST             = 0x0005, /* a.k.a. OCSP stapling   */
    TLSX_SUPPORTED_GROUPS           = 0x000a, /* a.k.a. Supported Curves */
    TLSX_EC_POINT_FORMATS           = 0x000b,
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG)
    TLSX_SIGNATURE_ALGORITHMS       = 0x000d, /* HELLO_EXT_SIG_ALGO */
#endif
    TLSX_APPLICATION_LAYER_PROTOCOL = 0x0010, /* a.k.a. ALPN */
    TLSX_STATUS_REQUEST_V2          = 0x0011, /* a.k.a. OCSP stapling v2 */
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    TLSX_ENCRYPT_THEN_MAC           = 0x0016, /* RFC 7366 */
#endif
    TLSX_EXTENDED_MASTER_SECRET     = 0x0017, /* HELLO_EXT_EXTMS */
    TLSX_QUANTUM_SAFE_HYBRID        = 0x0018, /* a.k.a. QSH  */
    TLSX_SESSION_TICKET             = 0x0023,
#ifdef WOLFSSL_TLS13
    #if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
    TLSX_PRE_SHARED_KEY             = 0x0029,
    #endif
    #ifdef WOLFSSL_EARLY_DATA
    TLSX_EARLY_DATA                 = 0x002a,
    #endif
    TLSX_SUPPORTED_VERSIONS         = 0x002b,
    #ifdef WOLFSSL_SEND_HRR_COOKIE
    TLSX_COOKIE                     = 0x002c,
    #endif
    #if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
    TLSX_PSK_KEY_EXCHANGE_MODES     = 0x002d,
    #endif
    #ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    TLSX_POST_HANDSHAKE_AUTH        = 0x0031,
    #endif
    #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG)
    TLSX_SIGNATURE_ALGORITHMS_CERT  = 0x0032,
    #endif
    TLSX_KEY_SHARE                  = 0x0033,
#endif
    TLSX_RENEGOTIATION_INFO         = 0xff01
} TLSX_Type;

typedef struct TLSX {
    TLSX_Type    type; /* Extension Type  */
    void*        data; /* Extension Data  */
    word32       val;  /* Extension Value */
    byte         resp; /* IsResponse Flag */
    struct TLSX* next; /* List Behavior   */
} TLSX;

WOLFSSL_LOCAL TLSX* TLSX_Find(TLSX* list, TLSX_Type type);
WOLFSSL_LOCAL void  TLSX_Remove(TLSX** list, TLSX_Type type, void* heap);
WOLFSSL_LOCAL void  TLSX_SetResponse(WOLFSSL* ssl, TLSX_Type type);
WOLFSSL_LOCAL int   TLSX_Push(TLSX** list, TLSX_Type type, const void* data,
                                                                    void* heap);
#ifdef WOLFSSL_TLS13
WOLFSSL_LOCAL int   TLSX_Prepend(TLSX** list, TLSX_Type type, void* data,
                                                                    void* heap);
#endif
#ifndef NO_WOLFSSL_CLIENT
WOLFSSL_LOCAL int   TLSX_CheckUnsupportedExtension(WOLFSSL* ssl,
                                                                TLSX_Type type);
WOLFSSL_LOCAL int   TLSX_HandleUnsupportedExtension(WOLFSSL* ssl);
#else
#define TLSX_CheckUnsupportedExtension(ssl, type) 0
#define TLSX_HandleUnsupportedExtension(ssl) 0
#endif

#endif /* HAVE_TLS_EXTENSIONS */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_TLSX_BASE_H */
