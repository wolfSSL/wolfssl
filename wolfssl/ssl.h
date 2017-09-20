/* ssl.h
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

/*!
    \file ssl.h
    \brief Header file containing key wolfSSL API

*************************
    \defgroup 3DES Algorithms - 3DES
    \defgroup AES Algorithms - AES
    \defgroup ARC4 Algorithms - ARC4
    \defgroup BLAKE2 Algorithms - BLAKE2
    \defgroup Camellia Algorithms - Camellia
    \defgroup ChaCha Algorithms - ChaCha
    \defgroup ChaCha20Poly1305 Algorithms - ChaCha20_Poly1305
    \defgroup Curve25519 Algorithms - Curve25519
    \defgroup DSA Algorithms - DSA
    \defgroup Diffie-Hellman Algorithms - Diffie-Hellman
    \defgroup ECC Algorithms - ECC
    \defgroup ED25519 Algorithms - ED25519
    \defgroup HC128 Algorithms - HC-128
    \defgroup HMAC Algorithms - HMAC
    \defgroup IDEA Algorithms - IDEA
    \defgroup MD2 Algorithms - MD2
    \defgroup MD4 Algorithms - MD4
    \defgroup MD5 Algorithms - MD5
    \defgroup PKCS7 Algorithms - PKCS7
    \defgroup Password Algorithms - Password Based
    \defgroup Poly1305 Algorithms - Poly1305
    \defgroup RIPEMD Algorithms - RIPEMD
    \defgroup RSA Algorithms - RSA
    \defgroup Rabbit Algorithms - Rabbit
    \defgroup SHA Algorithms - SHA 128/224/256/384/512
    \defgroup SRP Algorithms - SRP

    \defgroup ASN ASN.1
    \defgroup Base_Encoding Base Encoding
    \defgroup CertManager CertManager API
    \defgroup Compression Compression
    \defgroup Error Error Reporting
    \defgroup Keys Key and Cert Conversion
    \defgroup Logging Logging
    \defgroup Math Math API
    \defgroup Memory Memory Handling
    \defgroup Random Random Number Generation
    \defgroup Signature Signature API
    \defgroup openSSL OpenSSL API
    \defgroup wolfCrypt wolfCrypt Init and Cleanup
    \defgroup wolfssl wolfSSL Manual API
*************************
*/
/* wolfSSL API */

#ifndef WOLFSSL_SSL_H
#define WOLFSSL_SSL_H


/* for users not using preprocessor flags*/
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>

#ifdef HAVE_WOLF_EVENT
    #include <wolfssl/wolfcrypt/wolfevent.h>
#endif

#ifndef NO_FILESYSTEM
    #if defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
        #if MQX_USE_IO_OLD
            #include <fio.h>
        #else
            #include <nio.h>
        #endif
    #endif
#endif

#ifdef WOLFSSL_PREFIX
    #include "prefix_ssl.h"
#endif

#ifdef LIBWOLFSSL_VERSION_STRING
    #define WOLFSSL_VERSION LIBWOLFSSL_VERSION_STRING
#endif

#ifdef _WIN32
    /* wincrypt.h clashes */
    #undef OCSP_REQUEST
    #undef OCSP_RESPONSE
#endif

#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/bn.h>
    #include <wolfssl/openssl/hmac.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef WOLFSSL_WOLFSSL_TYPE_DEFINED
#define WOLFSSL_WOLFSSL_TYPE_DEFINED
typedef struct WOLFSSL          WOLFSSL;
#endif
typedef struct WOLFSSL_SESSION  WOLFSSL_SESSION;
typedef struct WOLFSSL_METHOD   WOLFSSL_METHOD;
#ifndef WOLFSSL_WOLFSSL_CTX_TYPE_DEFINED
#define WOLFSSL_WOLFSSL_CTX_TYPE_DEFINED
typedef struct WOLFSSL_CTX      WOLFSSL_CTX;
#endif

typedef struct WOLFSSL_STACK      WOLFSSL_STACK;
typedef struct WOLFSSL_X509       WOLFSSL_X509;
typedef struct WOLFSSL_X509_NAME  WOLFSSL_X509_NAME;
typedef struct WOLFSSL_X509_NAME_ENTRY  WOLFSSL_X509_NAME_ENTRY;
typedef struct WOLFSSL_X509_CHAIN WOLFSSL_X509_CHAIN;

typedef struct WOLFSSL_CERT_MANAGER WOLFSSL_CERT_MANAGER;
typedef struct WOLFSSL_SOCKADDR     WOLFSSL_SOCKADDR;
typedef struct WOLFSSL_CRL          WOLFSSL_CRL;

/* redeclare guard */
#define WOLFSSL_TYPES_DEFINED

#include <wolfssl/io.h>


#ifndef WOLFSSL_RSA_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_RSA            WOLFSSL_RSA;
#define WOLFSSL_RSA_TYPE_DEFINED
#endif

#ifndef WC_RNG_TYPE_DEFINED /* guard on redeclaration */
    typedef struct WC_RNG WC_RNG;
    #define WC_RNG_TYPE_DEFINED
#endif

#ifndef WOLFSSL_DSA_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_DSA            WOLFSSL_DSA;
#define WOLFSSL_DSA_TYPE_DEFINED
#endif

#ifndef WOLFSSL_EC_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_EC_KEY         WOLFSSL_EC_KEY;
typedef struct WOLFSSL_EC_POINT       WOLFSSL_EC_POINT;
typedef struct WOLFSSL_EC_GROUP       WOLFSSL_EC_GROUP;
#define WOLFSSL_EC_TYPE_DEFINED
#endif

#ifndef WOLFSSL_ECDSA_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_ECDSA_SIG      WOLFSSL_ECDSA_SIG;
#define WOLFSSL_ECDSA_TYPE_DEFINED
#endif

typedef struct WOLFSSL_CIPHER         WOLFSSL_CIPHER;
typedef struct WOLFSSL_X509_LOOKUP    WOLFSSL_X509_LOOKUP;
typedef struct WOLFSSL_X509_LOOKUP_METHOD WOLFSSL_X509_LOOKUP_METHOD;
typedef struct WOLFSSL_X509_CRL       WOLFSSL_X509_CRL;
typedef struct WOLFSSL_X509_STORE     WOLFSSL_X509_STORE;
typedef struct WOLFSSL_BIO            WOLFSSL_BIO;
typedef struct WOLFSSL_BIO_METHOD     WOLFSSL_BIO_METHOD;
typedef struct WOLFSSL_X509_EXTENSION WOLFSSL_X509_EXTENSION;
typedef struct WOLFSSL_ASN1_TIME      WOLFSSL_ASN1_TIME;
typedef struct WOLFSSL_ASN1_INTEGER   WOLFSSL_ASN1_INTEGER;
typedef struct WOLFSSL_ASN1_OBJECT    WOLFSSL_ASN1_OBJECT;

typedef struct WOLFSSL_ASN1_STRING      WOLFSSL_ASN1_STRING;
typedef struct WOLFSSL_dynlock_value    WOLFSSL_dynlock_value;
typedef struct WOLFSSL_DH               WOLFSSL_DH;
typedef struct WOLFSSL_ASN1_BIT_STRING  WOLFSSL_ASN1_BIT_STRING;
typedef unsigned char*                  WOLFSSL_BUF_MEM;

#define WOLFSSL_ASN1_UTCTIME          WOLFSSL_ASN1_TIME
#define WOLFSSL_ASN1_GENERALIZEDTIME  WOLFSSL_ASN1_TIME

struct WOLFSSL_ASN1_INTEGER {
    /* size can be increased set at 20 for tag, length then to hold at least 16
     * byte type */
    unsigned char data[20];
    /* ASN_INTEGER | LENGTH | hex of number */
};

struct WOLFSSL_ASN1_TIME {
    /* MAX_DATA_SIZE is 32 */
    unsigned char data[32 + 2];
    /* ASN_TIME | LENGTH | date bytes */
};

#ifndef WOLFSSL_EVP_PKEY_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_EVP_PKEY     WOLFSSL_EVP_PKEY;
#define WOLFSSL_EVP_PKEY_TYPE_DEFINED
#endif

typedef struct WOLFSSL_MD4_CTX {
    int buffer[32];      /* big enough to hold, check size in Init */
} WOLFSSL_MD4_CTX;


typedef struct WOLFSSL_COMP_METHOD {
    int type;            /* stunnel dereference */
} WOLFSSL_COMP_METHOD;

struct WOLFSSL_X509_LOOKUP_METHOD {
    int type;
};

struct WOLFSSL_X509_LOOKUP {
    WOLFSSL_X509_STORE *store;
};

struct WOLFSSL_X509_STORE {
    int                   cache;          /* stunnel dereference */
    WOLFSSL_CERT_MANAGER* cm;
    WOLFSSL_X509_LOOKUP   lookup;
#ifdef OPENSSL_EXTRA
    int                   isDynamic;
#endif
};

typedef struct WOLFSSL_ALERT {
    int code;
    int level;
} WOLFSSL_ALERT;

typedef struct WOLFSSL_ALERT_HISTORY {
    WOLFSSL_ALERT last_rx;
    WOLFSSL_ALERT last_tx;
} WOLFSSL_ALERT_HISTORY;

typedef struct WOLFSSL_X509_REVOKED {
    WOLFSSL_ASN1_INTEGER* serialNumber;          /* stunnel dereference */
} WOLFSSL_X509_REVOKED;


typedef struct WOLFSSL_X509_OBJECT {
    union {
        char* ptr;
        WOLFSSL_X509 *x509;
        WOLFSSL_X509_CRL* crl;           /* stunnel dereference */
    } data;
} WOLFSSL_X509_OBJECT;

typedef struct WOLFSSL_BUFFER_INFO {
    unsigned char* buffer;
    unsigned int length;
} WOLFSSL_BUFFER_INFO;

typedef struct WOLFSSL_X509_STORE_CTX {
    WOLFSSL_X509_STORE* store;    /* Store full of a CA cert chain */
    WOLFSSL_X509* current_cert;   /* stunnel dereference */
    WOLFSSL_STACK* chain;
    char* domain;                /* subject CN domain name */
    void* ex_data;               /* external data, for fortress build */
    void* userCtx;               /* user ctx */
    int   error;                 /* current error */
    int   error_depth;           /* cert depth for this error */
    int   discardSessionCerts;   /* so verify callback can flag for discard */
    int   totalCerts;            /* number of peer cert buffers */
    WOLFSSL_BUFFER_INFO* certs;  /* peer certs */
} WOLFSSL_X509_STORE_CTX;

typedef char* WOLFSSL_STRING;

/* Valid Alert types from page 16/17 */
enum AlertDescription {
    close_notify                    =   0,
    unexpected_message              =  10,
    bad_record_mac                  =  20,
    record_overflow                 =  22,
    decompression_failure           =  30,
    handshake_failure               =  40,
    no_certificate                  =  41,
    bad_certificate                 =  42,
    unsupported_certificate         =  43,
    certificate_revoked             =  44,
    certificate_expired             =  45,
    certificate_unknown             =  46,
    illegal_parameter               =  47,
    decode_error                    =  50,
    decrypt_error                   =  51,
    #ifdef WOLFSSL_MYSQL_COMPATIBLE
    /* catch name conflict for enum protocol with MYSQL build */
    wc_protocol_version             =  70,
    #else
    protocol_version                =  70,
    #endif
    no_renegotiation                = 100,
    unrecognized_name               = 112, /**< RFC 6066, section 3 */
    bad_certificate_status_response = 113, /**< RFC 6066, section 8 */
    no_application_protocol         = 120
};


enum AlertLevel {
    alert_warning = 1,
    alert_fatal   = 2
};


typedef WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_client_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_client_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_client_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_client_method_ex(void* heap);
#ifdef WOLFSSL_TLS13
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_client_method_ex(void* heap);
#endif
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_client_method_ex(void* heap);

#ifdef WOLFSSL_DTLS
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_server_method_ex(void* heap);
/*!
    \ingroup wolfssl

    \brief This function initializes the DTLS v1.2 client method.
    
    \return pointer This function returns a pointer to a new WOLFSSL_METHOD structure.
    
    \param none No parameters.
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    …
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    \endcode
    
    \sa wolfSSL_Init
    \sa wolfSSL_CTX_new
*/
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_server_method_ex(void* heap);
#endif

/*!
    \ingroup wolfssl

    \brief This function returns a WOLFSSL_METHOD similar to wolfSSLv23_client_method except that it is not determined which side yet (server/client).
    
    \return WOLFSSL_METHOD* On successful creations returns a WOLFSSL_METHOD pointer
    \return NULL Null if memory allocation error or failure to create method
    
    \param none No parameters.
    
    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfSSLv23_method());
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_method(void);
/*!
    \ingroup wolfssl
   
    \brief The wolfSSLv3_server_method() function is used to indicate that the application is a server and will only support the SSL 3.0 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new

*/
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_server_method(void);
/*!   
    \ingroup wolfssl

    \brief The wolfSSLv3_client_method() function is used to indicate that the application is a client and will only support the SSL 3.0 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
 */
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_client_method(void);
/*!
    \ingroup wolfssl

    \brief The wolfTLSv1_server_method() function is used to indicate that the application is a server and will only support the TLS 1.0 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_server_method(void);
/*!
    \ingroup wolfssl

    \brief The wolfTLSv1_client_method() function is used to indicate that the application is a client and will only support the TLS 1.0 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_client_method(void);
/*!
    \ingroup wolfssl

    \brief The wolfTLSv1_1_server_method() function is used to indicate that the application is a server and will only support the TLS 1.1 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);
/*!
    \ingroup wolfssl

    \brief The wolfTLSv1_1_client_method() function is used to indicate that the application is a client and will only support the TLS 1.0 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);
/*!
    \ingroup wolfssl

    \brief The wolfTLSv1_2_server_method() function is used to indicate that the application is a server and will only support the TLS 1.2 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);
/*!
    \ingroup wolfssl

    \brief The wolfTLSv1_2_client_method() function is used to indicate that the application is a client and will only support the TLS 1.2 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);
#ifdef WOLFSSL_TLS13
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_server_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_client_method(void);
#endif

#ifdef WOLFSSL_DTLS
/*!
    \ingroup wolfssl

    \brief The wolfDTLSv1_client_method() function is used to indicate that the application is a client and will only support the DTLS 1.0 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new(). This function is only available when wolfSSL has been compiled with DTLS support (--enable-dtls, or by defining wolfSSL_DTLS).
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code    
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_client_method(void);
/*!
    \ingroup wolfssl

    \brief The wolfDTLSv1_server_method() function is used to indicate that the application is a server and will only support the DTLS 1.0 protocol.  This function allocates memory for and initializes a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new(). This function is only available when wolfSSL has been compiled with DTLS support (--enable-dtls, or by defining wolfSSL_DTLS).
    
    \return * If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none No parameters.
    
    _Example_
    \code 
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_server_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_client_method(void);
/*!
    \ingroup wolfssl

    \brief This function creates and initializes a WOLFSSL_METHOD for the server side.
    
    \return This function returns a WOLFSSL_METHOD pointer.
    
    \param none No parameters.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    \endcode

    \sa wolfSSL_CTX_new
*/
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);
#endif

#ifdef HAVE_POLY1305
/*!
    \ingroup wolfssl

    \brief Since there is some differences between the first release and newer versions of chacha-poly AEAD construction we have added an option to communicate with servers/clients using the older version. By default wolfSSL uses the new version.
    
    \return 0 upon success
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param value whether or not to use the older version of setting up the information for poly1305. Passing a flag value of 1 indicates yes use the old poly AEAD, to switch back to using the new version pass a flag value of 0.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_use_old_poly(ssl, 1);
    if (ret != 0) {
        // failed to set poly1305 AEAD version
    }
    \endcode
    
    \sa none
*/
    WOLFSSL_API int wolfSSL_use_old_poly(WOLFSSL*, int);
#endif

#ifdef WOLFSSL_SESSION_EXPORT
#ifdef WOLFSSL_DTLS
typedef int (*wc_dtls_export)(WOLFSSL* ssl,
                   unsigned char* exportBuffer, unsigned int sz, void* userCtx);
/*!
    \ingroup wolfssl

    \brief The wolfSSL_dtls_import() function is used to parse in a serialized session state. This allows for picking up the connection after the handshake has been completed.
    
    \return Success If successful, the amount of the buffer read will be returned.
    \return Failure All unsuccessful return values will be less than 0.
    \return VERSION_ERROR If a version mismatch is found ie DTLS v1 and ctx was set up for DTLS v1.2 then VERSION_ERROR is returned.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf serialized session to import.
    \param sz size of serialized session buffer.
    
    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    //get information sent from wc_dtls_export function and place it in buf
    fread(buf, 1, bufSz, input);
    ret = wolfSSL_dtls_import(ssl, buf, bufSz);
    if (ret < 0) {
    // handle error case
    }
    // no wolfSSL_accept needed since handshake was already done
    ...
    ret = wolfSSL_write(ssl) and wolfSSL_read(ssl);
    ...
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
WOLFSSL_API int wolfSSL_dtls_import(WOLFSSL* ssl, unsigned char* buf,
                                                               unsigned int sz);
/*!
    \ingroup wolfssl

    \brief The wolfSSL_CTX_dtls_set_export() function is used to set the callback function for exporting a session. It is allowed to pass in NULL as the parameter func to clear the export function previously stored. Used on the server side and is called immediately after handshake is completed.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG If null or not expected arguments are passed in
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created with wolfSSL_CTX_new().
    \param func wc_dtls_export function to use when exporting a session.
    
    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passses buf (serialized session) to destination
    WOLFSSL_CTX* ctx;
    int ret;
    ...
    ret = wolfSSL_CTX_dtls_set_export(ctx, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_dtls_set_export
    \sa Static buffer use
*/
WOLFSSL_API int wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx,
                                                           wc_dtls_export func);
/*!
    \ingroup wolfssl

    \brief The wolfSSL_dtls_set_export() function is used to set the callback function for exporting a session. It is allowed to pass in NULL as the parameter func to clear the export function previously stored. Used on the server side and is called immediately after handshake is completed.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG If null or not expected arguments are passed in
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param func wc_dtls_export function to use when exporting a session.
    
    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passses buf (serialized session) to destination
    WOLFSSL* ssl;
    int ret;
    ...
    ret = wolfSSL_dtls_set_export(ssl, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
WOLFSSL_API int wolfSSL_dtls_set_export(WOLFSSL* ssl, wc_dtls_export func);
/*!
    \ingroup wolfssl

    \brief The wolfSSL_dtls_export() function is used to serialize a WOLFSSL session into the provided buffer. Allows for less memory overhead than using a function callback for sending a session and choice over when the session is serialized. If buffer is NULL when passed to function then sz will be set to the size of buffer needed for serializing the WOLFSSL session.
    
    \return Success If successful, the amount of the buffer used will be returned.
    \return Failure All unsuccessful return values will be less than 0.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf buffer to hold serialized session.
    \param sz size of buffer.
    
    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    ret = wolfSSL_dtls_export(ssl, buf, bufSz);
    if (ret < 0) {
        // handle error case
    }
    ...
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
    \sa wolfSSL_dtls_import
*/
WOLFSSL_API int wolfSSL_dtls_export(WOLFSSL* ssl, unsigned char* buf,
                                                              unsigned int* sz);
#endif /* WOLFSSL_DTLS */
#endif /* WOLFSSL_SESSION_EXPORT */

#ifdef WOLFSSL_STATIC_MEMORY
#ifndef WOLFSSL_MEM_GUARD
#define WOLFSSL_MEM_GUARD
    typedef struct WOLFSSL_MEM_STATS      WOLFSSL_MEM_STATS;
    typedef struct WOLFSSL_MEM_CONN_STATS WOLFSSL_MEM_CONN_STATS;
#endif
/*!
    \ingroup wolfssl

    \brief This function is used to set aside static memory for a CTX. Memory set aside is then used for the CTX’s lifetime and for any SSL objects created from the CTX. By passing in a NULL ctx pointer and a wolfSSL_method_func function the creation of the CTX itself will also use static memory. wolfSSL_method_func has the function signature of WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);. Passing in 0 for max makes it behave as if not set and no max concurrent use restrictions is in place. The flag value passed in determines how the memory is used and behavior while operating. Available flags are the following: 0 - default general memory, WOLFMEM_IO_POOL - used for input/output buffer when sending receiving messages and overrides general memory, so all memory in buffer passed in is used for IO, WOLFMEM_IO_FIXED - same as WOLFMEM_IO_POOL but each SSL now keeps two buffers to themselves for their lifetime, WOLFMEM_TRACK_STATS - each SSL keeps track of memory stats while running.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE upon failure.
    
    \param ctx address of pointer to a WOLFSSL_CTX structure.
    \param method function to create protocol. (should be NULL if ctx is not also NULL)
    \param buf memory to use for all operations.
    \param sz size of memory buffer being passed in.
    \param flag type of memory.
    \param max max concurrent operations.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    unsigned char IO[MAX];
    int IOSz = MAX;
    int flag = WOLFMEM_IO_FIXED | WOLFMEM_TRACK_STATS;
    ...
    // create ctx also using static memory, start with general memory to use
    ctx = NULL:
    ret = wolfSSL_CTX_load_static_memory(&ctx, wolfSSLv23_server_method_ex, memory, memorySz, 0,    MAX_CONCURRENT_HANDSHAKES);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    // load in memory for use with IO
    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL, IO, IOSz, flag, MAX_CONCURRENT_IO);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_is_static_memory
    \sa wolfSSL_is_static_memory
*/
WOLFSSL_API int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx,
                                            wolfSSL_method_func method,
                                            unsigned char* buf, unsigned int sz,
                                            int flag, int max);
/*!
    \ingroup wolfssl

    \brief This function does not change any of the connections behavior and is used only for gathering information about the static memory usage.
    
    \return 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param mem_stats structure to hold information about static memory usage.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int ret;
    WOLFSSL_MEM_STATS mem_stats;
    ...
    //get information about static memory with CTX
    ret = wolfSSL_CTX_is_static_memory(ctx, &mem_stats);
    if (ret == 1) {
        // handle case of is using static memory
         // print out or inspect elements of mem_stats
    }
    if (ret == 0) {
        //handle case of ctx not using static memory
    }
    …
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_load_static_memory
    \sa wolfSSL_is_static_memory
*/
WOLFSSL_API int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx,
                                                 WOLFSSL_MEM_STATS* mem_stats);
/*!
    \ingroup wolfssl

    \brief wolfSSL_is_static_memory is used to gather information about a SSL’s static memory usage. The return value indicates if static memory is being used and WOLFSSL_MEM_CONN_STATS will be filled out if and only if the flag WOLFMEM_TRACK_STATS was passed to the parent CTX when loading in static memory.
    
    \return 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param mem_stats structure to contain static memory usage.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    WOLFSSL_MEM_CONN_STATS mem_stats;
    ...
    ret = wolfSSL_is_static_memory(ssl, mem_stats);
    if (ret == 1) {
    // handle case when is static memory
    // investigate elements in mem_stats if WOLFMEM_TRACK_STATS flag
    }
    ...
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_is_static_memory
*/
WOLFSSL_API int wolfSSL_is_static_memory(WOLFSSL* ssl,
                                            WOLFSSL_MEM_CONN_STATS* mem_stats);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)

/*!
    \ingroup wolfssl

    \brief This function loads a certificate file into the SSL context (WOLFSSL_CTX).  The file is provided by the file argument.  The format argument specifies the format type of the file, either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes might include the file is in the wrong format, or the wrong format has been given using the “format” argument, file doesn’t exist, can’t be read, or is corrupted, an out of memory condition occurs, Base16 decoding fails on the file.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the certificate to be loaded into the wolfSSL SSL context.
    \param format - format of the certificates pointed to by file.  Possible options are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_file(ctx, “./client-cert.pem”,
                                     SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
WOLFSSL_API int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX*, const char*, int);
/*!
    \ingroup wolfssl

    \brief This function loads a private key file into the SSL context (WOLFSSL_CTX).  The file is provided by the file argument.  The format argument specifies the format type of the file - SSL_FILETYPE_ASN1or SSL_FILETYPE_PEM.  Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE The file is in the wrong format, or the wrong format has been given using the “format” argument. The file doesn’t exist, can’t be read, or is corrupted. An out of memory condition occurs. Base16 decoding fails on the file. The key file is encrypted but no password is provided.
    
    \param none No parameters.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, “./server-key.pem”,
                                    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
*/
WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX*, const char*, int);
/*!
    \ingroup wolfssl

    \brief This function loads PEM-formatted CA certificate files into the SSL context (WOLFSSL_CTX).  These certificates will be treated as trusted root certificates and used to verify certs received from peers during the SSL handshake. The root certificate file, provided by the file argument, may be a single certificate or a file containing multiple certificates.  If multiple CA certs are included in the same file, wolfSSL will load them in the same order they are presented in the file.  The path argument is a pointer to the name of a directory that contains certificates of trusted root CAs. If the value of file is not NULL, path may be specified as NULL if not needed.  If path is specified and NO_WOLFSSL_DIR was not defined when building the library, wolfSSL will load all CA certificates located in the given directory. This function will attempt to load all files in the directory and locate any files with the PEM header “-----BEGIN CERTIFICATE-----”. Please see the examples for proper usage.
    
    \return SSL_SUCCESS up success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and path are NULL.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than the receiving buffer.
    \return BAD_PATH_ERROR will be returned if opendir() fails when trying to open path.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing PEM-formatted CA certificates.
    \param path pointer to the name of a directory to load PEM-formatted certificates from.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations(ctx, “./ca-cert.pem”, 0);
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
WOLFSSL_API int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX*, const char*,
                                                const char*);
#ifdef WOLFSSL_TRUST_PEER_CERT
/*!
    \ingroup wolfssl

    \brief This function loads a certificate to use for verifying a peer when performing a TLS/SSL handshake. The peer certificate sent during the handshake is compared by using the SKID when available and the signature. If these two things do not match then any loaded CAs are used. Feature is enabled by defining the macro WOLFSSL_TRUST_PEER_CERT. Please see the examples for proper usage.

    \return SSL_SUCCES upon success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and type are invalid.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing certificates
    \param type type of certificate being loaded ie SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    ...

    ret = wolfSSL_CTX_trust_peer_cert(ctx, “./peer-cert.pem”, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        // error loading trusted peer cert
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
WOLFSSL_API int wolfSSL_CTX_trust_peer_cert(WOLFSSL_CTX*, const char*, int);
#endif
/*!
    \ingroup wolfssl

    \brief This function loads a chain of certificates into the SSL context (WOLFSSL_CTX).  The file containing the certificate chain is provided by the file argument, and must contain PEM-formatted certificates.  This function will process up to MAX_CHAIN_DEPTH (default = 9, defined in internal.h) certificates, plus the subject cert.
    
    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might include the file is in the wrong format, or the wrong format has been given using the “format” argument, file doesn’t exist, can’t be read, or is corrupted, an out of memory condition occurs.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the chain of certificates to be loaded into the wolfSSL SSL context.  Certificates must be in PEM format.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *,
                                                     const char *file);
/*!
    \ingroup openSSL
    
    \brief This function loads the private RSA key used in the SSL connection into the SSL context (WOLFSSL_CTX).  This function is only available when wolfSSL has been compiled with the OpenSSL compatibility layer enabled (--enable-opensslExtra, #define OPENSSL_EXTRA), and is identical to the more-typically used wolfSSL_CTX_use_PrivateKey_file() function. The file argument contains a pointer to the RSA private key file, in the format specified by format.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE  If the function call fails, possible causes might include: The input key file is in the wrong format, or the wrong format has been given using the “format” argument, file doesn’t exist, can’t be read, or is corrupted, an out of memory condition occurs.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the RSA private key to be loaded into the wolfSSL SSL context, with format as specified by format.
    \param format the encoding type of the RSA private key specified by file.  Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_RSAPrivateKey_file(ctx, “./server-key.pem”,
                                       SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_RSAPrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
WOLFSSL_API int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX*, const char*, int);

/*!
    \ingroup wolfssl

    \brief This function returns the maximum chain depth allowed, which is 9 by default, for a valid session i.e. there is a non-null session object (ssl).
    
    \return MAX_CHAIN_DEPTH returned if the WOLFSSL_CTX structure is not NULL. By default the value is 9.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    long sslDep = wolfSSL_get_verify_depth(ssl);

    if(sslDep > EXPECTED){
    	// The verified depth is greater than what was expected
    } else {
    	// The verified depth is smaller or equal to the expected value
    }
    \endcode
    
    \sa wolfSSL_CTX_get_verify_depth
*/
WOLFSSL_API long wolfSSL_get_verify_depth(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function gets the certificate chaining depth using the CTX structure.
    
    \return MAX_CHAIN_DEPTH returned if the CTX struct is not NULL. The constant representation of the max certificate chain peer depth.
    \return BAD_FUNC_ARG returned if the CTX structure is NULL.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_METHOD method; // protocol method
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    long ret = wolfSSL_CTX_get_verify_depth(ctx);

    if(ret == EXPECTED){
    	//  You have the expected value
    } else {
    	//  Handle an unexpected depth
    }
    \endcode
    
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_get_verify_depth
*/
WOLFSSL_API long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx);
/*!
    \ingroup openSSL
    
    \brief This function loads a certificate file into the SSL session (WOLFSSL structure).  The certificate file is provided by the file argument.  The format argument specifies the format type of the file - either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might include: The file is in the wrong format, or the wrong format has been given using the “format” argument, file doesn’t exist, can’t be read, or is corrupted, an out of memory condition occurs, Base16 decoding fails on the file
    
    \param ssl a pointer to a WOLFSSL structure, created with wolfSSL_new().
    \param file a pointer to the name of the file containing the certificate to be loaded into the wolfSSL SSL session, with format as specified by format.
    \param format the encoding type of the certificate specified by file.  Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_certificate_file(ssl, “./client-cert.pem”,
                                 SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
WOLFSSL_API int wolfSSL_use_certificate_file(WOLFSSL*, const char*, int);
/*!
    \ingroup openSSL
    
    \brief This function loads a private key file into the SSL session (WOLFSSL structure).  The key file is provided by the file argument.  The format argument specifies the format type of the file - SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes might include: The file is in the wrong format, or the wrong format has been given using the “format” argument, The file doesn’t exist, can’t be read, or is corrupted, An out of memory condition occurs, Base16 decoding fails on the file, The key file is encrypted but no password is provided
    
    \param ssl a pointer to a WOLFSSL structure, created with wolfSSL_new().
    \param file a pointer to the name of the file containing the key file to be loaded into the wolfSSL SSL session, with format as specified by format.
    \param format the encoding type of the key specified by file.  Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_PrivateKey_file(ssl, “./server-key.pem”,
                                SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
*/
WOLFSSL_API int wolfSSL_use_PrivateKey_file(WOLFSSL*, const char*, int);
/*!
    \ingroup openSSL
    
    \brief This function loads a chain of certificates into the SSL session (WOLFSSL structure).  The file containing the certificate chain is provided by the file argument, and must contain PEM-formatted certificates.  This function will process up to MAX_CHAIN_DEPTH (default = 9, defined in internal.h) certificates, plus the subject certificate.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes might include: The file is in the wrong format, or the wrong format has been given using the “format” argument, file doesn’t exist, can’t be read, or is corrupted, an out of memory condition occurs

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new()
    \param file a pointer to the name of the file containing the chain of certificates to be loaded into the wolfSSL SSL session.  Certificates must be in PEM format.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ctx;
    ...
    ret = wolfSSL_use_certificate_chain_file(ssl, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
WOLFSSL_API int wolfSSL_use_certificate_chain_file(WOLFSSL*, const char *file);
/*!
    \ingroup openSSL
    
    \brief This function loads the private RSA key used in the SSL connection into the SSL session (WOLFSSL structure).  This function is only available when wolfSSL has been compiled with the OpenSSL compatibility layer enabled (--enable-opensslExtra, #define OPENSSL_EXTRA), and is identical to the more-typically used wolfSSL_use_PrivateKey_file() function. The file argument contains a pointer to the RSA private key file, in the format specified by format.
    
    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might include: The input key file is in the wrong format, or the wrong format has been given using the “format” argument, file doesn’t exist, can’t be read, or is corrupted, an out of memory condition occurs

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new()
    \param file a pointer to the name of the file containing the RSA private key to be loaded into the wolfSSL SSL session, with format as specified by format.
    \parm format the encoding type of the RSA private key specified by file.  Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_RSAPrivateKey_file(ssl, “./server-key.pem”,
                                   SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_use_RSAPrivateKey_file
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
WOLFSSL_API int wolfSSL_use_RSAPrivateKey_file(WOLFSSL*, const char*, int);

#ifdef WOLFSSL_DER_LOAD
/*!
    \ingroup wolfssl

    \brief This function is similar to wolfSSL_CTX_load_verify_locations, but allows the loading of DER-formatted CA files into the SSL context (WOLFSSL_CTX).  It may still be used to load PEM-formatted CA files as well.  These certificates will be treated as trusted root certificates and used to verify certs received from peers during the SSL handshake. The root certificate file, provided by the file argument, may be a single certificate or a file containing multiple certificates.  If multiple CA certs are included in the same file, wolfSSL will load them in the same order they are presented in the file.  The format argument specifies the format which the certificates are in either, SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1 (DER).  Unlike wolfSSL_CTX_load_verify_locations, this function does not allow the loading of CA certificates from a given directory path. Note that this function is only available when the wolfSSL library was compiled with WOLFSSL_DER_LOAD defined.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE upon failure.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the CA certificates to be loaded into the wolfSSL SSL context, with format as specified by format.
    \param format the encoding type of the certificates specified by file.  Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_der_load_verify_locations(ctx, “./ca-cert.der”,
                                          SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
	    // error loading CA certs
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_buffer
*/
    WOLFSSL_API int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX*,
                                                    const char*, int);
#endif

#ifdef HAVE_NTRU
/*!
    \ingroup wolfssl

    \brief This function loads an NTRU private key file into the WOLFSSL Context.  It behaves like the normal version, only differing in its ability to accept an NTRU raw key file.   This function is needed since the format of the file is different than the normal key file (buffer) functions.  Please see the examples for proper usage.
    
    \return SSL_SUCCES upon success.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than the receiving buffer.
    \return NO_PASSWORD will be returned if the key file is encrypted but no password is provided.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the NTRU private key to be loaded into the wolfSSL SSL context.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_NTRUPrivateKey_file(ctx, “./ntru-key.raw”);
    if (ret != SSL_SUCCESS) {
    	// error loading NTRU private key
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
    WOLFSSL_API int wolfSSL_CTX_use_NTRUPrivateKey_file(WOLFSSL_CTX*, const char*);
    /* load NTRU private key blob */
#endif

#ifndef WOLFSSL_PEMCERT_TODER_DEFINED
/*!
    \ingroup openSSL
    
    \brief Loads the PEM certificate from fileName and converts it into DER format, placing the result into derBuffer which is of size derSz.
    
    \return Success If successful the call will return the number of bytes written to derBuffer.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return SSL_NO_PEM_HEADER will be returned if the PEM certificate header can’t be found.
    \return BUFFER_E will be returned if a chain buffer is bigger than the receiving buffer.
    
    \param filename pointer to the name of the PEM-formatted certificate for conversion.
    \param derBuffer the buffer for which the converted PEM certificate will be placed in DER format.
    \param derSz size of derBuffer.
    
    _Example_
    \code
    int derSz;
    byte derBuf[...];
    derSz = wolfSSL_PemCertToDer(“./cert.pem”, derBuf, sizeof(derBuf));
    \endcode
    
    \sa SSL_get_peer_certificate
*/
    WOLFSSL_API int wolfSSL_PemCertToDer(const char*, unsigned char*, int);
    #define WOLFSSL_PEMCERT_TODER_DEFINED
#endif

#endif /* !NO_FILESYSTEM && !NO_CERTS */

/*!
    \ingroup wolfssl

    \brief This function creates a new SSL context, taking a desired SSL/TLS protocol method for input.
    
    \return pointer If successful the call will return a pointer to the newly-created WOLFSSL_CTX.
    \return NULL upon failure.
    
    \param method pointer to the desired WOLFSSL_METHOD to use for the SSL context. This is created using one of the wolfSSLvXX_XXXX_method() functions to specify SSL/TLS/DTLS protocol level.
    
    _Example_
    \code
    
    \endcode
    WOLFSSL_CTX*    ctx    = 0;
    WOLFSSL_METHOD* method = 0;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
    	// context creation failed
    }
    
    \sa wolfSSL_new
*/
WOLFSSL_API WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);
/*!
    \ingroup wolfssl
    
    \brief This function creates a new SSL session, taking an already created SSL context as input.
    
    \return * If successful the call will return a pointer to the newly-created wolfSSL structure.
    \return NULL Upon failure.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL*     ssl = NULL;
    WOLFSSL_CTX* ctx = 0;

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
	    context creation failed
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
	    SSL object creation failed
    }
    \endcode
    
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_is_server(WOLFSSL*);
WOLFSSL_API WOLFSSL* wolfSSL_write_dup(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function assigns a file descriptor (fd) as the input/output facility for the SSL connection. Typically this will be a socket file descriptor.
    
    \return SSL_SUCCESS upon success.
    \return Bad_FUNC_ARG upon failure.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param fd file descriptor to use with SSL/TLS connection.
    
    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
    	// failed to set SSL file descriptor
    }
    \endcode
    
    \sa wolfSSL_SetIOSend
    \sa wolfSSL_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
*/
WOLFSSL_API int  wolfSSL_set_fd (WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_write_fd (WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_read_fd (WOLFSSL*, int);
/*!
    \ingroup wolfssl

    \brief Get the name of cipher at priority level passed in.

    \return string Success
    \return 0 Priority is either out of bounds or not valid.
    
    \param priority Integer representing the priority level of a cipher.
    
    _Example_
    \code
    printf("The cipher at 1 is %s", wolfSSL_get_cipher_list(1));
    \endcode
    
    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
WOLFSSL_API char* wolfSSL_get_cipher_list(int priority);
WOLFSSL_API char* wolfSSL_get_cipher_list_ex(WOLFSSL* ssl, int priority);
/*!
    \ingroup wolfssl

    \brief This function gets the ciphers enabled in wolfSSL.
    
    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the buf parameter was NULL or if the len argument was less than or equal to zero.
    \return BUFFER_E returned if the buffer is not large enough and will overflow.
    
    \param buf a char pointer representing the buffer.
    \param len the length of the buffer.
    
    _Example_
    \code
    static void ShowCiphers(void){
	char* ciphers;
	int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

	if(ret == SSL_SUCCES){
	    	printf(“%s\n”, ciphers);
	    }
    }
    \endcode
    
    \sa GetCipherNames
    \sa wolfSSL_get_cipher_list
    \sa ShowCiphers
*/
WOLFSSL_API int  wolfSSL_get_ciphers(char*, int);
/*!
    \ingroup wolfssl

    \brief This function gets the cipher name in the format DHE-RSA by passing through argument to wolfSSL_get_cipher_name_internal.
    
    \return string This function returns the string representation of the cipher suite that was matched.
    \return NULL error or cipher not found.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    char* cipherS = wolfSSL_get_cipher_name(ssl);

    if(cipher == NULL){
	    // There was not a cipher suite matched
    } else {
	    // There was a cipher suite matched
	    printf(“%s\n”, cipherS);
    }
    \endcode
    
    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
*/
WOLFSSL_API const char* wolfSSL_get_cipher_name(WOLFSSL* ssl);
WOLFSSL_API const char* wolfSSL_get_shared_ciphers(WOLFSSL* ssl, char* buf,
    int len);
WOLFSSL_API const char* wolfSSL_get_curve_name(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function returns the file descriptor (fd) used as the input/output facility for the SSL connection.  Typically this will be a socket file descriptor.
    
    \return fd If successful the call will return the SSL session file descriptor.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_fd(ssl);
    ...
    \endcode
    
    \sa wolfSSL_set_fd
*/
WOLFSSL_API int  wolfSSL_get_fd(const WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function informs the WOLFSSL object that the underlying I/O is non-blocking. After an application creates a WOLFSSL object, if it will be used with a non-blocking socket, call wolfSSL_set_using_nonblock() on it. This lets the WOLFSSL object know that receiving EWOULDBLOCK means that the recvfrom call would block rather than that it timed out.
    
    \return none No return.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param nonblock value used to set non-blocking flag on WOLFSSL object.  Use 1 to specify non-blocking, otherwise 0.
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_using_nonblock(ssl, 1);
    \endcode
    
    \sa wolfSSL_get_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
WOLFSSL_API void wolfSSL_set_using_nonblock(WOLFSSL*, int);
/*!
    \ingroup wolfssl

    \brief This function allows the application to determine if wolfSSL is using non-blocking I/O.  If wolfSSL is using non-blocking I/O, this function will return 1, otherwise 0. After an application creates a WOLFSSL object, if it will be used with a non-blocking socket, call wolfSSL_set_using_nonblock() on it. This lets the WOLFSSL object know that receiving EWOULDBLOCK means that the recvfrom call would block rather than that it timed out.
    
    \return 0 underlying I/O is blocking.
    \return 1 underlying I/O is non-blocking.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_get_using_nonblock(ssl);
    if (ret == 1) {
    	// underlying I/O is non-blocking
    }
    ...
    \endcode
    
    \sa wolfSSL_set_session
*/
WOLFSSL_API int  wolfSSL_get_using_nonblock(WOLFSSL*);
/* please see note at top of README if you get an error from connect */
WOLFSSL_API int  wolfSSL_connect(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function writes sz bytes from the buffer, data, to the SSL connection, ssl. If necessary, wolfSSL_write() will negotiate an SSL/TLS session if the handshake has not already been performed yet by wolfSSL_connect() or wolfSSL_accept(). wolfSSL_write() works with both blocking and non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_write() will return when the underlying I/O could not satisfy the needs of wolfSSL_write() to continue.  In this case, a call to wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call to wolfSSL_write() when the underlying I/O is ready. If the underlying I/O is blocking, wolfSSL_write() will only return once the buffer data of size sz has been completely written or an error occurred.
    
    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and the application needs to call wolfSSL_write() again.  Use wolfSSL_get_error() to get a specific error code.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data data buffer which will be sent to peer.
    \param sz size, in bytes, of data to send to the peer (data).
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags;
    int ret;
    ...

    ret = wolfSSL_write(ssl, msg, msgSz);
    if (ret <= 0) {
    	// wolfSSL_write() failed, call wolfSSL_get_error()
    }
    \endcode
    
    \sa wolfSSL_send
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
WOLFSSL_API int  wolfSSL_write(WOLFSSL*, const void*, int);
/*!
    \ingroup wolfssl

    \brief This function reads sz bytes from the SSL session (ssl) internal read buffer into the buffer data. The bytes read are removed from the internal receive buffer. If necessary wolfSSL_read() will negotiate an SSL/TLS session if the handshake has not already been performed yet by wolfSSL_connect() or wolfSSL_accept(). The SSL/TLS protocol uses SSL records which have a maximum size of 16kB (the max record size can be controlled by the MAX_RECORD_SIZE define in <wolfssl_root>/wolfssl/internal.h).  As such, wolfSSL needs to read an entire SSL record internally before it is able to process and decrypt the record.  Because of this, a call to wolfSSL_read() will only be able to return the maximum buffer size which has been decrypted at the time of calling.  There may be additional not-yet-decrypted data waiting in the internal wolfSSL receive buffer which will be retrieved and decrypted with the next call to wolfSSL_read(). If sz is larger than the number of bytes in the internal read buffer, SSL_read() will return the bytes available in the internal read buffer.  If no bytes are buffered in the internal read buffer yet, a call to wolfSSL_read() will trigger processing of the next record.
    
    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure.  This may be caused by a either a clean (close notify alert) shutdown or just that the peer closed the connection.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and the application needs to call wolfSSL_read() again.  Use wolfSSL_get_error() to get a specific error code.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_read() will place data read.
    \param sz number of bytes to read into data.
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }

    See wolfSSL examples (client, server, echoclient, echoserver) for more complete examples of wolfSSL_read().
    \endcode
    
    \sa wolfSSL_recv
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
WOLFSSL_API int  wolfSSL_read(WOLFSSL*, void*, int);
/*!
    \ingroup wolfssl

    \brief This function copies sz bytes from the SSL session (ssl) internal read buffer into the buffer data. This function is identical to wolfSSL_read() except that the data in the internal SSL session receive buffer is not removed or modified. If necessary, like wolfSSL_read(), wolfSSL_peek() will negotiate an SSL/TLS session if the handshake has not already been performed yet by wolfSSL_connect() or wolfSSL_accept(). The SSL/TLS protocol uses SSL records which have a maximum size of 16kB (the max record size can be controlled by the MAX_RECORD_SIZE define in <wolfssl_root>/wolfssl/internal.h).  As such, wolfSSL needs to read an entire SSL record internally before it is able to process and decrypt the record.  Because of this, a call to wolfSSL_peek() will only be able to return the maximum buffer size which has been decrypted at the time of calling.  There may be additional not-yet-decrypted data waiting in the internal wolfSSL receive buffer which will be retrieved and decrypted with the next call to wolfSSL_peek() / wolfSSL_read(). If sz is larger than the number of bytes in the internal read buffer, SSL_peek() will return the bytes available in the internal read buffer.  If no bytes are buffered in the internal read buffer yet, a call to wolfSSL_peek() will trigger processing of the next record.
    
    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure.  This may be caused by a either a clean (close notify alert) shutdown or just that the peer closed the connection.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and the application needs to call wolfSSL_peek() again.  Use wolfSSL_get_error() to get a specific error code.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_peek() will place data read.
    \param sz number of bytes to read into data.
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...
    
    input = wolfSSL_peek(ssl, reply, sizeof(reply));
    if (input > 0) {
	    // “input” number of bytes returned into buffer “reply”
    }
    \endcode
    
    \sa wolfSSL_read
*/
WOLFSSL_API int  wolfSSL_peek(WOLFSSL*, void*, int);
/*!
    \ingroup wolfssl

    \brief This function is called on the server side and waits for an SSL client to initiate the SSL/TLS handshake.  When this function is called, the underlying communication channel has already been set up. wolfSSL_accept() works with both blocking and non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_accept() will return when the underlying I/O could not satisfy the needs of wolfSSL_accept to continue the handshake.  In this case, a call to wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call to wolfSSL_accept when data is available to read and wolfSSL will pick up where it left off. When using a non-blocking socket, nothing needs to be done, but select() can be used to check for the required condition. If the underlying I/O is blocking, wolfSSL_accept() will only return once the handshake has been finished or an error occurred.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a more detailed error code, call wolfSSL_get_error().
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
WOLFSSL_API int  wolfSSL_accept(WOLFSSL*);
#ifdef WOLFSSL_TLS13
WOLFSSL_API int  wolfSSL_send_hrr_cookie(WOLFSSL* ssl,
    const unsigned char* secret, unsigned int secretSz);
WOLFSSL_API int  wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_no_dhe_psk(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_update_keys(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_CTX_allow_post_handshake_auth(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_allow_post_handshake_auth(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_request_certificate(WOLFSSL* ssl);

/*!
    \ingroup wolfssl

    \brief This function is called on the client side and initiates an SSL/TLS handshake with a server.  When this function is called, the underlying communication channel has already been set up. wolfSSL_connect() works with both blocking and non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_connect() will return when the underlying I/O could not satisfy the needs of wolfSSL_connect to continue the handshake.  In this case, a call to wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call to wolfSSL_connect() when the underlying I/O is ready and wolfSSL will pick up where it left off. When using a non-blocking socket, nothing needs to be done, but select() can be used to check for the required condition. If the underlying I/O is blocking, wolfSSL_connect() will only return once the handshake has been finished or an error occurred. wolfSSL takes a different approach to certificate verification than OpenSSL does.  The default policy for the client is to verify the server, this means that if you don't load CAs to verify the server you'll get a connect error, unable to verify (-155).  It you want to mimic OpenSSL behavior of having SSL_connect succeed even if verifying the server fails and reducing security you can do this by calling: SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); before calling SSL_new();  Though it's not recommended.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred.  To get a more detailed error code, call wolfSSL_get_error().
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    
    \sa wolfSSL_get_error
    \sa wolfSSL_accept
*/
WOLFSSL_API int  wolfSSL_connect_TLSv13(WOLFSSL*);
WOLFSSL_API int  wolfSSL_accept_TLSv13(WOLFSSL*);

#ifdef WOLFSSL_EARLY_DATA
WOLFSSL_API int  wolfSSL_CTX_set_max_early_data(WOLFSSL_CTX* ctx,
                                                unsigned int sz);
WOLFSSL_API int  wolfSSL_set_max_early_data(WOLFSSL* ssl, unsigned int sz);
WOLFSSL_API int  wolfSSL_write_early_data(WOLFSSL*, const void*, int, int*);
WOLFSSL_API int  wolfSSL_read_early_data(WOLFSSL*, void*, int, int*);
#endif
#endif
/*!
    \ingroup wolfssl

    \brief This function frees an allocated WOLFSSL_CTX object.  This function decrements the CTX reference count and only frees the context when the reference count has reached 0.
    
    \return none No return.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_free(ctx);
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API void wolfSSL_CTX_free(WOLFSSL_CTX*);
/*!
    \ingroup wolfssl
    
    \brief This function frees an allocated wolfSSL object.

    \return none No return.
    
    \param ssl pointer to the SSL object, created with wolfSSL_new().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL* ssl = 0;
    ...
    wolfSSL_free(ssl);
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API void wolfSSL_free(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function shuts down an active SSL/TLS connection using the SSL session, ssl.  This function will try to send a “close notify” alert to the peer. The calling application can choose to wait for the peer to send its “close notify” alert in response or just go ahead and shut down the underlying connection after directly calling wolfSSL_shutdown (to save resources).  Either option is allowed by the TLS specification.  If the underlying connection will be used again in the future, the complete two-directional shutdown procedure must be performed to keep synchronization intact between the peers. wolfSSL_shutdown() works with both blocking and non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_shutdown() will return an error if the underlying I/O could not satisfy the needs of wolfSSL_shutdown() to continue. In this case, a call to wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call to wolfSSL_shutdown() when the underlying I/O is ready.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_SHUTDOWN_NOT_DONE will be returned when shutdown has not finished, and the function should be called again.
    \return SSL_FATAL_ERROR will be returned upon failure.  Call wolfSSL_get_error() for a more specific error code.
    
    \param ssl pointer to the SSL session created with wolfSSL_new().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_shutdown(ssl);
    if (ret != 0) {
	    failed to shut down SSL connection
    }
    \endcode
    
    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API int  wolfSSL_shutdown(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function writes sz bytes from the buffer, data, to the SSL connection, ssl, using the specified flags for the underlying write operation. If necessary wolfSSL_send() will negotiate an SSL/TLS session if the handshake has not already been performed yet by wolfSSL_connect() or wolfSSL_accept(). wolfSSL_send() works with both blocking and non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_send() will return when the underlying I/O could not satisfy the needs of wolfSSL_send to continue.  In this case, a call to wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call to wolfSSL_send() when the underlying I/O is ready. If the underlying I/O is blocking, wolfSSL_send() will only return once the buffer data of size sz has been completely written or an error occurred.

    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and the application needs to call wolfSSL_send() again.  Use wolfSSL_get_error() to get a specific error code.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data data buffer to send to peer.
    \param sz size, in bytes, of data to be sent to peer.
    \param flags the send flags to use for the underlying send operation.
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags = ... ;
    ...

    input = wolfSSL_send(ssl, msg, msgSz, flags);
    if (input != msgSz) {
    	// wolfSSL_send() failed
    }
    \endcode
    
    \sa wolfSSL_write
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
WOLFSSL_API int  wolfSSL_send(WOLFSSL*, const void*, int sz, int flags);
/*!
    \ingroup wolfssl

    \brief This function reads sz bytes from the SSL session (ssl) internal read buffer into the buffer data using the specified flags for the underlying recv operation.  The bytes read are removed from the internal receive buffer.  This function is identical to wolfSSL_read() except that it allows the application to set the recv flags for the underlying read operation. If necessary wolfSSL_recv() will negotiate an SSL/TLS session if the handshake has not already been performed yet by wolfSSL_connect() or wolfSSL_accept(). The SSL/TLS protocol uses SSL records which have a maximum size of 16kB (the max record size can be controlled by the MAX_RECORD_SIZE define in <wolfssl_root>/wolfssl/internal.h). As such, wolfSSL needs to read an entire SSL record internally before it is able to process and decrypt the record. Because of this, a call to wolfSSL_recv() will only be able to return the maximum buffer size which has been decrypted at the time of calling.  There may be additional not-yet-decrypted data waiting in the internal wolfSSL receive buffer which will be retrieved and decrypted with the next call to wolfSSL_recv(). If sz is larger than the number of bytes in the internal read buffer, SSL_recv() will return the bytes available in the internal read buffer.  If no bytes are buffered in the internal read buffer yet, a call to wolfSSL_recv() will trigger processing of the next record.
    
    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure. This may be caused by a either a clean (close notify alert) shutdown or just that the peer closed the connection. Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and the application needs to call wolfSSL_recv() again.  Use wolfSSL_get_error() to get a specific error code.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_recv() will place data read.
    \param sz number of bytes to read into data.
    \param flags the recv flags to use for the underlying recv operation.
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    int flags = ... ;
    ...

    input = wolfSSL_recv(ssl, reply, sizeof(reply), flags);
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }
    \endcode
    
    \sa wolfSSL_read
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
WOLFSSL_API int  wolfSSL_recv(WOLFSSL*, void*, int sz, int flags);

WOLFSSL_API void wolfSSL_CTX_set_quiet_shutdown(WOLFSSL_CTX*, int);
WOLFSSL_API void wolfSSL_set_quiet_shutdown(WOLFSSL*, int);

/*!
    \ingroup wolfssl

    \brief This function returns a unique error code describing why the previous API function call (wolfSSL_connect, wolfSSL_accept, wolfSSL_read, wolfSSL_write, etc.) resulted in an error return code (SSL_FAILURE).  The return value of the previous function is passed to wolfSSL_get_error through ret. After wolfSSL_get_error is called and returns the unique error code, wolfSSL_ERR_error_string() may be called to get a human-readable error string.  See wolfSSL_ERR_error_string() for more information.

    \return code On successful completion, this function will return the unique error code describing why the previous API function failed.
    \return SSL_ERROR_NONE will be returned if ret > 0.
    
    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param ret return value of the previous function that resulted in an error return code.
    
    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode
    
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
WOLFSSL_API int  wolfSSL_get_error(WOLFSSL*, int);
/*!
    \ingroup wolfssl

    \brief This function gets the alert history.
    
    \return SSL_SUCCESS returned when the function completed successfully. Either there was alert history or there wasn’t, either way, the return value is SSL_SUCCESS.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param h a pointer to a WOLFSSL_ALERT_HISTORY structure that will hold the WOLFSSL struct’s alert_history member’s value.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_ALERT_HISTORY* h;
    ...
    wolfSSL_get_alert_history(ssl, h);
    // h now has a copy of the ssl->alert_history  contents
    \endcode
    
    \sa wolfSSL_get_error
*/
WOLFSSL_API int  wolfSSL_get_alert_history(WOLFSSL*, WOLFSSL_ALERT_HISTORY *);

/*!
    \ingroup wolfssl

    \brief This function sets the session to be used when the SSL object, ssl, is used to establish a SSL/TLS connection. For session resumption, before calling wolfSSL_shutdown() with your session object, an application should save the session ID from the object with a call to wolfSSL_get_session(), which returns a pointer to the session.  Later, the application should create a new WOLFSSL object and assign the saved session with wolfSSL_set_session().  At this point, the application may call wolfSSL_connect() and wolfSSL will try to resume the session.  The wolfSSL server code allows session resumption by default.
    
    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return SSL_FAILURE will be returned on failure.  This could be caused by the session cache being disabled, or if the session has timed out.
    
    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param session pointer to the WOLFSSL_SESSION used to set the session for ssl.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    WOLFSSL_SESSION* session;
    ...

    ret = wolfSSL_get_session(ssl, session);
    if (ret != SSL_SUCCESS) {
    	// failed to set the SSL session
    }
    ...
    \endcode
    
    \sa wolfSSL_get_session
*/
WOLFSSL_API int        wolfSSL_set_session(WOLFSSL* ssl,WOLFSSL_SESSION* session);
WOLFSSL_API long       wolfSSL_SSL_SESSION_set_timeout(WOLFSSL_SESSION* session, long t);
/*!
    \ingroup wolfssl

    \brief This function returns a pointer to the current session (WOLFSSL_SESSION) used in ssl.  The WOLFSSL_SESSION pointed to contains all the necessary information required to perform a session resumption and reestablish the connection without a new handshake. For session resumption, before calling wolfSSL_shutdown() with your session object, an application should save the session ID from the object with a call to wolfSSL_get_session(), which returns a pointer to the session.  Later, the application should create a new WOLFSSL object and assign the saved session with wolfSSL_set_session().  At this point, the application may call wolfSSL_connect() and wolfSSL will try to resume the session.  The wolfSSL server code allows session resumption by default.
    
    \return pointer If successful the call will return a pointer to the the current SSL session object.
    \return NULL will be returned if ssl is NULL, the SSL session cache is disabled, wolfSSL doesn’t have the Session ID available, or mutex functions fail.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    WOLFSSL_SESSION* session = 0;
    ...
    session = wolfSSL_get_session(ssl);
    if (session == NULL) {
	    // failed to get session pointer
    }
    ...
    \endcode
    
    \sa wolfSSL_set_session
*/
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function flushes session from the session cache which have expired.  The time, tm, is used for the time comparison. Note that wolfSSL currently uses a static table for sessions, so no flushing is needed.  As such, this function is currently just a stub.  This function provides OpenSSL compatibility (SSL_flush_sessions) when wolfSSL is compiled with the OpenSSL compatibility layer.
    
    \return none No returns.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param tm time used in session expiration comparison.
    
    _Example_
    \code
    WOLFSSL_CTX* ssl;
    ...
    wolfSSL_flush_sessions(ctx, time(0));
    \endcode
    
    \sa wolfSSL_get_session
    \sa wolfSSL_set_session
*/
WOLFSSL_API void       wolfSSL_flush_sessions(WOLFSSL_CTX *ctx, long tm);
/*!
    \ingroup wolfssl

    \brief This function associates the client session with the server id. If the newSession flag is on, an existing session won’t be reused.
    
    \return SSL_SUCCESS returned if the finction executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct or id parameter is NULL or if len is not greater than zero.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param id a constant byte pointer that will be copied to the serverID member of the WOLFSSL_SESSION structure.
    \param len an int type representing the length of the session id parameter.
    \param newSession an int type representing the flag to denote whether to reuse a session or not.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    const byte id[MAX_SIZE];  // or dynamically create space
    int len = 0; // initialize length
    int newSession = 0; // flag to allow
    …
    int ret = wolfSSL_SetServerID(ssl, id, len, newSession);

    if(ret){
	// The Id was successfully set
    }
    \endcode
    
    \sa GetSessionClient
*/
WOLFSSL_API int        wolfSSL_SetServerID(WOLFSSL* ssl, const unsigned char*,
                                         int, int);

#ifdef SESSION_INDEX
/*!
    \ingroup wolfssl

    \brief This function gets the session index of the WOLFSSL structure.
    
    \return int The function returns an int type representing the sessionIndex within the WOLFSSL struct.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int sesIdx = wolfSSL_GetSessionIndex(ssl);

    if(sesIdx < 0 || sesIdx > sizeof(ssl->sessionIndex)/sizeof(int)){
    	// You have an out of bounds index number and something is not right.
    }
    \endcode
    
    \sa wolfSSL_GetSessionAtIndex
*/
WOLFSSL_API int wolfSSL_GetSessionIndex(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function gets the session at specified index of the session cache and copies it into memory. The WOLFSSL_SESSION structure holds the session information.
    
    \return SSL_SUCCESS returned if the function executed successfully and no errors were thrown.
    \return BAD_MUTEX_E returned if there was an unlock or lock mutex error.
    \return SSL_FAILURE returned if the function did not execute successfully.
    
    \param idx an int type representing the session index.
    \param session a pointer to the WOLFSSL_SESSION structure.
    
    _Example_
    \code
    int idx; // The index to locate the session.
    WOLFSSL_SESSION* session;  // Buffer to copy to.
    ...
    if(wolfSSL_GetSessionAtIndex(idx, session) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode
    
    \sa UnLockMutex
    \sa LockMutex
    \sa wolfSSL_GetSessionIndex
*/
WOLFSSL_API int wolfSSL_GetSessionAtIndex(int index, WOLFSSL_SESSION* session);
#endif /* SESSION_INDEX */

#if defined(SESSION_INDEX) && defined(SESSION_CERTS)
/*!
    \ingroup wolfssl

    \brief Returns the peer certificate chain from the WOLFSSL_SESSION struct.
    
    \return pointer A pointer to a WOLFSSL_X509_CHAIN structure that contains the peer certification chain.
    
    \param session a pointer to a WOLFSSL_SESSION structure.
    
    _Example_
    \code
    WOLFSSL_SESSION* session;
    WOLFSSL_X509_CHAIN* chain;
    ...
    chain = wolfSSL_SESSION_get_peer_chain(session);
    if(!chain){
    	// There was no chain. Failure case.
    }
    \endcode
    
    \sa get_locked_session_stats
    \sa wolfSSL_GetSessionAtIndex
    \sa wolfSSL_GetSessionIndex
    \sa AddSession
*/
WOLFSSL_API
    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);
#endif /* SESSION_INDEX && SESSION_CERTS */

typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*);
typedef int (pem_password_cb)(char*, int, int, void*);

/*!
    \ingroup wolfssl

    \brief This function sets the verification method for remote peers and also allows a verify callback to be registered with the SSL context.  The verify callback will be called only when a verification failure has occurred.  If no verify callback is desired, the NULL pointer can be used for verify_callback. The verification mode of peer certificates is a logically OR’d list of flags.  The possible flag values include: SSL_VERIFY_NONE Client mode: the client will not verify the certificate received from the server and the handshake will continue as normal. Server mode: the server will not send a certificate request to the client.  As such, client verification will not be enabled. SSL_VERIFY_PEER Client mode: the client will verify the certificate received from the server during the handshake.  This is turned on by default in wolfSSL, therefore, using this option has no effect. Server mode: the server will send a certificate request to the client and verify the client certificate received. SSL_VERIFY_FAIL_IF_NO_PEER_CERT Client mode: no effect when used on the client side. Server mode: the verification will fail on the server side if the client fails to send a certificate when requested to do so (when using SSL_VERIFY_PEER on the SSL server). SSL_VERIFY_FAIL_EXCEPT_PSK Client mode: no effect when used on the client side. Server mode: the verification is the same as SSL_VERIFY_FAIL_IF_NO_PEER_CERT except in the case of a PSK connection. If a PSK connection is being made then the connection will go through without a peer cert.

    \return none No return.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode session timeout value in seconds
    \param verify_callback callback to be called when verification fails.  If no callback is desired, the NULL pointer can be used for verify_callback.
    
    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
                     SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    \endcode
    
    \sa wolfSSL_set_verify
*/
WOLFSSL_API void wolfSSL_CTX_set_verify(WOLFSSL_CTX*, int,
                                      VerifyCallback verify_callback);
/*!
    \ingroup wolfssl

    \brief This function sets the verification method for remote peers and also allows a verify callback to be registered with the SSL session.  The verify callback will be called only when a verification failure has occurred.  If no verify callback is desired, the NULL pointer can be used for verify_callback. The verification mode of peer certificates is a logically OR’d list of flags.  The possible flag values include: SSL_VERIFY_NONE Client mode: the client will not verify the certificate received from the server and the handshake will continue as normal. Server mode: the server will not send a certificate request to the client.  As such, client verification will not be enabled. SSL_VERIFY_PEER Client mode: the client will verify the certificate received from the server during the handshake. This is turned on by default in wolfSSL, therefore, using this option has no effect. Server mode: the server will send a certificate request to the client and verify the client certificate received. SSL_VERIFY_FAIL_IF_NO_PEER_CERT Client mode: no effect when used on the client side. Server mode: the verification will fail on the server side if the client fails to send a certificate when requested to do so (when using SSL_VERIFY_PEER on the SSL server). SSL_VERIFY_FAIL_EXCEPT_PSK Client mode: no effect when used on the client side. Server mode: the verification is the same as SSL_VERIFY_FAIL_IF_NO_PEER_CERT except in the case of a PSK connection. If a PSK connection is being made then the connection will go through without a peer cert.

    \return none No return.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param mode session timeout value in seconds.
    \param verify_callback callback to be called when verification fails.  If no callback is desired, the NULL pointer can be used for verify_callback.
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    \endcode
    
    \sa wolfSSL_CTX_set_verify
*/
WOLFSSL_API void wolfSSL_set_verify(WOLFSSL*, int, VerifyCallback verify_callback);
/*!
    \ingroup wolfssl

    \brief This function stores user CTX object information for verify callback.
    
    \return none No return.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx a void pointer that is set to WOLFSSL structure’s verifyCbCtx member’s value.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    (void*)ctx;
    ...
    if(ssl != NULL){
    wolfSSL_SetCertCbCtx(ssl, ctx);
    } else {
	    // Error case, the SSL is not initialized properly.
    }
    \endcode
    
    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
WOLFSSL_API void wolfSSL_SetCertCbCtx(WOLFSSL*, void*);

/*!
    \ingroup wolfssl

    \brief This function returns the number of bytes which are buffered and available in the SSL object to be read by wolfSSL_read().
    
    \return int This function returns the number of bytes pending.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    int pending = 0;
    WOLFSSL* ssl = 0;
    ...

    pending = wolfSSL_pending(ssl);
    printf(“There are %d bytes buffered and available for reading”, pending);
    \endcode
    
    \sa wolfSSL_recv
    \sa wolfSSL_read
    \sa wolfSSL_peek
*/
WOLFSSL_API int  wolfSSL_pending(WOLFSSL*);

/*!
    \ingroup wolfssl

    \brief This function is for OpenSSL compatibility (SSL_load_error_string) only and takes no action.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    wolfSSL_load_error_strings();
    \endcode
    
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
WOLFSSL_API void wolfSSL_load_error_strings(void);
/*!
    \ingroup wolfssl

    \brief This function is called internally in wolfSSL_CTX_new(). This function is a wrapper around wolfSSL_Init() and exists for OpenSSL compatibility (SSL_library_init) when wolfSSL has been compiled with OpenSSL compatibility layer.  wolfSSL_Init() is the more typically-used wolfSSL initialization function.
    
    \return SSL_SUCCESS If successful the call will return.
    \return SSL_FATAL_ERROR is returned upon failure.
    
    \param none No parameters.
    
    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_library_init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL
    }
    ...
    \endcode
    
    \sa wolfSSL_Init
    \sa wolfSSL_Cleanup
*/
WOLFSSL_API int  wolfSSL_library_init(void);
/*!
    \ingroup wolfssl

    \brief This function enables or disables SSL session caching.  Behavior depends on the value used for mode.  The following values for mode are available: SSL_SESS_CACHE_OFF- disable session caching. Session caching is turned on by default. SSL_SESS_CACHE_NO_AUTO_CLEAR - Disable auto-flushing of the session cache. Auto-flushing is turned on by default.
    
    \return SSL_SUCCESS will be returned upon success.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode modifier used to change behavior of the session cache.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (ret != SSL_SUCCESS) {
    	// failed to turn SSL session caching off
    }
    \endcode
    
    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_timeout
*/
WOLFSSL_API long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX*, long);

#ifdef HAVE_SECRET_CALLBACK
typedef int (*SessionSecretCb)(WOLFSSL* ssl,
                                        void* secret, int* secretSz, void* ctx);
/*!
    \ingroup wolfssl

    \brief This function sets the session secret callback function. The SessionSecretCb type has the signature: int (*SessionSecretCb)(WOLFSSL* ssl, void* secret, int* secretSz, void* ctx). The sessionSecretCb member of the WOLFSSL struct is set to the parameter cb.
    
    \return SSL_SUCCESS returned if the execution of the function did not return an error.
    \return SSL_FATAL_ERROR returned if the WOLFSSL structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a SessionSecretCb type that is a function pointer with the above signature.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    // Signature of SessionSecretCb
    int SessionSecretCB (WOLFSSL* ssl, void* secret, int* secretSz, void* ctx) = SessionSecretCb;
    …
    int wolfSSL_set_session_secret_cb(ssl, SessionSecretCB, (void*)ssl->ctx){
	    // Function body.
    }
    \endcode
    
    \sa SessionSecretCb
*/
WOLFSSL_API int  wolfSSL_set_session_secret_cb(WOLFSSL*, SessionSecretCb, void*);
#endif /* HAVE_SECRET_CALLBACK */

/* session cache persistence */
/*!
    \ingroup wolfssl

    \brief This function persists the session cache to file. It doesn’t use memsave because of additional memory use.
    
    \return SSL_SUCCESS returned if the function executed without error. The session cache has been written to a file.
    \return SSL_BAD_FILE returned if fname cannot be opened or is otherwise corrupt.
    \return FWRITE_ERROR returned if XFWRITE failed to write to the file.
    \return BAD_MUTEX_E returned if there was a mutex lock failure.
    
    \param name is a constant char pointer that points to a file for writing.
    
    _Example_
    \code
    const char* fname;
    ...
    if(wolfSSL_save_session_cache(fname) != SSL_SUCCESS){	
    	// Fail to write to file.
    }
    \endcode
    
    \sa XFWRITE
    \sa wolfSSL_restore_session_cache
    \sa wolfSSL_memrestore_session_cache
*/
WOLFSSL_API int  wolfSSL_save_session_cache(const char*);
/*!
    \ingroup wolfssl

    \brief This function restores the persistent session cache from file. It does not use memstore because of additional memory use.
    
    \return SSL_SUCCESS returned if the function executed without error.
    \return SSL_BAD_FILE returned if the file passed into the function was corrupted and could not be opened by XFOPEN.
    \return FREAD_ERROR returned if the file had a read error from XFREAD.
    \return CACHE_MATCH_ERROR returned if the session cache header match failed.
    \return BAD_MUTEX_E returned if there was a mutex lock failure.
    
    \param fname a constant char pointer file input that will be read.
    
    _Example_
    \code
    const char *fname;
    ...
    if(wolfSSL_restore_session_cache(fname) != SSL_SUCCESS){
        // Failure case. The function did not return SSL_SUCCESS.
    }
    \endcode
    
    \sa XFREAD
    \sa XFOPEN
*/
WOLFSSL_API int  wolfSSL_restore_session_cache(const char*);
/*!
    \ingroup wolfssl

    \brief This function persists session cache to memory.
    
    \return SSL_SUCCESS returned if the function executed without error. The session cache has been successfully persisted to memory.
    \return BAD_MUTEX_E returned if there was a mutex lock error.
    \return BUFFER_E returned if the buffer size was too small.
    
    \param mem a void pointer representing the destination for the memory copy, XMEMCPY().
    \param sz an int type representing the size of mem.
    
    _Example_
    \code
    void* mem;
    int sz; // Max size of the memory buffer.
    …
    if(wolfSSL_memsave_session_cache(mem, sz) != SSL_SUCCESS){
    	// Failure case, you did not persist the session cache to memory
    }
    \endcode
    
    \sa XMEMCPY
    \sa wolfSSL_get_session_cache_memsize
*/
WOLFSSL_API int  wolfSSL_memsave_session_cache(void*, int);
/*!
    \ingroup wolfssl

    \brief This function restores the persistent session cache from memory.
    
    \return SSL_SUCCESS returned if the function executed without an error.
    \return BUFFER_E returned if the memory buffer is too small.
    \return BAD_MUTEX_E returned if the session cache mutex lock failed.
    \return CACHE_MATCH_ERROR returned if the session cache header match failed.
    
    \param mem a constant void pointer containing the source of the restoration.
    \param sz an integer representing the size of the memory buffer.
    
    _Example_
    \code
    const void* memoryFile; 
    int szMf;
    ...
    if(wolfSSL_memrestore_session_cache(memoryFile, szMf) != SSL_SUCCESS){
    	// Failure case. SSL_SUCCESS was not returned.
    }
    \endcode
    
    \sa wolfSSL_save_session_cache
*/
WOLFSSL_API int  wolfSSL_memrestore_session_cache(const void*, int);
/*!
    \ingroup wolfssl

    \brief This function returns how large the session cache save buffer should be.
    
    \return int This function returns an integer that represents the size of the session cache save buffer.
    
    \param none No parameters.
    
    _Example_
    \code
    int sz = // Minimum size for error checking;
    ...
    if(sz < wolfSSL_get_session_cache_memsize()){
        // Memory buffer is too small
    }
    \endcode
    
    \sa wolfSSL_memrestore_session_cache
*/
WOLFSSL_API int  wolfSSL_get_session_cache_memsize(void);

/* certificate cache persistence, uses ctx since certs are per ctx */
/*!
    \ingroup wolfssl

    \brief This function writes the cert cache from memory to file.
    
    \return SSL_SUCCESS if CM_SaveCertCache exits normally.
    \return BAD_FUNC_ARG is returned if either of the arguments are NULL.
    \return SSL_BAD_FILE if the cert cache save file could not be opened.
    \return BAD_MUTEX_E if the lock mutex failed.
    \return MEMORY_E the allocation of memory failed.
    \return FWRITE_ERROR Certificate cache file write failed.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, holding the certificate information.
    \param fname  the cert cache buffer.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    const char* fname;
    ...
    if(wolfSSL_CTX_save_cert_cache(ctx, fname)){
	    // file was written.
    }
    \endcode
    
    \sa CM_SaveCertCache
    \sa DoMemSaveCertCache
*/
WOLFSSL_API int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX*, const char*);
/*!
    \ingroup wolfssl

    \brief This function persistes certificate cache from a file.
    
    \return SSL_SUCCESS returned if the function, CM_RestoreCertCache, executes normally.
    \return SSL_BAD_FILE returned if XFOPEN returns XBADFILE. The file is corrupted.
    \return MEMORY_E returned if the allocated memory for the temp buffer fails.
    \return BAD_FUNC_ARG returned if fname or ctx have a NULL value.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, holding the certificate information.
    \param fname the cert cache buffer.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* fname = "path to file";
    ...
    if(wolfSSL_CTX_restore_cert_cache(ctx, fname)){
    	// check to see if the execution was successful
    }
    \endcode
    
    \sa CM_RestoreCertCache
    \sa XFOPEN
*/
WOLFSSL_API int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX*, const char*);
/*!
    \ingroup wolfssl

    \brief This function persists the certificate cache to memory.
    
    \return SSL_SUCCESS returned on successful execution of the function. No errors were thrown.
    \return BAD_MUTEX_E mutex error where the WOLFSSL_CERT_MANAGER member caLock was not 0 (zero).
    \return BAD_FUNC_ARG returned if ctx, mem, or used is NULL or if sz is less than or equal to 0 (zero).
    \return BUFFER_E output buffer mem was too small.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param mem a void pointer to the destination (output buffer).
    \param sz the size of the output buffer.
    \param used a pointer to size of the cert cache header.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol );
    void* mem;
    int sz;
    int* used;
    ...
    if(wolfSSL_CTX_memsave_cert_cache(ctx, mem, sz, used) != SSL_SUCCESS){
	    // The function returned with an error
    }
    \endcode
    
    \sa DoMemSaveCertCache
    \sa GetCertCacheMemSize
    \sa CM_MemRestoreCertCache
    \sa CM_GetCertCacheMemSize
*/
WOLFSSL_API int  wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX*, void*, int, int*);
/*!
    \ingroup wolfssl

    \brief This function restores the certificate cache from memory.
    
    \return SSL_SUCCESS returned if the function and subroutines executed without an error.
    \return BAD_FUNC_ARG returned if the ctx or mem parameters are NULL or if the sz parameter is less than or equal to zero.
    \return BUFFER_E returned if the cert cache memory buffer is too small.
    \return CACHE_MATCH_ERROR returned if there was a cert cache header mismatch.
    \return BAD_MUTEX_E returned if the lock mutex on failed.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param mem a void pointer with a value that will be restored to the certificate cache.
    \param sz an int type that represents the size of the mem parameter.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    void* mem;
    int sz = (*int) sizeof(mem);
    …
    if(wolfSSL_CTX_memrestore_cert_cache(ssl->ctx, mem, sz)){ 
    	// The success case
    }
    \endcode
    
    \sa CM_MemRestoreCertCache
*/
WOLFSSL_API int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX*, const void*, int);
/*!
    \ingroup wolfssl

    \brief Returns the size the certificate cache save buffer needs to be.
    
    \return int integer value returned representing the memory size upon success.
    \return BAD_FUNC_ARG is returned if the WOLFSSL_CTX struct is NULL.
    \return BAD_MUTEX_E - returned if there was a mutex lock error.
    
    \param ctx a pointer to a wolfSSL_CTX structure, created using wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol);
    ...
    int certCacheSize = wolfSSL_CTX_get_cert_cache_memsize(ctx);

    if(certCacheSize != BAD_FUNC_ARG || certCacheSize != BAD_MUTEX_E){
	// Successfully retrieved the memory size.
    }
    \endcode
    
    \sa CM_GetCertCacheMemSize
*/
WOLFSSL_API int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX*);

/* only supports full name from cipher_name[] delimited by : */
/*!
    \ingroup wolfssl

    \brief This function sets cipher suite list for a given WOLFSSL_CTX.  This cipher suite list becomes the default list for any new SSL sessions (WOLFSSL) created using this context.  The ciphers in the list should be sorted in order of preference from highest to lowest.  Each call to wolfSSL_CTX_set_cipher_list() resets the cipher suite list for the specific SSL context to the provided list each time the function is called. The cipher suite list, list, is a null-terminated text string, and a colon-delimited list.  For example, one value for list may be "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256" Valid cipher values are the full name values from the cipher_names[] array in src/internal.c (for a definite list of valid cipher values check src/internal.c)
    
    \return SSL_SUCCESS will be returned upon successful function completion.
    \return SSL_FAILURE will be returned on failure.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param list null-terminated text string and a colon-delimited list of cipher suites to use with the specified SSL context.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_cipher_list(ctx,
    “DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256”);
    if (ret != SSL_SUCCESS) {
    	// failed to set cipher suite list
    }
    \endcode
    
    \sa wolfSSL_set_cipher_list
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX*, const char*);
/*!
    \ingroup wolfssl

    \brief This function sets cipher suite list for a given WOLFSSL object (SSL session).  The ciphers in the list should be sorted in order of preference from highest to lowest.  Each call to wolfSSL_set_cipher_list() resets the cipher suite list for the specific SSL session to the provided list each time the function is called. The cipher suite list, list, is a null-terminated text string, and a colon-delimited list. For example, one value for list may be "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256". Valid cipher values are the full name values from the cipher_names[] array in src/internal.c (for a definite list of valid cipher values check src/internal.c)
    
    \return SSL_SUCCESS will be returned upon successful function completion.
    \return SSL_FAILURE will be returned on failure.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param list null-terminated text string and a colon-delimited list of cipher suites to use with the specified SSL session.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_cipher_list(ssl,
    “DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256”);
    if (ret != SSL_SUCCESS) {
    	// failed to set cipher suite list
    }
    \endcode
    
    \sa wolfSSL_CTX_set_cipher_list
    \sa wolfSSL_new
*/
WOLFSSL_API int  wolfSSL_set_cipher_list(WOLFSSL*, const char*);

/* Nonblocking DTLS helper functions */
/*!
    \ingroup wolfssl

    \brief This function returns the current timeout value in seconds for the WOLFSSL object. When using non-blocking sockets, something in the user code needs to decide when to check for available recv data and how long it has been waiting. The value returned by this function indicates how long the application should wait.
    
    \return seconds The current DTLS timeout value in seconds
    \return NOT_COMPILED_IN if wolfSSL was not built with DTLS support.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    int timeout = 0;
    WOLFSSL* ssl;
    ...
    timeout = wolfSSL_get_dtls_current_timeout(ssl);
    printf(“DTLS timeout (sec) = %d\n”, timeout);
    \endcode
    
    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
WOLFSSL_API int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function sets the dtls timeout.
    
    \return SSL_SUCCESS returned if the function executes without an error. The dtls_timeout_init and the dtls_timeout members of SSL have been set.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if the timeout is not greater than 0. It will also return if the timeout argument exceeds the maximum value allowed.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param timeout an int type that will be set to the dtls_timeout_init member of the WOLFSSL structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUT;
    ...
    if(wolfSSL_dtls_set_timeout_init(ssl, timeout)){
    	// the dtls timeout was set
    } else {
    	// Failed to set DTLS timeout.
    }
    \endcode
    
    \sa wolfSSL_dtls_set_timeout_max
    \sa wolfSSL_dtls_got_timeout
*/
WOLFSSL_API int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int);
/*!
    \ingroup wolfssl

    \brief This function sets the maximum dtls timeout.
    
    \return SSL_SUCCESS returned if the function executed without an error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if the timeout argument is not greater than zero or is less than the dtls_timeout_init member of the WOLFSSL structure.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param timeout an int type representing the dtls maximum timeout.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUTVAL;
    ...
    int ret = wolfSSL_dtls_set_timeout_max(ssl);
    if(!ret){
    	// Failed to set the max timeout
    }
    \endcode
    
    \sa wolfSSL_dtls_set_timeout_init
    \sa wolfSSL_dtls_got_timeout
*/
WOLFSSL_API int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int);
/*!
    \ingroup wolfssl

    \brief When using non-blocking sockets with DTLS, this function should be called on the WOLFSSL object when the controlling code thinks the transmission has timed out. It performs the actions needed to retry the last transmit, including adjusting the timeout value. If it has been too long, this will return a failure.
    
    \return SSL_SUCCESS will be returned upon success
    \return SSL_FATAL_ERROR will be returned if there have been too many retransmissions/timeouts without getting a response from the peer.
    \return NOT_COMPILED_IN will be returned if wolfSSL was not compiled with DTLS support.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    See the following files for usage examples:
    <wolfssl_root>/examples/client/client.c
    <wolfssl_root>/examples/server/server.c
    \endcode
    
    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
WOLFSSL_API int  wolfSSL_dtls_got_timeout(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function is used to determine if the SSL session has been configured to use DTLS.
    
    \return 1 If the SSL session (ssl) has been configured to use DTLS, this function will return 1. 
    \return 0 otherwise.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls(ssl);
    if (ret) {
    	// SSL session has been configured to use DTLS
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
WOLFSSL_API int  wolfSSL_dtls(WOLFSSL* ssl);

/*!
    \ingroup wolfssl

    \brief This function sets the DTLS peer, peer (sockaddr_in) with size of peerSz.
    
    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled with DTLS support.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer pointer to peer’s sockaddr_in structure.
    \param peerSz size of the sockaddr_in structure pointed to by peer.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to set DTLS peer
    }
    \endcode
    
    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
WOLFSSL_API int  wolfSSL_dtls_set_peer(WOLFSSL*, void*, unsigned int);
/*!
    \ingroup wolfssl

    \brief This function gets the sockaddr_in (of size peerSz) of the current DTLS peer.  The function will compare peerSz to the actual DTLS peer size stored in the SSL session.  If the peer will fit into peer, the peer’s sockaddr_in will be copied into peer, with peerSz set to the size of peer.
    
    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled with DTLS support.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer pointer to memory location to store peer’s sockaddr_in structure.
    \param peerSz input/output size. As input, the size of the allocated memory pointed to by peer.  As output, the size of the actual sockaddr_in structure pointed to by peer.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_get_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to get DTLS peer
    }
    \endcode
    
    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
WOLFSSL_API int  wolfSSL_dtls_get_peer(WOLFSSL*, void*, unsigned int*);

WOLFSSL_API int  wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_dtls_set_sctp(WOLFSSL*);
WOLFSSL_API int  wolfSSL_CTX_dtls_set_mtu(WOLFSSL_CTX*, unsigned short);
WOLFSSL_API int  wolfSSL_dtls_set_mtu(WOLFSSL*, unsigned short);

WOLFSSL_API int   wolfSSL_ERR_GET_REASON(unsigned long err);
/*!
    \ingroup wolfssl

    \brief This function converts an error code returned by wolfSSL_get_error() into a more human-readable error string.  errNumber is the error code returned by wolfSSL_get_error() and data is the storage buffer which the error string will be placed in. The maximum length of data is 80 characters by default, as defined by MAX_ERROR_SZ is wolfssl/wolfcrypt/error.h.
    
    \return success On successful completion, this function returns the same string as is returned in data.
    \return failure Upon failure, this function returns a string with the appropriate failure reason, msg.
    
    \param errNumber error code returned by wolfSSL_get_error().
    \param data output buffer containing human-readable error string matching errNumber.
    
    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode
    
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
WOLFSSL_API char* wolfSSL_ERR_error_string(unsigned long,char*);
/*!
    \ingroup wolfssl

    \brief This function is a version of wolfSSL_ERR_error_string() where len specifies the maximum number of characters that may be written to buf.  Like wolfSSL_ERR_error_string(), this function converts an error code returned from wolfSSL_get_error() into a more human-readable error string.  The human-readable string is placed in buf.
    
    \return none No returns.
    
    \param e error code returned by wolfSSL_get_error().
    \param buff output buffer containing human-readable error string matching e.
    \param len maximum length in characters which may be written to buf.
    
    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string_n(err, buffer, 80);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode
    
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
WOLFSSL_API void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long sz);
WOLFSSL_API const char* wolfSSL_ERR_reason_error_string(unsigned long);

/* extras */

#define STACK_OF(x) WOLFSSL_STACK
WOLFSSL_API int wolfSSL_sk_X509_push(STACK_OF(WOLFSSL_X509_NAME)* sk,
                                                            WOLFSSL_X509* x509);
WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_pop(STACK_OF(WOLFSSL_X509_NAME)* sk);
WOLFSSL_API void wolfSSL_sk_X509_free(STACK_OF(WOLFSSL_X509_NAME)* sk);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_new(void);
WOLFSSL_API void wolfSSL_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT* obj);
WOLFSSL_API int wolfSSL_sk_ASN1_OBJECT_push(STACK_OF(WOLFSSL_ASN1_OBJEXT)* sk,
                                                      WOLFSSL_ASN1_OBJECT* obj);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_sk_ASN1_OBJCET_pop(
                                            STACK_OF(WOLFSSL_ASN1_OBJECT)* sk);
WOLFSSL_API void wolfSSL_sk_ASN1_OBJECT_free(STACK_OF(WOLFSSL_ASN1_OBJECT)* sk);
WOLFSSL_API int wolfSSL_ASN1_STRING_to_UTF8(unsigned char **out, WOLFSSL_ASN1_STRING *in);

WOLFSSL_API int  wolfSSL_set_ex_data(WOLFSSL*, int, void*);
/*!
    \ingroup wolfssl

    \brief This function checks the shutdown conditions in closeNotify or connReset or sentNotify members of the Options structure. The Options structure is within the WOLFSSL structure.
    
    \return 1 SSL_SENT_SHUTDOWN is returned.
    \return 2 SS_RECEIVED_SHUTDOWN is returned.
    
    \param ssl a constant pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    int ret;
    ret = wolfSSL_get_shutdown(ssl);

    if(ret == 1){
	    SSL_SENT_SHUTDOWN
    } else if(ret == 2){
	    SSL_RECEIVED_SHUTDOWN
    } else {
	    Fatal error.
    }
    \endcode
    
    \sa wolfSSL_SESSION_free
*/
WOLFSSL_API int  wolfSSL_get_shutdown(const WOLFSSL*);
WOLFSSL_API int  wolfSSL_set_rfd(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_wfd(WOLFSSL*, int);
WOLFSSL_API void wolfSSL_set_shutdown(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_session_id_context(WOLFSSL*, const unsigned char*,
                                           unsigned int);
WOLFSSL_API void wolfSSL_set_connect_state(WOLFSSL*);
WOLFSSL_API void wolfSSL_set_accept_state(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function returns the resuming member of the options struct. The flag indicates whether or not to reuse a session. If not, a new session must be established.
    
    \return This function returns an int type held in the Options structure representing the flag for session reuse.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(!wolfSSL_session_reused(sslResume)){
	    // No session reuse allowed.
    }
    \endcode
    
    \sa wolfSSL_SESSION_free
    \sa wolfSSL_GetSessionIndex
    \sa wolfSSL_memsave_session_cache
*/
WOLFSSL_API int  wolfSSL_session_reused(WOLFSSL*);
WOLFSSL_API void wolfSSL_SESSION_free(WOLFSSL_SESSION* session);
/*!
    \ingroup wolfssl

    \brief This function checks to see if the connection is established.
    
    \return 0 returned if the connection is not established, i.e. the WOLFSSL struct is NULL or the handshake is not done.
    \return 1 returned if the connection is not established i.e. the WOLFSSL struct is null or the handshake is not done.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _EXAMPLE_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_is_init_finished(ssl)){
	    Handshake is done and connection is established
    }
    \endcode
    
    \sa wolfSSL_set_accept_state
    \sa wolfSSL_get_keys
    \sa wolfSSL_set_shutdown
*/
WOLFSSL_API int  wolfSSL_is_init_finished(WOLFSSL*);

/*!
    \ingroup wolfssl

    \brief Returns the SSL version being used as a string.
    
    \return "SSLv3" Using SSLv3
    \return "TLSv1" Using TLSv1
    \return "TLSv1.1" Using TLSv1.1
    \return "TLSv1.2" Using TLSv1.2
    \return "TLSv1.3" Using TLSv1.3
    \return "DTLS": Using DTLS
    \return "DTLSv1.2" Using DTLSv1.2
    \return "unknown" There was a problem determining which version of TLS being used.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);
    printf(wolfSSL_get_version("Using version: %s", ssl));
    \endcode
    
    \sa wolfSSL_lib_version
*/
WOLFSSL_API const char*  wolfSSL_get_version(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Returns the current cipher suit an ssl session is using.
    
    \return ssl->options.cipherSuite An integer representing the current cipher suite.
    \return 0 The ssl session provided is null.
    
    \param ssl The SSL session to check.
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);
    
    if(wolfSSL_get_current_cipher_suite(ssl) == 0)
    {
        // Error getting cipher suite
    }
    \endcode
    
    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_list
*/
WOLFSSL_API int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function returns a pointer to the current cipher in the ssl session.
    
    \return The function returns the address of the cipher member of the WOLFSSL struct. This is a pointer to the WOLFSSL_CIPHER structure.
    \return NULL returned if the WOLFSSL structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    WOLFSSL_CIPHER* cipherCurr = wolfSSL_get_current_cipher;

    if(!cipherCurr){
    	// Failure case.
    } else {
    	// The cipher was returned to cipherCurr
    }
    \endcode
    
    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
WOLFSSL_API WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL*);
WOLFSSL_API char* wolfSSL_CIPHER_description(const WOLFSSL_CIPHER*, char*, int);
/*!
    \ingroup wolfssl

    \brief This function matches the cipher suite in the SSL object with the available suites and returns the string representation.
    
    \return string This function returns the string representation of the matched cipher suite.
    \return none It will return “None” if there are no suites matched.
    
    \param cipher a constant pointer to a WOLFSSL_CIPHER structure.
    
    _Example_
    \code
    // gets cipher name in the format DHE_RSA ...
    const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl){
	WOLFSSL_CIPHER* cipher;
	const char* fullName;
    …
	cipher = wolfSSL_get_curent_cipher(ssl);
	fullName = wolfSSL_CIPHER_get_name(cipher);

	if(fullName){
		// sanity check on returned cipher
	}
    \endcode
    
    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
WOLFSSL_API const char*  wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API const char*  wolfSSL_SESSION_CIPHER_get_name(WOLFSSL_SESSION* session);
/*!
    \ingroup wolfssl

    \brief This function matches the cipher suite in the SSL object with the available suites.
    
    \return This function returns the string value of the suite matched. It will return “None” if there are no suites matched.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    #ifdef WOLFSSL_DTLS
    …
    // make sure a valid suite is used
    if(wolfSSL_get_cipher(ssl) == NULL){
	    WOLFSSL_MSG(“Can not match cipher suite imported”);
	    return MATCH_SUITE_ERROR;
    }
    …
    #endif // WOLFSSL_DTLS
    \endcode
    
    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
WOLFSSL_API const char*  wolfSSL_get_cipher(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function returns the WOLFSSL_SESSION from the WOLFSSL structure.
    
    \return WOLFSSL_SESSION On success return session pointer.
    \return NULL on failure returns NULL.
    
    \param ssl WOLFSSL structure to get session from.
    
    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* ses;
    // attempt/complete handshake
    ses  = wolfSSL_get1_session(ssl);
    // check ses information
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);
                           /* what's ref count */

WOLFSSL_API void wolfSSL_X509_free(WOLFSSL_X509*);
WOLFSSL_API void wolfSSL_OPENSSL_free(void*);

WOLFSSL_API int wolfSSL_OCSP_parse_url(char* url, char** host, char** port,
                                     char** path, int* ssl);

/*!
    \ingroup wolfssl

    \brief The wolfSSLv23_client_method() function is used to indicate that the application is a client and will support the highest protocol version supported by the server between SSL 3.0 - TLS 1.2.  This function allocates memory for and initializes a new WOLFSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new(). Both wolfSSL clients and servers have robust version downgrade capability.  If a specific protocol version method is used on either side, then only that version will be negotiated or an error will be returned.  For example, a client that uses TLSv1 and tries to connect to a SSLv3 only server will fail, likewise connecting to a TLSv1.1 will fail as well. To resolve this issue, a client that uses the wolfSSLv23_client_method() function will use the highest protocol version supported by the server and downgrade to SSLv3 if needed. In this case, the client will be able to connect to a server running SSLv3 - TLSv1.2.

    \return pointer upon succes a pointer to a WOLFSSL_METHOD.
    \return Failure If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none
    
    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;
    method = wolfSSLv23_client_method();
    if (method == NULL) {
	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD* wolfSSLv23_client_method(void);
WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_client_method(void);
WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_server_method(void);

WOLFSSL_API void wolfSSL_MD4_Init(WOLFSSL_MD4_CTX*);
WOLFSSL_API void wolfSSL_MD4_Update(WOLFSSL_MD4_CTX*, const void*, unsigned long);
WOLFSSL_API void wolfSSL_MD4_Final(unsigned char*, WOLFSSL_MD4_CTX*);


WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new(WOLFSSL_BIO_METHOD*);
WOLFSSL_API int  wolfSSL_BIO_free(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_free_all(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_read(WOLFSSL_BIO*, void*, int);
WOLFSSL_API int  wolfSSL_BIO_write(WOLFSSL_BIO*, const void*, int);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO*, WOLFSSL_BIO* append);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_flush(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_pending(WOLFSSL_BIO*);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void);
WOLFSSL_API long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO*, long size);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void);
WOLFSSL_API WOLFSSL_BIO*        wolfSSL_BIO_new_socket(int sfd, int flag);
WOLFSSL_API int         wolfSSL_BIO_eof(WOLFSSL_BIO*);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void);
WOLFSSL_API void wolfSSL_BIO_set_flags(WOLFSSL_BIO*, int);

/*!
    \ingroup wolfssl

    \brief This is used to set a byte pointer to the start of the internal memory buffer.
    
    \return size On success the size of the buffer is returned
    \return SSL_FATAL_ERROR If an error case was encountered.
    
    \param bio WOLFSSL_BIO structure to get memory buffer of.
    \param p byte pointer to set to memory buffer.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    const byte* p;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_get_mem_data(bio, &p);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,void* p);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(void* buf, int len);


WOLFSSL_API long wolfSSL_BIO_set_ssl(WOLFSSL_BIO*, WOLFSSL*, int flag);
/*!
    \ingroup wolfssl

    \brief Sets the file descriptor for bio to use.
    
    \return SSL_SUCCESS(1) upon success.
    
    \param bio WOLFSSL_BIO structure to set fd.
    \param fd file descriptor to use.
    \param closeF flag for behavior when closing fd.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    int fd;
    // setup bio
    wolfSSL_BIO_set_fd(bio, fd, BIO_NOCLOSE);
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int flag);
WOLFSSL_API void wolfSSL_set_bio(WOLFSSL*, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr);
WOLFSSL_API int  wolfSSL_add_all_algorithms(void);

#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_file(void);
#endif

WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_bio(void);
/*!
    \ingroup wolfssl

    \brief This is used to get a BIO_SOCKET type WOLFSSL_BIO_METHOD.
    
    \return WOLFSSL_BIO_METHOD pointer to a WOLFSSL_BIO_METHOD structure that is a socket type
    
    \param none No parameters.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket);
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void);

WOLFSSL_API long wolfSSL_BIO_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, void *parg);
WOLFSSL_API long wolfSSL_BIO_int_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, int iarg);

/*!
    \ingroup wolfssl

    \brief This is used to set the size of write buffer for a WOLFSSL_BIO. If write buffer has been previously set this function will free it when resetting the size. It is similar to wolfSSL_BIO_reset in that it resets read and write indexes to 0.
    
    \return SSL_SUCCESS On successfully setting the write buffer.
    \return SSL_FAILURE If an error case was encountered.
    
    \param bio WOLFSSL_BIO structure to set fd.
    \param size size of buffer to allocate.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret = wolfSSL_BIO_set_write_buf_size(bio, 15000);
    // check return value
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API int  wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size);
/*!
    \ingroup wolfssl

    \brief This is used to pair two bios together. A pair of bios acts similar to a two way pipe writing to one can be read by the other and vice versa. It is expected that both bios be in the same thread, this function is not thread safe. Freeing one of the two bios removes both from being paired. If a write buffer size was not previously set for either of the bios it is set to a default size of 17000 (WOLFSSL_BIO_SIZE) before being paired.
    
    \return SSL_SUCCESS On successfully pairing the two bios.
    \return SSL_FAILURE If an error case was encountered.
    
    \param b1 WOLFSSL_BIO structure to set pair.
    \param b2 second WOLFSSL_BIO structure to complete pair.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BIO* bio2;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    ret = wolfSSL_BIO_make_bio_pair(bio, bio2);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API int  wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2);
/*!
    \ingroup wolfssl

    \brief This is used to set the read request flag back to 0.
    
    \return SSL_SUCCESS On successfully setting value.
    \return SSL_FAILURE If an error case was encountered.
    
    \param bio WOLFSSL_BIO structure to set read request flag.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    ...
    ret = wolfSSL_BIO_ctrl_reset_read_request(bio);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new, wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_new, wolfSSL_BIO_free
*/
WOLFSSL_API int  wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *b);
/*!
    \ingroup wolfssl

    \brief This is used to get a buffer pointer for reading from. Unlike wolfSSL_BIO_nread the internal read index is not advanced by the number returned from the function call. Reading past the value returned can result in reading out of array bounds.
    
    \return >=0 on success return the number of bytes to read
    
    \param bio WOLFSSL_BIO structure to read from.
    \param buf pointer to set at beginning of read array.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nread0(bio, &bufPt); // read as many bytes as possible
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite0
*/
WOLFSSL_API int  wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf);
/*!
    \ingroup wolfssl

    \brief This is used to get a buffer pointer for reading from. The internal read index is advanced by the number returned from the function call with buf being pointed to the beginning of the buffer to read from. In the case that less bytes are in the read buffer than the value requested with num the lesser value is returned. Reading past the value returned can result in reading out of array bounds.
    
    \return >=0 on success return the number of bytes to read
    \return WOLFSSL_BIO_ERROR(-1) on error case with nothing to read return -1
    
    \param bio WOLFSSL_BIO structure to read from.
    \param buf pointer to set at beginning of read array.
    \param num number of bytes to try and read.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;

    // set up bio
    ret = wolfSSL_BIO_nread(bio, &bufPt, 10); // try to read 10 bytes
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite
*/
WOLFSSL_API int  wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num);
/*!
    \ingroup wolfssl

    \brief Gets a pointer to the buffer for writing as many bytes as returned by the function. Writing more bytes to the pointer returned then the value returned can result in writing out of bounds.
    
    \return int Returns the number of bytes that can be written to the buffer pointer returned.
    \return WOLFSSL_BIO_UNSET(-2) in the case that is not part of a bio pair
    \return WOLFSSL_BIO_ERROR(-1) in the case that there is no more room to write to
    
    \param bio WOLFSSL_BIO structure to write to.
    \param buf pointer to buffer to write to.
    \param num number of bytes desired to be written.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nwrite(bio, &bufPt, 10); // try to write 10 bytes
    // handle negative ret check
    // write ret bytes to bufPt
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_nread
*/
WOLFSSL_API int  wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num);
/*!
    \ingroup wolfssl

    \brief Resets bio to an initial state. As an example for type BIO_BIO this resets the read and write index.
    
    \return 0 On successfully resetting the bio.
    \return WOLFSSL_BIO_ERROR(-1) Returned on bad input or unsuccessful reset.
    
    \param bio WOLFSSL_BIO structure to reset.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    // setup bio
    wolfSSL_BIO_reset(bio);
    //use pt
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API int  wolfSSL_BIO_reset(WOLFSSL_BIO *bio);

/*!
    \ingroup wolfssl

    \brief This function adjusts the file pointer to the offset given. This is the offset from the head of the file.
    
    \return 0 On successfully seeking.
    \return -1 If an error case was encountered.
    
    \param bio WOLFSSL_BIO structure to set.
    \param ofs offset into file.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, &fp);
    // check ret value
    ret  = wolfSSL_BIO_seek(bio, 3);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API int  wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs);
/*!
    \ingroup wolfssl

    \brief This is used to set and write to a file. WIll overwrite any data currently in the file and is set to close the file when the bio is freed.
    
    \return SSL_SUCCESS On successfully opening and setting file.
    \return SSL_FAILURE If an error case was encountered.
    
    \param bio WOLFSSL_BIO structure to set file.
    \param name name of file to write to.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_write_filename(bio, “test.txt”);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_file
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API int  wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name);
/*!
    \ingroup wolfssl

    \brief This is used to set the end of file value. Common value is -1 so as not to get confused with expected positive values.
    
    \return 0 returned on completion
    
    \param bio WOLFSSL_BIO structure to set end of file value.
    \param v value to set in bio.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_set_mem_eof_return(bio, -1);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new 
    \sa wolfSSL_BIO_s_mem 
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v);
/*!
    \ingroup wolfssl

    \brief This is a getter function for WOLFSSL_BIO memory pointer.
    
    \return SSL_SUCCESS On successfully getting the pointer SSL_SUCCESS is returned (currently value of 1).
    \return SSL_FAILURE Returned if NULL arguments are passed in (currently value of 0).
    
    \param bio pointer to the WOLFSSL_BIO structure for getting memory pointer.
    \param ptr structure that is currently a char*. Is set to point to bio’s memory.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BUF_MEM* pt;
    // setup bio
    wolfSSL_BIO_get_mem_ptr(bio, &pt);
    //use pt
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
WOLFSSL_API long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **m);

WOLFSSL_API void        wolfSSL_RAND_screen(void);
WOLFSSL_API const char* wolfSSL_RAND_file_name(char*, unsigned long);
WOLFSSL_API int         wolfSSL_RAND_write_file(const char*);
WOLFSSL_API int         wolfSSL_RAND_load_file(const char*, long);
WOLFSSL_API int         wolfSSL_RAND_egd(const char*);
WOLFSSL_API int         wolfSSL_RAND_seed(const void*, int);
WOLFSSL_API void        wolfSSL_RAND_add(const void*, int, double);

WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void);
WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void);
WOLFSSL_API int wolfSSL_COMP_add_compression_method(int, void*);

WOLFSSL_API int wolfSSL_get_ex_new_index(long, void*, void*, void*, void*);

WOLFSSL_API void wolfSSL_set_id_callback(unsigned long (*f)(void));
WOLFSSL_API void wolfSSL_set_locking_callback(void (*f)(int, int, const char*,
                                                      int));
WOLFSSL_API void wolfSSL_set_dynlock_create_callback(WOLFSSL_dynlock_value* (*f)
                                                   (const char*, int));
WOLFSSL_API void wolfSSL_set_dynlock_lock_callback(void (*f)(int,
                                      WOLFSSL_dynlock_value*, const char*, int));
WOLFSSL_API void wolfSSL_set_dynlock_destroy_callback(void (*f)
                                     (WOLFSSL_dynlock_value*, const char*, int));
WOLFSSL_API int  wolfSSL_num_locks(void);

WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get_current_cert(
                                                        WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API int   wolfSSL_X509_STORE_CTX_get_error(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API int   wolfSSL_X509_STORE_CTX_get_error_depth(WOLFSSL_X509_STORE_CTX*);
/*!
    \ingroup wolfssl

    \brief This function copies the name of the x509 into a buffer.
    
    \return A char pointer to the buffer with the WOLFSSL_X509_NAME structures name member’s data is returned if the function executed normally.
    
    \param name a pointer to a WOLFSSL_X509 structure.
    \param in a buffer to hold the name copied from the WOLFSSL_X509_NAME structure.
    \param sz the maximum size of the buffer.
    
    _Example_
    \code
    WOLFSSL_X509 x509;
    char* name;
    ...
    name = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(name <= 0){
    	// There’s nothing in the buffer.
    }
    \endcode
    
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
WOLFSSL_API char*       wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME*, char*, int);
/*!
    \ingroup wolfssl

    \brief This function returns the name of the certificate issuer.
    
    \return point a pointer to the WOLFSSL_X509 struct’s issuer member is returned.
    \return NULL if the cert passed in is NULL.
    
    \param cert a pointer to a WOLFSSL_X509 structure.
    
    _Example_
    \code
    WOLFSSL_X509* x509;
    WOLFSSL_X509_NAME issuer;
    ...
    issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(!issuer){
    	// NULL was returned
    } else {
    	// issuer hods the name of the certificate issuer.
    }
    \endcode
    
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_NAME_oneline
*/
WOLFSSL_API WOLFSSL_X509_NAME*  wolfSSL_X509_get_issuer_name(WOLFSSL_X509*);
/*!
    \ingroup wolfssl

    \brief This function returns the subject member of the WOLFSSL_X509 structure.
    
    \return pointer a pointer to the WOLFSSL_X509_NAME structure. The pointer may be NULL if the WOLFSSL_X509 struct is NULL or if the subject member of the structure is NULL.
    
    \param cert a pointer to a WOLFSSL_X509 structure.
    
    _Example_
    \code
    WOLFSSL_X509* cert;
    WOLFSSL_X509_NAME name;
    …
    name = wolfSSL_X509_get_subject_name(cert);
    if(name == NULL){
	    // Deal with the NULL cacse 
    }
    \endcode
    
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_API WOLFSSL_X509_NAME*  wolfSSL_X509_get_subject_name(WOLFSSL_X509*);
WOLFSSL_API int  wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509*, int);
WOLFSSL_API int  wolfSSL_X509_ext_get_critical_by_NID(WOLFSSL_X509*, int);
/*!
    \ingroup wolfssl

    \brief Checks the isCa member of the WOLFSSL_X509 structure and returns the value.
    
    \return isCA returns the value in the isCA member of the WOLFSSL_X509 structure is returned.
    \return 0 returned if there is not a valid x509 structure passed in.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    /code
    WOLFSSL* ssl;
    ...
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_X509_get_isCA(ssl)){
    	// This is the CA
    }else {
    	// Failure case
    }
    \endcode
    
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
*/
WOLFSSL_API int  wolfSSL_X509_get_isCA(WOLFSSL_X509*);
WOLFSSL_API int  wolfSSL_X509_get_isSet_pathLength(WOLFSSL_X509*);
WOLFSSL_API unsigned int wolfSSL_X509_get_pathLength(WOLFSSL_X509*);
WOLFSSL_API unsigned int wolfSSL_X509_get_keyUsage(WOLFSSL_X509*);
WOLFSSL_API unsigned char* wolfSSL_X509_get_authorityKeyID(
                                            WOLFSSL_X509*, unsigned char*, int*);
WOLFSSL_API unsigned char* wolfSSL_X509_get_subjectKeyID(
                                            WOLFSSL_X509*, unsigned char*, int*);
WOLFSSL_API int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME*);
/*!
    \ingroup wolfssl

    \brief This function gets the text related to the passed in NID value.
    
    \return int returns the size of the text buffer.
    
    \param name WOLFSSL_X509_NAME to search for text.
    \param nid NID to search for.
    \param buf buffer to hold text when found.
    \param len length of buffer.
    
    _Example_
    \code
    WOLFSSL_X509_NAME* name;
    char buffer[100];
    int bufferSz;
    int ret;
    // get WOLFSSL_X509_NAME
    ret = wolfSSL_X509_NAME_get_text_by_NID(name, NID_commonName, buffer, bufferSz);

    //check ret value
    \endcode
    
    \sa none
*/
WOLFSSL_API int wolfSSL_X509_NAME_get_text_by_NID(
                                            WOLFSSL_X509_NAME*, int, char*, int);
WOLFSSL_API int wolfSSL_X509_NAME_get_index_by_NID(
                                           WOLFSSL_X509_NAME*, int, int);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_X509_NAME_ENTRY_get_data(WOLFSSL_X509_NAME_ENTRY*);
WOLFSSL_API char* wolfSSL_ASN1_STRING_data(WOLFSSL_ASN1_STRING*);
WOLFSSL_API int wolfSSL_ASN1_STRING_length(WOLFSSL_ASN1_STRING*);
WOLFSSL_API int         wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API const char* wolfSSL_X509_verify_cert_error_string(long);
/*!
    \ingroup wolfssl

    \brief This function returns the value stored in the sigOID member of the WOLFSSL_X509 structure.
    
    \return 0 returned if the WOLFSSL_X509 structure is NULL.
    \return int an integer value is returned which was retrieved from the x509 object.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509SigType = wolfSSL_X509_get_signature_type(x509);

    if(x509SigType != EXPECTED){
	// Deal with an unexpected value
    }
    \endcode
    
    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_notAfter
    \sa wolfSSL_X509_free
*/
WOLFSSL_API int wolfSSL_X509_get_signature_type(WOLFSSL_X509*);
/*!
    \ingroup wolfssl

    \brief Gets the X509 signature and stores it in the buffer.
    
    \return SSL_SUCCESS returned if the function successfully executes. The signature is loaded into the buffer.
    \return SSL_FATAL_ERRROR returns if the x509 struct or the bufSz member is NULL. There is also a check for the length member of the sig structure (sig is a member of x509).
    
    \param x509 pointer to a WOLFSSL_X509 structure.
    \param buf a char pointer to the buffer.
    \param bufSz an integer pointer to the size of the buffer.
    
    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    unsigned char* buf; // Initialize
    int* bufSz = sizeof(buf)/sizeof(unsigned char);
    ...
    if(wolfSSL_X509_get_signature(x509, buf, bufSz) != SSL_SUCCESS){
	    // The function did not execute successfully.
    } else{
	    // The buffer was written to correctly.
    }
    \endcode
    
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_get_signature_type
    \sa wolfSSL_X509_get_device_type
*/
WOLFSSL_API int wolfSSL_X509_get_signature(WOLFSSL_X509*, unsigned char*, int*);

WOLFSSL_API int wolfSSL_X509_LOOKUP_add_dir(WOLFSSL_X509_LOOKUP*,const char*,long);
WOLFSSL_API int wolfSSL_X509_LOOKUP_load_file(WOLFSSL_X509_LOOKUP*, const char*,
                                            long);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_hash_dir(void);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_file(void);

WOLFSSL_API WOLFSSL_X509_LOOKUP* wolfSSL_X509_STORE_add_lookup(WOLFSSL_X509_STORE*,
                                                    WOLFSSL_X509_LOOKUP_METHOD*);
WOLFSSL_API WOLFSSL_X509_STORE*  wolfSSL_X509_STORE_new(void);
WOLFSSL_API void         wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE*);
/*!
    \ingroup wolfssl

    \brief This function adds a certificate to the WOLFSSL_X509_STRE structure.
    
    \return SSL_SUCCESS If certificate is added successfully.
    \return SSL_FATAL_ERROR: If certificate is not added successfully.
    
    \param str certificate store to add the certificate to.
    \param x509 certificate to add.
    
    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    WOLFSSL_X509* x509;
    int ret;
    ret = wolfSSL_X509_STORE_add_cert(str, x509);
    //check ret value
    \endcode
    
    \sa wolfSSL_X509_free
*/
WOLFSSL_API int          wolfSSL_X509_STORE_add_cert(
                                              WOLFSSL_X509_STORE*, WOLFSSL_X509*);
/*!
    \ingroup wolfssl

    \brief This function is a getter function for chain variable in WOLFSSL_X509_STORE_CTX structure. Currently chain is not populated.
    
    \return pointer if successful returns WOLFSSL_STACK (same as STACK_OF(WOLFSSL_X509)) pointer
    \return Null upon failure
    
    \param ctx certificate store ctx to get parse chain from.
    
    _Example_
    \code
    WOLFSSL_STACK* sk;
    WOLFSSL_X509_STORE_CTX* ctx;
    sk = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode
    
    \sa wolfSSL_sk_X509_free
*/
WOLFSSL_API WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);
/*!
    \ingroup wolfssl

    \brief This function takes in a flag to change the behavior of the WOLFSSL_X509_STORE structure passed in. An example of a flag used is WOLFSSL_CRL_CHECK.
    
    \return SSL_SUCCESS If no errors were encountered when setting the flag.
    \return <0 a negative vlaue will be returned upon failure.
    
    \param str certificate store to set flag in.
    \param flag flag for behavior.
    
    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    int ret;
    // create and set up str
    ret = wolfSSL_X509_STORE_set_flags(str, WOLFSSL_CRL_CHECKALL);
    If (ret != SSL_SUCCESS) {
    	//check ret value and handle error case
    }
    \endcode
    
    \sa wolfSSL_X509_STORE_new
    \sa wolfSSL_X509_STORE_free
*/
WOLFSSL_API int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store,
                                                            unsigned long flag);
WOLFSSL_API int          wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE*);
WOLFSSL_API int          wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX*,
                                   int, WOLFSSL_X509_NAME*, WOLFSSL_X509_OBJECT*);
WOLFSSL_API WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void);
WOLFSSL_API int  wolfSSL_X509_STORE_CTX_init(WOLFSSL_X509_STORE_CTX*,
                      WOLFSSL_X509_STORE*, WOLFSSL_X509*, STACK_OF(WOLFSSL_X509)*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX*);

WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_lastUpdate(WOLFSSL_X509_CRL*);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_nextUpdate(WOLFSSL_X509_CRL*);

WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_X509_get_pubkey(WOLFSSL_X509*);
WOLFSSL_API int       wolfSSL_X509_CRL_verify(WOLFSSL_X509_CRL*, WOLFSSL_EVP_PKEY*);
WOLFSSL_API void      wolfSSL_X509_STORE_CTX_set_error(WOLFSSL_X509_STORE_CTX*,
                                                     int);
WOLFSSL_API void      wolfSSL_X509_OBJECT_free_contents(WOLFSSL_X509_OBJECT*);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey(int type,
        WOLFSSL_EVP_PKEY** out, const unsigned char **in, long inSz);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_PKEY_new(void);
WOLFSSL_API void      wolfSSL_EVP_PKEY_free(WOLFSSL_EVP_PKEY*);
WOLFSSL_API int       wolfSSL_X509_cmp_current_time(const WOLFSSL_ASN1_TIME*);
WOLFSSL_API int       wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED*);

WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_X509_CRL_get_REVOKED(WOLFSSL_X509_CRL*);
WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
                                                      WOLFSSL_X509_REVOKED*,int);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_X509_get_serialNumber(WOLFSSL_X509*);

WOLFSSL_API int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO*, const WOLFSSL_ASN1_TIME*);

WOLFSSL_API int  wolfSSL_ASN1_INTEGER_cmp(const WOLFSSL_ASN1_INTEGER*,
                                       const WOLFSSL_ASN1_INTEGER*);
WOLFSSL_API long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER*);

#ifdef OPENSSL_EXTRA
/*!
    \ingroup wolfssl

    \brief This function is used to copy a WOLFSSL_ASN1_INTEGER value to a WOLFSSL_BIGNUM structure.
    
    \return pointer On successfully copying the WOLFSSL_ASN1_INTEGER value a WOLFSSL_BIGNUM pointer is returned.
    \return Null upon failure.
    
    \param ai WOLFSSL_ASN1_INTEGER structure to copy from.
    \param bn if wanting to copy into an already existing WOLFSSL_BIGNUM struct then pass in a pointer to it. Optionally this can be NULL and a new WOLFSSL_BIGNUM structure will be created.
    
    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* ai;
    WOLFSSL_BIGNUM* bn;
    // create ai
    bn = wolfSSL_ASN1_INTEGER_to_BN(ai, NULL);

    // or if having already created bn and wanting to reuse structure
    // wolfSSL_ASN1_INTEGER_to_BN(ai, bn);
    // check bn is or return value is not NULL
    \endcode
    
    \sa none
*/
WOLFSSL_API WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
                                       WOLFSSL_BIGNUM *bn);
WOLFSSL_API STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_load_client_CA_file(const char*);
#endif

WOLFSSL_API STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_SSL_CTX_get_client_CA_list(
        const WOLFSSL_CTX *s);
WOLFSSL_API void  wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX*,
                                               STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API void* wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX*, int);
WOLFSSL_API int   wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);
WOLFSSL_API void* wolfSSL_get_ex_data(const WOLFSSL*, int);

WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX*,
                                                          void* userdata);
WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX*,
                                                   pem_password_cb*);


WOLFSSL_API void wolfSSL_CTX_set_info_callback(WOLFSSL_CTX*,
                          void (*)(const WOLFSSL* ssl, int type, int val));

WOLFSSL_API unsigned long wolfSSL_ERR_peek_error(void);
WOLFSSL_API int           wolfSSL_GET_REASON(int);

WOLFSSL_API char* wolfSSL_alert_type_string_long(int);
WOLFSSL_API char* wolfSSL_alert_desc_string_long(int);
WOLFSSL_API char* wolfSSL_state_string_long(const WOLFSSL*);

WOLFSSL_API WOLFSSL_RSA* wolfSSL_RSA_generate_key(int, unsigned long,
                                               void(*)(int, int, void*), void*);
WOLFSSL_API void wolfSSL_CTX_set_tmp_rsa_callback(WOLFSSL_CTX*,
                                             WOLFSSL_RSA*(*)(WOLFSSL*, int, int));

WOLFSSL_API int wolfSSL_PEM_def_callback(char*, int num, int w, void* key);

WOLFSSL_API long wolfSSL_CTX_sess_accept(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_connect(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_accept_good(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_connect_good(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_accept_renegotiate(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_connect_renegotiate(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_hits(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_cb_hits(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_cache_full(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_misses(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_timeouts(WOLFSSL_CTX*);
WOLFSSL_API long wolfSSL_CTX_sess_number(WOLFSSL_CTX*);

/*!
    \ingroup wolfssl

    \brief This function adds the certificate to the internal chain being built in the WOLFSSL_CTX structure.
    
    \return SSL_SUCCESS after successfully adding the certificate.
    \return SSL_FAILURE if failing to add the certificate to the chain.
    
    \param ctx WOLFSSL_CTX structure to add certificate to.
    \param x509 certificate to add to the chain.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL_X509* x509;
    int ret;
    // create ctx
    ret = wolfSSL_CTX_add_extra_chain_cert(ctx, x509);
    // check ret value
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX*, WOLFSSL_X509*);
WOLFSSL_API long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX*, long);
WOLFSSL_API long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX*);

WOLFSSL_API long wolfSSL_CTX_get_session_cache_mode(WOLFSSL_CTX*);
/*!
    \ingroup wolfssl

    \brief This function returns the get read ahead flag from a WOLFSSL_CTX structure.
    
    \return flag On success returns the read ahead flag.
    \return SSL_FAILURE If ctx is NULL then SSL_FAILURE is returned.
    
    \param ctx WOLFSSL_CTX structure to get read ahead flag from.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    // setup ctx
    flag = wolfSSL_CTX_get_read_ahead(ctx);
    //check flag
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_read_ahead
*/
WOLFSSL_API int  wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX*);
/*!
    \ingroup wolfssl

    \brief This function sets the read ahead flag in the WOLFSSL_CTX structure.
    
    \return SSL_SUCCESS If ctx read ahead flag set.
    \return SSL_FAILURE If ctx is NULL then SSL_FAILURE is returned.
    
    \param ctx WOLFSSL_CTX structure to set read ahead flag.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_read_ahead(ctx, flag);
    // check return value
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_get_read_ahead
*/
WOLFSSL_API int  wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX*, int v);
/*!
    \ingroup wolfssl

    \brief This function sets the options argument to use with OCSP.
    
    \return SSL_FAILURE If ctx or it’s cert manager is NULL.
    \return SSL_SUCCESS If successfully set.
    
    \param ctx WOLFSSL_CTX structure to set user argument.
    \param arg user argument.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_status_arg(ctx, data);

    //check ret value
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX*, void* arg);
/*!
    \ingroup wolfssl

    \brief This function sets the optional argument to be passed to the PRF callback.
    
    \return SSL_FAILURE If ctx is NULL.
    \return SSL_SUCCESS If successfully set.
    
    \param ctx WOLFSSL_CTX structure to set user argument.
    \param arg user argument.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_opaques_prf_input_callback_arg(ctx, data);
    //check ret value
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(
        WOLFSSL_CTX*, void* arg);

/*!
    \ingroup wolfssl

    \brief This function sets the options mask in the ssl. Some valid options are, SSL_OP_ALL, SSL_OP_COOKIE_EXCHANGE, SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_TLSv1, SSL_OP_NO_TLSv1_1, SSL_OP_NO_TLSv1_2, SSL_OP_NO_COMPRESSION.
    
    \return val Returns the updated options mask value stored in ssl.
    
    \param ssl WOLFSSL structure to set options mask.
    
    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask = SSL_OP_NO_TLSv1
    mask  = wolfSSL_set_options(ssl, mask);
    // check mask
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_get_options
*/
WOLFSSL_API unsigned long wolfSSL_set_options(WOLFSSL *s, unsigned long op);
/*!
    \ingroup wolfssl

    \brief This function returns the current options mask.
    
    \return val Returns the mask value stored in ssl.
    
    \param ssl WOLFSSL structure to get options mask from.
    
    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask  = wolfSSL_get_options(ssl);
    // check mask
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_set_options
*/
WOLFSSL_API unsigned long wolfSSL_get_options(const WOLFSSL *s);
WOLFSSL_API long wolfSSL_clear_num_renegotiations(WOLFSSL *s);
WOLFSSL_API long wolfSSL_total_renegotiations(WOLFSSL *s);
/*!
    \ingroup wolfssl

    \brief This function sets the temporary DH to use during the handshake.
    
    \return SSL_SUCCESS On successful setting DH.
    \return SSL_FAILURE in error cases
    \return MEMORY_E in error cases
    \return SSL_FATAL_ERROR in error cases
    \return BAD_FUNC_ARG in error cases
    
    \param ssl WOLFSSL structure to set temporary DH.
    \param dh DH to use.
    
    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_DH* dh;
    int ret;
    // create ssl object
    ret  = wolfSSL_set_tmp_dh(ssl, dh);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API long wolfSSL_set_tmp_dh(WOLFSSL *s, WOLFSSL_DH *dh);
/*!
    \ingroup wolfssl

    \brief This is used to set the debug argument passed around.
    
    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If an NULL ssl passed in.
    
    \param ssl WOLFSSL structure to set argument in.
    \param arg argument to use.
    
    _Example_
    \code
    WOLFSSL* ssl;
    void* args;
    int ret;
    // create ssl object
    ret  = wolfSSL_set_tlsext_debug_arg(ssl, args);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API long wolfSSL_set_tlsext_debug_arg(WOLFSSL *s, void *arg);
/*!
    \ingroup openSSL
    
    \brief This function is called when the client application request that a server send back an OCSP status response (also known as OCSP stapling).Currently, the only supported type is TLSEXT_STATUSTYPE_ocsp.
    
    \return 1 upon success.
    \return 0 upon error.
    
    \param s pointer to WolfSSL struct which is created by SSL_new() function
    \param type ssl extension type which TLSEXT_STATUSTYPE_ocsp is only supported.
    
    _Example_
    \code
    WOLFSSL *ssl;
    WOLFSSL_CTX *ctx;
    int ret;
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    ssl = wolfSSL_new(ctx);
    ret = WolfSSL_set_tlsext_status_type(ssl,TLSEXT_STATUSTYPE_ocsp);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type);
WOLFSSL_API long wolfSSL_set_tlsext_status_exts(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_tlsext_status_ids(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_set_tlsext_status_ids(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char **resp);
WOLFSSL_API long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char *resp, int len);

WOLFSSL_API void wolfSSL_CONF_modules_unload(int all);
WOLFSSL_API long wolfSSL_get_tlsext_status_exts(WOLFSSL *s, void *arg);
/*!
    \ingroup wolfssl

    \brief This is used to get the results after trying to verify the peer's certificate.
    
    \return X509_V_OK On successful verification.
    \return SSL_FAILURE If an NULL ssl passed in.
    
    \param ssl WOLFSSL structure to get verification results from.
    
    _Example_
    WOLFSSL* ssl;
    long ret;
    // attempt/complete handshake
    ret  = wolfSSL_get_verify_result(ssl);
    // check ret value

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API long wolfSSL_get_verify_result(const WOLFSSL *ssl);

#define WOLFSSL_DEFAULT_CIPHER_LIST ""   /* default all */
#define WOLFSSL_RSA_F4 0x10001L

/* seperated out from other enums because of size */
enum {
    SSL_OP_MICROSOFT_SESS_ID_BUG                  = 0x00000001,
    SSL_OP_NETSCAPE_CHALLENGE_BUG                 = 0x00000002,
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG       = 0x00000004,
    SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG            = 0x00000008,
    SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER             = 0x00000010,
    SSL_OP_MSIE_SSLV2_RSA_PADDING                 = 0x00000020,
    SSL_OP_SSLEAY_080_CLIENT_DH_BUG               = 0x00000040,
    SSL_OP_TLS_D5_BUG                             = 0x00000080,
    SSL_OP_TLS_BLOCK_PADDING_BUG                  = 0x00000100,
    SSL_OP_TLS_ROLLBACK_BUG                       = 0x00000200,
    SSL_OP_ALL                                    = 0x00000400,
    SSL_OP_EPHEMERAL_RSA                          = 0x00000800,
    SSL_OP_NO_SSLv3                               = 0x00001000,
    SSL_OP_NO_TLSv1                               = 0x00002000,
    SSL_OP_PKCS1_CHECK_1                          = 0x00004000,
    SSL_OP_PKCS1_CHECK_2                          = 0x00008000,
    SSL_OP_NETSCAPE_CA_DN_BUG                     = 0x00010000,
    SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG        = 0x00020000,
    SSL_OP_SINGLE_DH_USE                          = 0x00040000,
    SSL_OP_NO_TICKET                              = 0x00080000,
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS            = 0x00100000,
    SSL_OP_NO_QUERY_MTU                           = 0x00200000,
    SSL_OP_COOKIE_EXCHANGE                        = 0x00400000,
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00800000,
    SSL_OP_SINGLE_ECDH_USE                        = 0x01000000,
    SSL_OP_CIPHER_SERVER_PREFERENCE               = 0x02000000,
    SSL_OP_NO_TLSv1_1                             = 0x04000000,
    SSL_OP_NO_TLSv1_2                             = 0x08000000,
    SSL_OP_NO_COMPRESSION                         = 0x10000000,
    SSL_OP_NO_TLSv1_3                             = 0x20000000,
};


enum {
    OCSP_NOCERTS     = 1,
    OCSP_NOINTERN    = 2,
    OCSP_NOSIGS      = 4,
    OCSP_NOCHAIN     = 8,
    OCSP_NOVERIFY    = 16,
    OCSP_NOEXPLICIT  = 32,
    OCSP_NOCASIGN    = 64,
    OCSP_NODELEGATED = 128,
    OCSP_NOCHECKS    = 256,
    OCSP_TRUSTOTHER  = 512,
    OCSP_RESPID_KEY  = 1024,
    OCSP_NOTIME      = 2048,

    OCSP_CERTID   = 2,
    OCSP_REQUEST  = 4,
    OCSP_RESPONSE = 8,
    OCSP_BASICRESP = 16,

    WOLFSSL_OCSP_URL_OVERRIDE = 1,
    WOLFSSL_OCSP_NO_NONCE     = 2,
    WOLFSSL_OCSP_CHECKALL     = 4,

    WOLFSSL_CRL_CHECKALL = 1,
    WOLFSSL_CRL_CHECK    = 27,

    ASN1_GENERALIZEDTIME = 4,
    SSL_MAX_SSL_SESSION_ID_LENGTH = 32,

    EVP_R_BAD_DECRYPT = 2,

    SSL_ST_CONNECT = 0x1000,
    SSL_ST_ACCEPT  = 0x2000,

    SSL_CB_LOOP = 0x01,
    SSL_CB_EXIT = 0x02,
    SSL_CB_READ = 0x04,
    SSL_CB_WRITE = 0x08,
    SSL_CB_HANDSHAKE_START = 0x10,
    SSL_CB_HANDSHAKE_DONE = 0x20,
    SSL_CB_ALERT = 0x4000,
    SSL_CB_READ_ALERT = (SSL_CB_ALERT | SSL_CB_READ),
    SSL_CB_WRITE_ALERT = (SSL_CB_ALERT | SSL_CB_WRITE),
    SSL_CB_ACCEPT_LOOP = (SSL_ST_ACCEPT | SSL_CB_LOOP),
    SSL_CB_ACCEPT_EXIT = (SSL_ST_ACCEPT | SSL_CB_EXIT),
    SSL_CB_CONNECT_LOOP = (SSL_ST_CONNECT | SSL_CB_LOOP),
    SSL_CB_CONNECT_EXIT = (SSL_ST_CONNECT | SSL_CB_EXIT),

    SSL_MODE_ENABLE_PARTIAL_WRITE = 2,

    BIO_FLAGS_BASE64_NO_NL = 1,
    BIO_CLOSE   = 1,
    BIO_NOCLOSE = 0,

    NID_undef = 0,

    X509_FILETYPE_PEM = 8,
    X509_LU_X509      = 9,
    X509_LU_CRL       = 12,

    X509_V_OK                                    = 0,
    X509_V_ERR_CRL_SIGNATURE_FAILURE             = 13,
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD    = 14,
    X509_V_ERR_CRL_HAS_EXPIRED                   = 15,
    X509_V_ERR_CERT_REVOKED                      = 16,
    X509_V_ERR_CERT_CHAIN_TOO_LONG               = 17,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT         = 18,
    X509_V_ERR_CERT_NOT_YET_VALID                = 19,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD    = 20,
    X509_V_ERR_CERT_HAS_EXPIRED                  = 21,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD     = 22,
    X509_V_ERR_CERT_REJECTED                     = 23,
    /* Required for Nginx  */
    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT       = 24,
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN         = 25,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 26,
    X509_V_ERR_CERT_UNTRUSTED                    = 27,
    X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE   = 28,
    X509_V_ERR_SUBJECT_ISSUER_MISMATCH           = 29,
    /* additional X509_V_ERR_* enums not used in wolfSSL */
    X509_V_ERR_UNABLE_TO_GET_CRL,
    X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
    X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
    X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
    X509_V_ERR_CERT_SIGNATURE_FAILURE,
    X509_V_ERR_CRL_NOT_YET_VALID,
    X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
    X509_V_ERR_OUT_OF_MEM,
    X509_V_ERR_INVALID_CA,
    X509_V_ERR_PATH_LENGTH_EXCEEDED,
    X509_V_ERR_INVALID_PURPOSE,
    X509_V_ERR_AKID_SKID_MISMATCH,
    X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
    X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
    X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
    X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION,
    X509_V_ERR_KEYUSAGE_NO_CRL_SIGN,
    X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
    X509_V_ERR_INVALID_NON_CA,
    X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED,
    X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE,
    X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED,
    X509_V_ERR_INVALID_EXTENSION,
    X509_V_ERR_INVALID_POLICY_EXTENSION,
    X509_V_ERR_NO_EXPLICIT_POLICY,
    X509_V_ERR_UNNESTED_RESOURCE,

    XN_FLAG_SPC_EQ  = (1 << 23),
    XN_FLAG_ONELINE = 0,
    XN_FLAG_RFC2253 = 1,

    CRYPTO_LOCK = 1,
    CRYPTO_NUM_LOCKS = 10,

    ASN1_STRFLGS_ESC_MSB = 4
};

/* extras end */

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
/* wolfSSL extension, provide last error from SSL_get_error
   since not using thread storage error queue */
#include <stdio.h>
/*!
    \ingroup wolfssl

    \brief This function converts an error code returned by wolfSSL_get_error() into a more human-readable error string and prints that string to the output file - fp.  err is the error code returned by wolfSSL_get_error() and fp is the file which the error string will be placed in.
    
    \return none No returns.
    
    \param fp output file for human-readable error string to be written to.
    \param err error code returned by wolfSSL_get_error().
    
    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    FILE* fp = ...
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_print_errors_fp(fp, err);
    \endcode
    
    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_load_error_strings
*/
WOLFSSL_API void  wolfSSL_ERR_print_errors_fp(FILE*, int err);
#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
WOLFSSL_API void wolfSSL_ERR_dump_errors_fp(FILE* fp);
#endif
#endif

enum { /* ssl Constants */
    SSL_ERROR_NONE      =  0,   /* for most functions */
    SSL_FAILURE         =  0,   /* for some functions */
    SSL_SUCCESS         =  1,
    SSL_SHUTDOWN_NOT_DONE =  2,  /* call wolfSSL_shutdown again to complete */

    SSL_ALPN_NOT_FOUND  = -9,
    SSL_BAD_CERTTYPE    = -8,
    SSL_BAD_STAT        = -7,
    SSL_BAD_PATH        = -6,
    SSL_BAD_FILETYPE    = -5,
    SSL_BAD_FILE        = -4,
    SSL_NOT_IMPLEMENTED = -3,
    SSL_UNKNOWN         = -2,
    SSL_FATAL_ERROR     = -1,

    SSL_FILETYPE_ASN1    = 2,
    SSL_FILETYPE_PEM     = 1,
    SSL_FILETYPE_DEFAULT = 2, /* ASN1 */
    SSL_FILETYPE_RAW     = 3, /* NTRU raw key blob */

    SSL_VERIFY_NONE                 = 0,
    SSL_VERIFY_PEER                 = 1,
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    SSL_VERIFY_CLIENT_ONCE          = 4,
    SSL_VERIFY_FAIL_EXCEPT_PSK      = 8,

    SSL_SESS_CACHE_OFF                = 0x0000,
    SSL_SESS_CACHE_CLIENT             = 0x0001,
    SSL_SESS_CACHE_SERVER             = 0x0002,
    SSL_SESS_CACHE_BOTH               = 0x0003,
    SSL_SESS_CACHE_NO_AUTO_CLEAR      = 0x0008,
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100,
    SSL_SESS_CACHE_NO_INTERNAL_STORE  = 0x0200,
    SSL_SESS_CACHE_NO_INTERNAL        = 0x0300,

    SSL_ERROR_WANT_READ        =  2,
    SSL_ERROR_WANT_WRITE       =  3,
    SSL_ERROR_WANT_CONNECT     =  7,
    SSL_ERROR_WANT_ACCEPT      =  8,
    SSL_ERROR_SYSCALL          =  5,
    SSL_ERROR_WANT_X509_LOOKUP = 83,
    SSL_ERROR_ZERO_RETURN      =  6,
    SSL_ERROR_SSL              = 85,

    SSL_SENT_SHUTDOWN     = 1,
    SSL_RECEIVED_SHUTDOWN = 2,
    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4,
    SSL_OP_NO_SSLv2       = 8,

    SSL_R_SSL_HANDSHAKE_FAILURE           = 101,
    SSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102,
    SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103,
    SSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104,

    PEM_BUFSIZE = 1024
};


#ifndef NO_PSK
    typedef unsigned int (*wc_psk_client_callback)(WOLFSSL*, const char*, char*,
                                    unsigned int, unsigned char*, unsigned int);
/*!
    \ingroup wolfssl

    \brief The function sets the client_psk_cb member of the WOLFSSL_CTX structure.
    
    \return none No returns.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param cb wc_psk_client_callback is a function pointer that will be stored in the WOLFSSL_CTX structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    …
    static INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    Unsigned int key_max_len){
    …
    wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
    \endcode
    
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
    WOLFSSL_API void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX*,
                                                    wc_psk_client_callback);
/*!
    \ingroup wolfssl

    \brief Sets the PSK client side callback.
    
    \return none No returns.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to type wc_psk_client_callback.
    
    _Example_
    \code
    WOLFSSL* ssl;
    unsigned int cb(WOLFSSL*, const char*, char*) // Header of function*
    {
    	// Funciton body
    }
    …
    cb = wc_psk_client_callback;
    if(ssl){
    wolfSSL_set_psk_client_callback(ssl, cb);
    } else {
    	// could not set callback
    }
    \endcode
    
    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_set_psk_server_callback
*/
    WOLFSSL_API void wolfSSL_set_psk_client_callback(WOLFSSL*,
                                                    wc_psk_client_callback);

/*!
    \ingroup wolfssl

    \brief This function returns the psk identity hint.
    
    \return pointer a const char pointer to the value that was stored in the arrays member of the WOLFSSL structure is returned.
    \return NULL returned if the WOLFSSL or Arrays structures are NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* idHint;
    ...
    idHint = wolfSSL_get_psk_identity_hint(ssl);
    if(idHint){
    	// The hint was retrieved
    	return idHint;
    } else {
    	// Hint wasn’t successfully retrieved
    }
    \endcode
    
    \sa wolfSSL_get_psk_identity
*/
    WOLFSSL_API const char* wolfSSL_get_psk_identity_hint(const WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief The function returns a constant pointer to the client_identity member of the Arrays structure.
    
    \return string the string value of the client_identity member of the Arrays structure.
    \return NULL if the WOLFSSL structure is NULL or if the Arrays member of the WOLFSSL structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* pskID;
    ...
    pskID = wolfSSL_get_psk_identity(ssl);

    if(pskID == NULL){
	    // There is not a value in pskID
    }
    \endcode
    
    \sa wolfSSL_get_psk_identity_hint
    \sa wolfSSL_use_psk_identity_hint
*/
    WOLFSSL_API const char* wolfSSL_get_psk_identity(const WOLFSSL*);

/*!
    \ingroup wolfssl

    \brief This function stores the hint argument in the server_hint member of the WOLFSSL_CTX structure.
    
    \return SSL_SUCCESS returned for successful execution of the function.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param hint a constant char pointer that will be copied to the WOLFSSL_CTX structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    const char* hint;
    int ret;
    …
    ret = wolfSSL_CTX_use_psk_identity_hint(ctx, hint);
    if(ret == SSL_SUCCESS){
    	// Function was succesfull.
	return ret;
    } else {
    	// Failure case.
    }
    \endcode
    
    \sa wolfSSL_use_psk_identity_hint
*/
    WOLFSSL_API int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX*, const char*);
/*!
    \ingroup wolfssl

    \brief This function stores the hint argument in the server_hint member of the Arrays structure within the WOLFSSL structure.
    
    \return SSL_SUCCESS returned if the hint was successfully stored in the WOLFSSL structure.
    \return SSL_FAILURE returned if the WOLFSSL or Arrays structures are NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \para hint a constant character pointer that holds the hint to be saved in memory.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* hint;
    ...
    if(wolfSSL_use_psk_identity_hint(ssl, hint) != SSL_SUCCESS){
    	// Handle failure case.
    }
    \endcode
    
    \sa wolfSSL_CTX_use_psk_identity_hint
*/
    WOLFSSL_API int wolfSSL_use_psk_identity_hint(WOLFSSL*, const char*);

    typedef unsigned int (*wc_psk_server_callback)(WOLFSSL*, const char*,
                          unsigned char*, unsigned int);
/*!
    \ingroup wolfssl

    \brief This function sets the psk callback for the server side in the WOLFSSL_CTX structure.
    
    \return none No returns.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer for the callback and will be stored in the WOLFSSL_CTX structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    unsigned int cb(WOLFSSL*, const char*, unsigned char*, unsigned int)
        // signature requirement
    {
    	// Function body.
    }
    …
    if(ctx != NULL){
    wolfSSL_CTX_set_psk_server_callback(ctx, cb);
    } else {
    	// The CTX object was not properly initialized.
    }
    \endcode
    
    \sa wc_psk_server_callback
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
    WOLFSSL_API void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX*,
                                                    wc_psk_server_callback);
/*!
    \ingroup wolfssl

    \brief Sets the psk callback for the server side by setting the WOLFSSL structure options members.
    
    \return none No returns.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer for the callback and will be stored in the WOLFSSL structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    …
    int cb(WOLFSSL*, const char*, unsigned char*, unsigned int) // Required sig.
    {
    	// Function body.
    }
    …
    if(ssl != NULL && cb != NULL){
    	wolfSSL_set_psk_server_callback(ssl, cb);
    }
    \endcode
    
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_get_psk_identity_hint
    \sa wc_psk_server_callback
    \sa InitSuites
*/
    WOLFSSL_API void wolfSSL_set_psk_server_callback(WOLFSSL*,
                                                    wc_psk_server_callback);

    #define PSK_TYPES_DEFINED
#endif /* NO_PSK */


#ifdef HAVE_ANON
/*!
    \ingroup wolfssl

    \brief This function enables the havAnon member of the CTX structure if HAVE_ANON is defined during compilation.
    
    \return SSL_SUCCESS returned if the function executed successfully and the haveAnnon member of the CTX is set to 1.
    \return SSL_FAILURE returned if the CTX structure was NULL.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    #ifdef HAVE_ANON
	if(cipherList == NULL){
	    wolfSSL_CTX_allow_anon_cipher(ctx);
	    if(wolfSSL_CTX_set_cipher_list(ctx, “ADH_AES128_SHA”) != SSL_SUCCESS){
		    // failure case
	    }	
    } 
    #endif
    \endcode
    
    \sa none
*/
    WOLFSSL_API int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX*);
#endif /* HAVE_ANON */


/* extra begins */

enum {  /* ERR Constants */
    ERR_TXT_STRING = 1
};

/* bio misc */
enum {
    WOLFSSL_BIO_ERROR = -1,
    WOLFSSL_BIO_UNSET = -2,
    WOLFSSL_BIO_SIZE  = 17000 /* default BIO write size if not set */
};


WOLFSSL_API unsigned long wolfSSL_ERR_get_error_line_data(const char**, int*,
                                                 const char**, int *);

WOLFSSL_API unsigned long wolfSSL_ERR_get_error(void);
WOLFSSL_API void          wolfSSL_ERR_clear_error(void);


WOLFSSL_API int  wolfSSL_RAND_status(void);
WOLFSSL_API int  wolfSSL_RAND_bytes(unsigned char* buf, int num);
/*!
    \ingroup wolfssl

    \brief The wolfSSLv23_server_method() function is used to indicate that the application is a server and will support clients connecting with protocol version from SSL 3.0 - TLS 1.2.  This function allocates memory for and initializes a new WOLFSSL_METHOD structure to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    
    \return pointer If successful, the call will return a pointer to the newly created WOLFSSL_METHOD structure.
    \return Failure If memory allocation fails when calling XMALLOC, the failure value of the underlying malloc() implementation will be returned (typically NULL with errno will be set to ENOMEM).
    
    \param none
    
    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv23_server_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode
    
    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_server_method(void);
WOLFSSL_API long wolfSSL_CTX_set_options(WOLFSSL_CTX*, long);
#ifndef NO_CERTS
  WOLFSSL_API int  wolfSSL_CTX_check_private_key(WOLFSSL_CTX*);
#endif /* !NO_CERTS */

WOLFSSL_API void wolfSSL_ERR_free_strings(void);
WOLFSSL_API void wolfSSL_ERR_remove_state(unsigned long);
WOLFSSL_API void wolfSSL_EVP_cleanup(void);
WOLFSSL_API int  wolfSSL_clear(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This is used to get the internal error state of the WOLFSSL structure.
    
    \return wolfssl_error returns ssl error state, usualy a negative
    \return BAD_FUNC_ARG if ssl is NULL.
    
    \return ssl WOLFSSL structure to get state from.
    
    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create ssl object
    ret  = wolfSSL_state(ssl);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API int  wolfSSL_state(WOLFSSL* ssl);

WOLFSSL_API void wolfSSL_cleanup_all_ex_data(void);
WOLFSSL_API long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode);
WOLFSSL_API long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx);
WOLFSSL_API void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m);
WOLFSSL_API long wolfSSL_SSL_get_mode(WOLFSSL* ssl);


WOLFSSL_API int  wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_CTX_set_session_id_context(WOLFSSL_CTX*,
                                            const unsigned char*, unsigned int);
/*!
    \ingroup wolfssl

    \brief This function gets the peer’s certificate.
    
    \return pointer a pointer to the peerCert member of the WOLFSSL_X509 structure if it exists.
    \return 0 returned if the peer certificate issuer size is not defined.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    WOLFSSL_X509* peerCert = wolfSSL_get_peer_certificate(ssl);

    if(peerCert){
    	// You have a pointer peerCert to the peer certification
    }
    
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLFSSL_API WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);

/*!
    \ingroup wolfssl

    \brief This function is similar to calling wolfSSL_get_error() and getting SSL_ERROR_WANT_READ in return.  If the underlying error state is SSL_ERROR_WANT_READ, this function will return 1, otherwise, 0.
    
    \return 1 wolfSSL_get_error() would return SSL_ERROR_WANT_READ, the underlying I/O has data available for reading.
    \return 0 There is no SSL_ERROR_WANT_READ error state.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_want_read(ssl);
    if (ret == 1) {
    	// underlying I/O has data available for reading (SSL_ERROR_WANT_READ)
    }
    \endcode
    
    \sa wolfSSL_want_write
    \sa wolfSSL_get_error
*/
WOLFSSL_API int wolfSSL_want_read(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function is similar to calling wolfSSL_get_error() and getting SSL_ERROR_WANT_WRITE in return. If the underlying error state is SSL_ERROR_WANT_WRITE, this function will return 1, otherwise, 0.
    
    \return 1 wolfSSL_get_error() would return SSL_ERROR_WANT_WRITE, the underlying I/O needs data to be written in order for progress to be made in the underlying SSL connection.
    \return 0 There is no SSL_ERROR_WANT_WRITE error state.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_want_write(ssl);
    if (ret == 1) {
    	// underlying I/O needs data to be written (SSL_ERROR_WANT_WRITE)
    }
    \endcode
    
    \sa wolfSSL_want_read
    \sa wolfSSL_get_error
*/
WOLFSSL_API int wolfSSL_want_write(WOLFSSL*);

WOLFSSL_API int wolfSSL_BIO_printf(WOLFSSL_BIO*, const char*, ...);
WOLFSSL_API int wolfSSL_ASN1_UTCTIME_print(WOLFSSL_BIO*,
                                         const WOLFSSL_ASN1_UTCTIME*);
WOLFSSL_API int wolfSSL_ASN1_GENERALIZEDTIME_print(WOLFSSL_BIO*,
                                         const WOLFSSL_ASN1_GENERALIZEDTIME*);
WOLFSSL_API int   wolfSSL_sk_num(WOLFSSL_X509_REVOKED*);
WOLFSSL_API void* wolfSSL_sk_value(WOLFSSL_X509_REVOKED*, int);

/* stunnel 4.28 needs */
WOLFSSL_API void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX*, int);
WOLFSSL_API int   wolfSSL_CTX_set_ex_data(WOLFSSL_CTX*, int, void*);
WOLFSSL_API void  wolfSSL_CTX_sess_set_get_cb(WOLFSSL_CTX*,
                       WOLFSSL_SESSION*(*f)(WOLFSSL*, unsigned char*, int, int*));
WOLFSSL_API void  wolfSSL_CTX_sess_set_new_cb(WOLFSSL_CTX*,
                                            int (*f)(WOLFSSL*, WOLFSSL_SESSION*));
WOLFSSL_API void  wolfSSL_CTX_sess_set_remove_cb(WOLFSSL_CTX*,
                                       void (*f)(WOLFSSL_CTX*, WOLFSSL_SESSION*));

WOLFSSL_API int          wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION*,unsigned char**);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_d2i_SSL_SESSION(WOLFSSL_SESSION**,
                                                   const unsigned char**, long);

WOLFSSL_API long wolfSSL_SESSION_get_timeout(const WOLFSSL_SESSION*);
WOLFSSL_API long wolfSSL_SESSION_get_time(const WOLFSSL_SESSION*);
WOLFSSL_API int  wolfSSL_CTX_get_ex_new_index(long, void*, void*, void*, void*);

/* extra ends */


/* wolfSSL extensions */

/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
/*!
    \ingroup wolfssl

    \brief wolfSSL by default checks the peer certificate for a valid date range and a verified signature.  Calling this function before wolfSSL_connect() or wolfSSL_accept() will add a domain name check to the list of checks to perform.  dn holds the domain name to check against the peer certificate when it’s received.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE will be returned if a memory error was encountered.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param dn domain name to check against the peer certificate when received.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    char* domain = (char*) “www.yassl.com”;
    ...

    ret = wolfSSL_check_domain_name(ssl, domain);
    if (ret != SSL_SUCCESS) {
       // failed to enable domain name check
    }
    \endcode
    
    \sa none
*/
WOLFSSL_API int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn);

/* need to call once to load library (session cache) */
/*!
    \ingroup wolfssl

    \brief Initializes the wolfSSL library for use.  Must be called once per application and before any other call to the library.
    
    \return SSL_SUCCESS If successful the call will return.
    \return BAD_MUTEX_E is an error that may be returned.
    \return WC_INIT_E wolfCrypt initialization error returned.
    
    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL library
    }

    \endcode
    
    \sa wolfSSL_Cleanup
*/
WOLFSSL_API int wolfSSL_Init(void);
/* call when done to cleanup/free session cache mutex / resources  */
/*!
    \ingroup wolfssl

    \brief Un-initializes the wolfSSL library from further use.  Doesn’t have to be called, though it will free any resources used by the library.
    
    \return SSL_SUCCESS return no errors.
    \return BAD_MUTEX_E a mutex error return.]
    
    _Example_
    \code
    wolfSSL_Cleanup();
    \endcode
    
    \sa wolfSSL_Init
*/
WOLFSSL_API int wolfSSL_Cleanup(void);

/* which library version do we have */
/*!
    \ingroup wolfssl

    \brief This function returns the current library version.
    
    \return LIBWOLFSSL_VERSION_STRING a const char pointer defining the version.
    
    \param none No parameters.
    
    _Example_
    \code
    char version[MAXSIZE];
    version = wolfSSL_KeepArrays();
    …
    if(version != ExpectedVersion){
	    // Handle the mismatch case
    }
    \endcode
    
    \sa word32_wolfSSL_lib_version_hex
*/
WOLFSSL_API const char* wolfSSL_lib_version(void);
/* which library version do we have in hex */
/*!
    \ingroup wolfssl

    \brief This function returns the current library version in hexadecimal notation.
    
    \return LILBWOLFSSL_VERSION_HEX returns the hexidecimal version defined in wolfssl/version.h.
    
    \param none No parameters.
    
    _Example_
    \code
    word32 libV;
    libV = wolfSSL_lib_version_hex();

    if(libV != EXPECTED_HEX){
	    // How to handle an unexpected value
    } else {
	    // The expected result for libV
    }
    \endcode
    
    \sa wolfSSL_lib_version
*/
WOLFSSL_API unsigned int wolfSSL_lib_version_hex(void);

/* turn logging on, only if compiled in */
/*!
    \ingroup wolfssl

    \brief If logging has been enabled at build time this function turns on logging at runtime.  To enable logging at build time use --enable-debug or define DEBUG_WOLFSSL.
    
    \return 0 upon success.
    \return NOT_COMPILED_IN is the error that will be returned if logging isn’t enabled for this build.
    
    \param none No parameters.
    
    _Example_
    \code
    wolfSSL_Debugging_ON();
    \endcode
    
    \sa wolfSSL_Debugging_OFF
    \sa wolfSSL_SetLoggingCb
*/
WOLFSSL_API int  wolfSSL_Debugging_ON(void);
/* turn logging off */
/*!
    \ingroup wolfssl

    \brief This function turns off runtime logging messages.  If they’re already off, no action is taken.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    wolfSSL_Debugging_OFF();
    \endcode
    
    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_SetLoggingCb
*/
WOLFSSL_API void wolfSSL_Debugging_OFF(void);

/* do accept or connect depedning on side */
/*!
    \ingroup wolfssl

    \brief Performs the actual connect or accept based on the side of the SSL method.  If called from the client side then an wolfSSL_connect() is done while a wolfSSL_accept() is performed if called from the server side.
    
    \return SSL_SUCCESS will be returned if successful. (Note, older versions will return 0.)
    \return SSL_FATAL_ERROR will be returned if the underlying call resulted in an error. Use wolfSSL_get_error() to get a specific error code.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    int ret = SSL_FATAL_ERROR;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_negotiate(ssl);
    if (ret == SSL_FATAL_ERROR) {
    	// SSL establishment failed
	int error_code = wolfSSL_get_error(ssl);
	...
    }
    ...
    \endcode
    
    \sa SSL_connect
    \sa SSL_accept
*/
WOLFSSL_API int wolfSSL_negotiate(WOLFSSL* ssl);
/* turn on wolfSSL data compression */
/*!
    \ingroup wolfssl

    \brief Turns on the ability to use compression for the SSL connection.  Both sides must have compression turned on otherwise compression will not be used.  The zlib library performs the actual data compression.  To compile into the library use --with-libz for the configure system and define HAVE_LIBZ otherwise. Keep in mind that while compressing data before sending decreases the actual size of the messages being sent and received, the amount of data saved by compression usually takes longer in time to analyze than it does to send it raw on all but the slowest of networks.

    \return SSL_SUCCESS upon success.
    \return NOT_COMPILED_IN will be returned if compression support wasn’t built into the library.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_compression(ssl);
    if (ret == SSL_SUCCESS) {
    	// successfully enabled compression for SSL session
    }
    \endcode
    
    \sa none
*/
WOLFSSL_API int wolfSSL_set_compression(WOLFSSL* ssl);

/*!
    \ingroup wolfssl

    \brief This function sets the SSL session timeout value in seconds.
    
    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned if ssl is NULL.
    
    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param to value, in seconds, used to set the SSL session timeout.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_timeout(ssl, 500);
    if (ret != SSL_SUCCESS) {
    	// failed to set session timeout value
    }
    ...
    \endcode
    
    \sa wolfSSL_get_session
    \sa wolfSSL_set_session
*/
WOLFSSL_API int wolfSSL_set_timeout(WOLFSSL*, unsigned int);
/*!
    \ingroup wolfssl

    \brief This function sets the timeout value for SSL sessions, in seconds, for the specified SSL context.
    
    \return SSL_SUCCESS will be returned upon success.
    \return BAD_FUNC_ARG will be returned when the input context (ctx) is null.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param to session timeout value in seconds.
    
    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    ret = wolfSSL_CTX_set_timeout(ctx, 500);
    if (ret != SSL_SUCCESS) {
	    // failed to set session timeout value
    }
    \endcode
    
    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_session_cache_mode
*/
WOLFSSL_API int wolfSSL_CTX_set_timeout(WOLFSSL_CTX*, unsigned int);

/* get wolfSSL peer X509_CHAIN */
/*!
    \ingroup openSSL
    
    \brief Retrieves the peer’s certificate chain.
    
    \return chain If successful the call will return the peer’s certificate chain.
    \return 0 will be returned if an invalid WOLFSSL pointer is passed to the function.
    
    \param ssl pointer to a valid WOLFSSL structure.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
WOLFSSL_API WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl);
/* peer chain count */
/*!
    \ingroup openSSL
    
    \brief Retrieve's the peers certificate chain count.
    
    \return Success If successful the call will return the peer’s certificate chain count.
    \return 0 will be returned if an invalid chain pointer is passed to the function.
    
    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/  
WOLFSSL_API int  wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain);
/* index cert length */
/*!
    \ingroup openSSL
    
    \brief Retrieves the peer’s ASN1.DER certificate length in bytes at index (idx).
    
    \return Success If successful the call will return the peer’s certificate length in bytes by index.
    \return 0 will be returned if an invalid chain pointer is passed to the function.
    
    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx index to start of chain.
    
    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
WOLFSSL_API int  wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN*, int idx);
/* index cert */
/*!
    \ingroup openSSL
    
    \brief Retrieves the peer’s ASN1.DER certificate at index (idx).
    
    \return Success If successful the call will return the peer’s certificate by index.
    \return 0 will be returned if an invalid chain pointer is passed to the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx index to start of chain.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert_pem
*/
WOLFSSL_API unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN*, int idx);
/* index cert in X509 */
/*!
    \ingroup wolfssl

    \brief This function gets the peer’s wolfSSL_X509_certificate at index (idx) from the chain of certificates.
    
    \return pointer returns a pointer to a WOLFSSL_X509 structure.
    
    \param chain a pointer to the WOLFSSL_X509_CHAIN used for no dynamic memory SESSION_CACHE.
    \param idx the index of the WOLFSSL_X509 certificate.
    
    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = &session->chain;
    int idx = 999; // set idx
    ...
    WOLFSSL_X509_CHAIN ptr;
    prt = wolfSSL_get_chain_X509(chain, idx);

    if(ptr != NULL){
        //ptr contains the cert at the index specified
    } else {
	    // ptr is NULL 
    }
    \endcode
    
    \sa InitDecodedCert
    \sa ParseCertRelative
    \sa CopyDecodedToX509
*/
WOLFSSL_API WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN*, int idx);
/* free X509 */
WOLFSSL_API void wolfSSL_FreeX509(WOLFSSL_X509*);
/* get index cert in PEM */
/*!
    \ingroup openSSL
    
    \brief Retrieves the peer’s PEM certificate at index (idx).
    
    \return Success If successful the call will return the peer’s certificate by index.
    \return 0 will be returned if an invalid chain pointer is passed to the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx indexto start of chain.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
*/
WOLFSSL_API int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN*, int idx,
                                unsigned char* buf, int inLen, int* outLen);
/*!
    \ingroup openSSL

    \brief Retrieves the session’s ID.  The session ID is always 32 bytes long.
    
    \return id The session ID.
    
    \param session pointer to a valid wolfssl session.
    
    _Example_
    \code
    none
    \endcode
    
    \sa SSL_get_session
*/
WOLFSSL_API const unsigned char* wolfSSL_get_sessionID(const WOLFSSL_SESSION* s);
/*!
    \ingroup openSSL
    
    \brief Retrieves the peer’s certificate serial number. The serial number buffer (in) should be at least 32 bytes long and be provided as the *inOutSz argument as input. After calling the function *inOutSz will hold the actual length in bytes written to the in buffer.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if a bad function argument was encountered.
    
    \param in The serial number buffer and should be at least 32 bytes long
    \param inOutSz will hold the actual length in bytes written to the in buffer.
    
    _Example_
    \code
    none
    \endcode
    
    \sa SSL_get_peer_certificate
*/
WOLFSSL_API int  wolfSSL_X509_get_serial_number(WOLFSSL_X509*,unsigned char*,int*);
/*!
    \ingroup wolfssl

    \brief Returns the common name of the subject from the certificate.
    
    \return NULL returned if the x509 structure is null
    \return string a string representation of the subject's common name is returned upon success
    
    \param x509 a pointer to a WOLFSSL_X509 structure containing certificate information.
    
    _Example_
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509Cn = wolfSSL_X509_get_subjectCN(x509);
    if(x509Cn == NULL){
	    // Deal with NULL case
    } else {
	    // x509Cn contains the common name
    }
    
    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name

*/
WOLFSSL_API char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509*);
/*!
    \ingroup wolfssl

    \brief This function gets the DER encoded certificate in the WOLFSSL_X509 struct.
    
    \return buffer This function returns the DerBuffer structure’s buffer member, which is of type byte.
    \return NULL returned if the x509 or outSz parameter is NULL.
    
    \param x509 a pointer to a WOLFSSL_X509 structure containing certificate information.
    \param outSz length of the derBuffer member of the WOLFSSL_X509 struct.
    
    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    int* outSz; // initialize
    ...
    byte* x509Der = wolfSSL_X509_get_der(x509, outSz);
    if(x509Der == NULL){
	    // Failure case one of the parameters was NULL
    }
    \endcode
    
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
WOLFSSL_API const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509*, int*);
WOLFSSL_API const unsigned char* wolfSSL_X509_notBefore(WOLFSSL_X509*);
/*!
    \ingroup wolfssl

    \brief This function checks to see if x509 is NULL and if it’s not, it returns the notAfter member of the x509 struct.
    
    \return pointer returns a constant byte pointer to the notAfter member of the x509 struct.
    \return NULL returned if the x509 object is NULL.
    
    \param x509 a pointer to the WOLFSSL_X509 struct.
    
    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    ...
    byte* notAfter = wolfSSL_X509_notAfter(x509);
    if(notAfter == NULL){
	    // Failure case, the x509 object is null.
    }
    \endcode
    
    \sa none 
*/
WOLFSSL_API const unsigned char* wolfSSL_X509_notAfter(WOLFSSL_X509*);
/*!
    \ingroup wolfssl

    \brief This function retrieves the version of the X509 certificate.
    
    \return 0 returned if the x509 structure is NULL.
    \return version the version stored in the x509 structure will be returned.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_X509* x509;
    int version;
    ...
    version = wolfSSL_X509_version(x509);
    if(!version){
	    // The function returned 0, failure case.
    }
    \endcode
    
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_API int wolfSSL_X509_version(WOLFSSL_X509*);

WOLFSSL_API int wolfSSL_cmp_peer_cert_to_file(WOLFSSL*, const char*);
/*!
    \ingroup wolfssl

    \brief This function returns the next, if any, altname from the peer certificate.
    
    \return NULL if there is not a next altname.
    \return cert->altNamesNext->name from the WOLFSSL_X509 structure that is a string value from the altName list is returned if it exists.
    
    \param cert a pointer to the wolfSSL_X509 structure.
    
    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509NextAltName = wolfSSL_X509_get_next_altname(x509);
    if(x509NextAltName == NULL){
	    // There isn’t another alt name
    }
    \endcode
    
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
WOLFSSL_API char* wolfSSL_X509_get_next_altname(WOLFSSL_X509*);

WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_d2i(WOLFSSL_X509** x509, const unsigned char* in, int len);
#ifndef NO_FILESYSTEM
    #ifndef NO_STDIO_FILESYSTEM
/*!
    \ingroup wolfssl

    \brief If NO_STDIO_FILESYSTEM is defined this function will allocate heap memory, initialize a WOLFSSL_X509 structure and return a pointer to it.
    
    \return *WOLFSSL_X509 WOLFSSL_X509 structure pointer is returned if the function executes successfully.
    \return NULL if the call to XFTELL macro returns a negative value.
    
    \param x509 a pointer to a WOLFSSL_X509 pointer.
    \param file a defined type that is a pointer to a FILE.
    
    _Example_
    \code
    WOLFSSL_X509* x509a = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL, 
    DYNAMIC_TYPE_X509);
    WOLFSSL_X509** x509 = x509a;
    XFILE file;  (mapped to struct fs_file*)
    ...
    WOLFSSL_X509* newX509 = wolfSSL_X509_d2i_fp(x509, file);
    if(newX509 == NULL){
	    // The function returned NULL
    }
    \endcode
    
    \sa wolfSSL_X509_d2i
    \sa XFTELL
    \sa XREWIND
    \sa XFSEEK
*/
    WOLFSSL_API WOLFSSL_X509*
        wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, FILE* file);
    #endif
/*!
    \ingroup wolfssl

    \brief The function loads the x509 certificate into memory.
    
    \return pointer a successful execution returns pointer to a WOLFSSL_X509 structure.
    \return NULL returned if the certificate was not able to be written.
    
    \param fname the certificate file to be loaded.
    \param format the format of the certificate.
    
    _Example_
    \code
    #define cliCert    “certs/client-cert.pem”
    …
    X509* x509;
    …
    x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM); 
    AssertNotNull(x509);
    \endcode
    
    \sa InitDecodedCert
    \sa PemToDer
    \sa wolfSSL_get_certificate
    \sa AssertNotNull
*/
WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_load_certificate_file(const char* fname, int format);
#endif
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_load_certificate_buffer(
    const unsigned char* buf, int sz, int format);

#ifdef WOLFSSL_SEP
/*!
    \ingroup wolfssl

    \brief This function copies the device type from the x509 structure to the buffer.
    
    \return pointer returns a byte pointer holding the device type from the x509 structure.
    \return NULL returned if the buffer size is NULL.
    
    \param x509 pointer to a WOLFSSL_X509 structure, created with WOLFSSL_X509_new().
    \param in a pointer to a byte type that will hold the device type (the buffer).
    \param inOutSz the minimum of either the parameter inOutSz or the deviceTypeSz member of the x509 structure.
    
    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    byte* in;
    int* inOutSz;
    ...
    byte* deviceType = wolfSSL_X509_get_device_type(x509, in, inOutSz);

    if(!deviceType){
	    // Failure case, NULL was returned.
    }
    \endcode
    
    \sa wolfSSL_X509_get_hw_type
    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_d2i
*/
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_device_type(WOLFSSL_X509*, unsigned char*, int*);
/*!
    \ingroup wolfssl

    \brief The function copies the hwType member of the WOLFSSL_X509 structure to the buffer.
    
    \return byte The function returns a byte type of the data previously held in the hwType member of the WOLFSSL_X509 structure.
    \return NULL returned if  inOutSz is NULL.
    
    \param x509 a pointer to a WOLFSSL_X509 structure containing certificate information.
    \param in pointer to type byte that represents the buffer.
    \param inOutSz pointer to type int that represents the size of the buffer.
    
    _Example_
    \code
    WOLFSSL_X509* x509;  // X509 certificate
    byte* in;  // initialize the buffer
    int* inOutSz;  // holds the size of the buffer
    ...
    byte* hwType = wolfSSL_X509_get_hw_type(x509, in, inOutSz);

    if(hwType == NULL){
	    // Failure case function returned NULL.
    }
    \endcode
    
    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_get_device_type
*/
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_type(WOLFSSL_X509*, unsigned char*, int*);
/*!
    \ingroup wolfssl

    \brief This function returns the hwSerialNum member of the x509 object.
    
    \return pointer the function returns a byte pointer to the in buffer that will contain the serial number loaded from the x509 object. 
    
    \param x509 pointer to a WOLFSSL_X509 structure containing certificate information.
    \param in a pointer to the buffer that will be copied to.
    \param inOutSz a pointer to the size of the buffer.
    
    _Example_
    \code
    char* serial;
    byte* in;
    int* inOutSz;
    WOLFSSL_X509 x509;  
    ...
    serial = wolfSSL_X509_get_hw_serial_number(x509, in, inOutSz);

    if(serial == NULL || serial <= 0){
    	// Failure case
    }
    \endcode
    
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509*, unsigned char*, int*);
#endif

/* connect enough to get peer cert */
/*!
    \ingroup wolfssl

    \brief This function is called on the client side and initiates an SSL/TLS handshake with a server only long enough to get the peer’s certificate chain.  When this function is called, the underlying communication channel has already been set up. wolfSSL_connect_cert() works with both blocking and non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_connect_cert() will return when the underlying I/O could not satisfy the needs of wolfSSL_connect_cert() to continue the handshake.  In this case, a call to wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call to wolfSSL_connect_cert() when the underlying I/O is ready and wolfSSL will pick up where it left off. When using a non-blocking socket, nothing needs to be done, but select() can be used to check for the required condition. If the underlying I/O is blocking, wolfSSL_connect_cert() will only return once the peer’s certificate chain has been received.
    
    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE will be returned if the SSL session parameter is NULL.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a more detailed error code, call wolfSSL_get_error().
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    ret = wolfSSL_connect_cert(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode
    
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept
*/
WOLFSSL_API int  wolfSSL_connect_cert(WOLFSSL* ssl);



/* PKCS12 compatibility */
typedef struct WC_PKCS12 WC_PKCS12;
/*!
    \ingroup openSSL
    
    \brief wolfSSL_d2i_PKCS12_bio (d2i_PKCS12_bio) copies in the PKCS12 information from WOLFSSL_BIO to the structure WC_PKCS12. The information is divided up in the structure as a list of Content Infos along with a structure to hold optional MAC information. After the information has been divided into chunks (but not decrypted) in the structure WC_PKCS12, it can then be parsed and decrypted by calling.
    
    \return WC_PKCS12 pointer to a WC_PKCS12 structure. 
    \return Failure If function failed it will return NULL.

    \param bio WOLFSSL_BIO structure to read PKCS12 buffer from.
    \param pkcs12 WC_PKCS12 structure pointer for new PKCS12 structure created. Can be NULL
    
    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode
    
    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WOLFSSL_API WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12** pkcs12);
/*!
    \ingroup openSSL
    
    \brief PKCS12 can be enabled with adding –enable-opensslextra to the configure command. It can use triple DES and RC4 for decryption so would recommend also enabling these features when enabling opensslextra (--enable-des3 –enable-arc4). wolfSSL does not currently support RC2 so decryption with RC2 is currently not available. This may be noticeable with default encryption schemes used by OpenSSL command line to create .p12 files. wolfSSL_PKCS12_parse (PKCS12_parse). The first thing this function does is check the MAC is correct if present. If the MAC fails then the function returns and does not try to decrypt any of the stored Content Infos. This function then parses through each Content Info looking for a bag type, if the bag type is known it is decrypted as needed and either stored in the list of certificates being built or as a key found. After parsing through all bags the key found is then compared with the certificate list until a matching pair is found. This matching pair is then returned as the key and certificate, optionally the certificate list found is returned as a STACK_OF certificates. At the moment a CRL, Secret or SafeContents bag will be skipped over and not parsed. It can be seen if these or other “Unknown” bags are skipped over by viewing the debug print out. Additional attributes such as friendly name are skipped over when parsing a PKCS12 file.

    \return SSL_SUCCESS On successfully parsing PKCS12.
    \return SSL_FAILURE If an error case was encountered.
    
    \param pkcs12 WC_PKCS12 structure to parse.
    \param paswd password for decrypting PKCS12.
    \param pkey structure to hold private key decoded from PKCS12.
    \param cert structure to hold certificate decoded from PKCS12.
    \param stack optional stack of extra certificates.
    
    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode
    
    \sa wolfSSL_d2i_PKCS12_bio
    \sa wc_PKCS12_free
*/
WOLFSSL_API int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
     WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert, STACK_OF(WOLFSSL_X509)** ca);
WOLFSSL_API void wolfSSL_PKCS12_PBE_add(void);



#ifndef NO_DH
/* server Diffie-Hellman parameters */
/*!
    \ingroup wolfssl

    \brief Server Diffie-Hellman Ephemeral parameters setting.  This function sets up the group parameters to be used if the server negotiates a cipher suite that uses DHE.
    
    \return SSL_SUCCESS upon success.
    \return MEMORY_ERROR will be returned if a memory error was encountered.
    \return SIDE_ERROR will be returned if this function is called on an SSL client instead of an SSL server.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param p Diffie-Hellman prime number parameter.
    \param pSz size of p.
    \param g Diffie-Hellman “generator” parameter.
    \param gSz size of g.
    
    _Example_
    \code
    WOLFSSL* ssl;
    static unsigned char p[] = {...};
    static unsigned char g[] = {...};
    ...
    wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
    \endcode
    
    \sa SSL_accept
*/
WOLFSSL_API int  wolfSSL_SetTmpDH(WOLFSSL*, const unsigned char* p, int pSz,
                                const unsigned char* g, int gSz);
/*!
    \ingroup wolfssl

    \brief The function calls the wolfSSL_SetTMpDH_buffer_wrapper, which is a wrapper for Diffie-Hellman parameters.
    
    \return SSL_SUCCESS on successful execution.
    \return SSL_BAD_FILETYPE if the file type is not PEM and is not ASN.1. It will also be returned if the wc_DhParamsLoad does not return normally.
    \return SSL_NO_PEM_HEADER returns from PemToDer if there is not a PEM header.
    \return SSL_BAD_FILE returned if there is a file error in PemToDer.
    \return SSL_FATAL_ERROR returned from PemToDer if there was a copy error.
    \return MEMORY_E - if there was a memory allocation error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if there was otherwise a NULL argument passed to a subroutine.
    \return DH_KEY_SIZE_E is returned if their is a key size error in wolfSSL_SetTmpDH() or in wolfSSL_CTX_SetTmpDH().
    \return SIDE_ERROR returned if it is not the server side in wolfSSL_SetTmpDH.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf allocated buffer passed in from wolfSSL_SetTMpDH_file_wrapper.
    \param sz a long int that holds the size of the file (fname within wolfSSL_SetTmpDH_file_wrapper).
    \param format an integer type passed through from wolfSSL_SetTmpDH_file_wrapper() that is a representation of the certificate format.
    
    _Example_
    \code
    Static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    long sz = 0;
    byte* myBuffer = staticBuffer[FILE_BUFFER_SIZE];
    …
    if(ssl)
    ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    \endcode
    
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wc_DhParamsLoad
    \sa wolfSSL_SetTmpDH
    \sa PemToDer
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
WOLFSSL_API int  wolfSSL_SetTmpDH_buffer(WOLFSSL*, const unsigned char* b, long sz,
                                       int format);
#ifndef NO_FILESYSTEM
/*!
    \ingroup wolfssl

    \brief This function calls wolfSSL_SetTmpDH_file_wrapper to set server Diffie-Hellman parameters.
    
    \return SSL_SUCCESS returned on successful completion of this function and its subroutines.
    \return MEMORY_E returned if a memory allocation failed in this function or a subroutine.
    \return SIDE_ERROR if the side member of the Options structure found in the WOLFSSL struct is not the server side.
    \return SSL_BAD_FILETYPE returns if the certificate fails a set of checks.
    \return BAD_FUNC_ARG returns if an argument value is NULL that is not permitted such as, the WOLFSSL structure.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param fname a constant char pointer holding the certificate.
    \param format an integer type that holds the format of the certification.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* dhParam;
    …
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM));
    \endcode
    
    \sa wolfSSL_CTX_SetTmpDH_file
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
*/
    WOLFSSL_API int  wolfSSL_SetTmpDH_file(WOLFSSL*, const char* f, int format);
#endif

/* server ctx Diffie-Hellman parameters */
/*!
    \ingroup wolfssl

    \brief Sets the parameters for the server CTX Diffie-Hellman.
    
    \return SSL_SUCCESS returned if the function and all subroutines return without error.
    \return BAD_FUNC_ARG returned if the CTX, p or g parameters are NULL.
    \return DH_KEY_SIZE_E returned if the minDhKeySz member of the WOLFSSL_CTX	struct is not the correct size.
    \return MEMORY_E returned if the allocation of memory failed in this function or a subroutine.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param p a constant unsigned char pointer loaded into the buffer member of the serverDH_P struct.
    \param pSz an int type representing the size of p, initialized to MAX_DH_SIZE.
    \param g a constant unsigned char pointer loaded into the buffer member of the serverDH_G struct.
    \param gSz an int type representing the size of g, initialized ot MAX_DH_SIZE.
    
    _Exmaple_
    \code
    WOLFSSL_CTX* ctx =  WOLFSSL_CTX_new( protocol );
    byte* p;
    byte* g;
    word32 pSz = (word32)sizeof(p)/sizeof(byte);
    word32 gSz = (word32)sizeof(g)/sizeof(byte);
    …
    int ret =  wolfSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);

    if(ret != SSL_SUCCESS){
    	// Failure case
    }
    \endcode
    
    \sa wolfSSL_SetTmpDH
    \sa wc_DhParamsLoad
*/
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX*, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);
/*!
    \ingroup wolfssl

    \brief A wrapper function that calls wolfSSL_SetTmpDH_buffer_wrapper
    
    \return 0 returned for a successful execution.
    \return BAD_FUNC_ARG returned if the ctx or buf parameters are NULL.
    \return MEMORY_E if there is a memory allocation error.
    \return SSL_BAD_FILETYPE returned if format is not correct.
    
    \param ctx a pointer to a WOLFSSL structure, created using wolfSSL_CTX_new().
    \param buf a pointer to a constant unsigned char type that is allocated as the buffer and passed through to wolfSSL_SetTmpDH_buffer_wrapper.
    \param sz a long integer type that is derived from the fname parameter in wolfSSL_SetTmpDH_file_wrapper().
    \param format an integer type passed through from wolfSSL_SetTmpDH_file_wrapper().
    
    _Example_
    \code
    static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    #ifdef WOLFSSL_SMALL_STACK
    byte staticBuffer[1]; // force heap usage 
    #else
    byte* staticBuffer;
    long sz = 0;
    …
    if(ssl){
    	ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    } else {
    ret = wolfSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }
    \endcode
    
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTMpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_CTX_SetTmpDH_file
*/
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX*, const unsigned char* b,
                                           long sz, int format);

#ifndef NO_FILESYSTEM
/*!
    \ingroup wolfssl

    \brief The function calls wolfSSL_SetTmpDH_file_wrapper to set the server Diffie-Hellman parameters.
    
    \return SSL_SUCCESS returned if the wolfSSL_SetTmpDH_file_wrapper or any of its subroutines return successfully.
    \return MEMORY_E returned if an allocation of dynamic memory fails in a subroutine.
    \return BAD_FUNC_ARG returned if the ctx or fname parameters are NULL or if a subroutine is passed a NULL argument.
    \return SSL_BAD_FILE returned if the certificate file is unable to open or if the a set of checks on the file fail from wolfSSL_SetTmpDH_file_wrapper.
    \return SSL_BAD_FILETYPE returned if teh format is not PEM or ASN.1 from wolfSSL_SetTmpDH_buffer_wrapper().
    \return DH_KEY_SIZE_E returned from wolfSSL_SetTmpDH() if the ctx minDhKeySz member exceeds maximum size allowed for DH.
    \return SIDE_ERROR returned in wolfSSL_SetTmpDH() if the side is not the server end.
    \return SSL_NO_PEM_HEADER returned from PemToDer if there is no PEM header.
    \return SSL_FATAL_ERROR returned from PemToDer if there is a memory copy failure.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param fname a constant character pointer to a certificate file.
    \param format an integer type passed through from wolfSSL_SetTmpDH_file_wrapper() that is a representation of the certificate format.
    
    _Example_
    \code
    #define dhParam     “certs/dh2048.pem”
    #DEFINE aSSERTiNTne(x, y)     AssertInt(x, y, !=, ==)
    WOLFSSL_CTX* ctx;
    …
    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()))
    …
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(NULL, dhParam, 
    SSL_FILETYPE_PEM));
    \endcode
    
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa AllocDer
    \sa PemToDer
*/
    WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX*, const char* f,
                                             int format);
#endif

/*!
    \ingroup wolfssl

    \brief This function sets the minimum size of the Diffie Hellman key size by accessing the minDhKeySz member in the WOLFSSL_CTX structure.
    
    \return SSL_SUCCESS returned if the function completes successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if the keySz is greater than 16,000 or not divisible by 8.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz a word16 type used to set the minimum DH key size. The WOLFSSL_CTX struct holds this information in the minDhKeySz member.
    
    _Example_
    \code
    public static int CTX_SetMinDhKey_Sz(IntPtr ctx, short minDhKey){
    …
    return wolfSSL_CTX_SetMinDhKey_Sz(local_ctx, minDhKey);
    \endcode
    
    \sa wolfSSL_SetMinDhKey_Sz
    \sa CTX_SetMinDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
    \sa wolfSSL_CTX_SetTMpDH_file
*/
WOLFSSL_API int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX*, unsigned short);
/*!
    \ingroup wolfssl

    \brief Sets the minimum size for a Diffie-Hellman key in the WOLFSSL structure in bytes.
    
    \return SSL_SUCCESS the minimum size was successfully set.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL or the keySz parameter was greater than the allowable size or not divisible by 8.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz a word16 type representing the bit size of the minimum DH key.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz;
    ...
    if(wolfSSL_SetMinDhKey(ssl, keySz) != SSL_SUCCESS){
	    // Failed to set.
    }
    \endcode
    
    \sa wolfSSL_GetDhKey_Sz
*/
WOLFSSL_API int wolfSSL_SetMinDhKey_Sz(WOLFSSL*, unsigned short);
/*!
    \ingroup wolfssl

    \brief Returns the value of dhKeySz that is a member of the options structure. This value represents the Diffie-Hellman key size in bytes.
    
    \return dhKeySz returns the value held in ssl->options.dhKeySz which is an integer value.
    \return BAD_FUNC_ARG returns if the WOLFSSL struct is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int dhKeySz;
    ...
    dhKeySz = wolfSSL_GetDhKey_Sz(ssl);

    if(dhKeySz == BAD_FUNC_ARG || dhKeySz <= 0){
    	// Failure case
    } else {
    	// dhKeySz holds the size of the key.
    }
    \endcode
    
    \sa wolfSSL_SetMinDhKey_sz
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
WOLFSSL_API int wolfSSL_GetDhKey_Sz(WOLFSSL*);
#endif /* NO_DH */

#ifndef NO_RSA
/*!
    \ingroup wolfssl

    \brief Sets the minimum RSA key size in both the WOLFSSL_CTX structure and the WOLFSSL_CERT_MANAGER structure.
    
    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the ctx structure is NULL or the keySz is less than zero or not divisible by 8.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param keySz a short integer type stored in minRsaKeySz in the ctx structure and the cm structure converted to bytes.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = SSL_CTX_new(method);
    (void)minDhKeyBits;
    ourCert = myoptarg;
    …
    minDhKeyBits = atoi(myoptarg);
    …
    if(wolfSSL_CTX_SetMinRsaKey_Sz(ctx, minRsaKeyBits) != SSL_SUCCESS){
    …
    \endcode
    
    \sa wolfSSL_SetMinRsaKey_Sz
*/
WOLFSSL_API int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX*, short);
/*!
    \ingroup wolfssl

    \brief Sets the minimum allowable key size in bytes for RSA located in the WOLFSSL structure.
    
    \return SSL_SUCCESS the minimum was set successfully.
    \return BAD_FUNC_ARG returned if the ssl structure is NULL or if the ksySz is less than zero or not divisible by 8.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz a short integer value representing the the minimum key in bits.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    short keySz;
    …

    int isSet =  wolfSSL_SetMinRsaKey_Sz(ssl, keySz);
    if(isSet != SSL_SUCCESS){
	    Failed to set.
    }
    \endcode
    
    \sa wolfSSL_CTX_SetMinRsaKey_Sz
*/
WOLFSSL_API int wolfSSL_SetMinRsaKey_Sz(WOLFSSL*, short);
#endif /* NO_RSA */

#ifdef HAVE_ECC
/*!
    \ingroup wolfssl

    \brief Sets the minimum size in bytes for the ECC key in the WOLF_CTX structure and the WOLFSSL_CERT_MANAGER structure.
    
    \return SSL_SUCCESS returned for a successful execution and the minEccKeySz member is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if the keySz is negative or not divisible by 8.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param keySz a short integer type that represents the minimum ECC key size in bits.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    short keySz; // minimum key size
    …
    if(wolfSSL_CTX_SetMinEccKey(ctx, keySz) != SSL_SUCCESS){
	    // Failed to set min key size
    }
    \endcode
    
    \sa wolfSSL_SetMinEccKey_Sz
*/
WOLFSSL_API int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX*, short);
/*!
    \ingroup wolfssl

    \brief Sets the value of the minEccKeySz member of the options structure. The options struct is a member of the WOLFSSL structure and is accessed through the ssl parameter.
    
    \return SSL_SUCCESS if the function successfully set the minEccKeySz member of the options structure.
    \return BAD_FUNC_ARG if the WOLFSSL_CTX structure is NULL or if the key size (keySz) is less than 0 (zero) or not divisible by 8.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz value used to set the minimum ECC key size. Sets value in the options structure.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx); // New session
    short keySz = 999; // should be set to min key size allowable
    ...
    if(wolfSSL_SetMinEccKey_Sz(ssl, keySz) != SSL_SUCCESS){
	    // Failure case.
    }
    \endcode
    
    \sa wolfSSL_CTX_SetMinEccKey_Sz
    \sa wolfSSL_CTX_SetMinRsaKey_Sz
    \sa wolfSSL_SetMinRsaKey_Sz
*/
WOLFSSL_API int wolfSSL_SetMinEccKey_Sz(WOLFSSL*, short);
#endif /* NO_RSA */

WOLFSSL_API int  wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL*, unsigned short);
WOLFSSL_API int  wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX*, unsigned short);

/* keyblock size in bytes or -1 */
/* need to call wolfSSL_KeepArrays before handshake to save keys */
WOLFSSL_API int wolfSSL_get_keyblock_size(WOLFSSL*);
WOLFSSL_API int wolfSSL_get_keys(WOLFSSL*,unsigned char** ms, unsigned int* msLen,
                                       unsigned char** sr, unsigned int* srLen,
                                       unsigned char** cr, unsigned int* crLen);

/* Computes EAP-TLS and EAP-TTLS keying material from the master_secret. */
/*!
    \ingroup wolfssl

    \brief This function is used by EAP_TLS and EAP-TTLS to derive keying material from the master secret.
    
    \return BUFFER_E returned if the actual size of the buffer exceeds the maximum size allowable.
    \return MEMORY_E returned if there is an error with memory allocation.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param msk a void pointer variable that will hold the result of the p_hash function.
    \param len an unsigned integer that represents the length of the msk variable.
    \param label a constant char pointer that is copied from in PRF().
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);;
    void* msk;
    unsigned int len;
    const char* label;
    …
    return wolfSSL_make_eap_keys(ssl, msk, len, label);
    \endcode
    
    \sa PRF
    \sa doPRF
    \sa p_hash
    \sa wc_HmacFinal
    \sa wc_HmacUpdate
*/
WOLFSSL_API int wolfSSL_make_eap_keys(WOLFSSL*, void* key, unsigned int len,
                                                             const char* label);


#ifndef _WIN32
    #ifndef NO_WRITEV
        #ifdef __PPU
            #include <sys/types.h>
            #include <sys/socket.h>
        #elif !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_IAR_ARM) && \
              !defined(WOLFSSL_PICOTCP) && !defined(WOLFSSL_ROWLEY_ARM) && \
              !defined(WOLFSSL_EMBOS) && !defined(WOLFSSL_FROSTED)
            #include <sys/uio.h>
        #endif
        /* allow writev style writing */
/*!
    \ingroup wolfssl

    \brief Simulates writev semantics but doesn’t actually do block at a time because of SSL_write() behavior and because front adds may be small.  Makes porting into software that uses writev easier.
    
    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for the specific error code.
    \return MEMORY_ERROR will be returned if a memory error was encountered.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and the application needs to call wolfSSL_write() again.  Use wolfSSL_get_error() to get a specific error code.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param iov array of I/O vectors to write
    \param iovcnt number of vectors in iov array.
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    char *bufA = “hello\n”;
    char *bufB = “hello world\n”;
    int iovcnt;
    struct iovec iov[2];

    iov[0].iov_base = buffA;
    iov[0].iov_len = strlen(buffA);
    iov[1].iov_base = buffB;
    iov[1].iov_len = strlen(buffB);
    iovcnt = 2;
    ...
    ret = wolfSSL_writev(ssl, iov, iovcnt);
    // wrote “ret” bytes, or error if <= 0.
    \endcode
    
    \sa wolfSSL_write
*/
        WOLFSSL_API int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);
    #endif
#endif


#ifndef NO_CERTS
    /* SSL_CTX versions */
/*!
    \ingroup wolfssl

    \brief This function unloads the CA signer list and frees the whole signer table.
    
    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or there are otherwise unpermitted argument values passed in a subroutine.
    \return BAD_MUTEX_E returned if there was a mutex error. The LockMutex() did not return 0.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method(); 
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    if(!wolfSSL_CTX_UnloadCAs(ctx)){
    	// The function did not unload CAs
    }
    \endcode
    
    \sa wolfSSL_CertManagerUnloadCAs
    \sa LockMutex
    \sa FreeSignerTable
    \sa UnlockMutex
*/
    WOLFSSL_API int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX*);
#ifdef WOLFSSL_TRUST_PEER_CERT
/*!
    \ingroup wolfssl

    \brief This function is used to unload all previously loaded trusted peer certificates. Feature is enabled by defining the macro WOLFSSL_TRUST_PEER_CERT.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if ctx is NULL.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_Unload_trust_peers(ctx);
    if (ret != SSL_SUCCESS) {
        // error unloading trusted peer certs
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_trust_peer_cert
*/
    WOLFSSL_API int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX*);
/*!
    \ingroup wolfssl

    \brief This function loads a certificate to use for verifying a peer when performing a TLS/SSL handshake. The peer certificate sent during the handshake is compared by using the SKID when available and the signature. If these two things do not match then any loaded CAs are used. Is the same functionality as wolfSSL_CTX_trust_peer_cert except is from a buffer instead of a file. Feature is enabled by defining the macro WOLFSSL_TRUST_PEER_CERT Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and type are invalid.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param buffer pointer to the buffer containing certificates.
    \param sz length of the buffer input.
    \param type type of certificate being loaded i.e. SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...

    ret = wolfSSL_CTX_trust_peer_buffer(ctx, bufferPtr, bufferSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    // error loading trusted peer cert
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_cert
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
    WOLFSSL_API int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
#endif
/*!
    \ingroup wolfssl

    \brief This function loads a CA certificate buffer into the WOLFSSL Context.  It behaves like the non-buffered version, only differing in its ability to be called with a buffer as input instead of a file.  The buffer is provided by the in argument of size sz.  format specifies the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  More than one CA certificate may be loaded per buffer as long as the format is in PEM.  Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than the receiving buffer.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in pointer to the CA certificate buffer.
    \param sz size of the input CA certificate buffer, in.
    \param format format of the buffer certificate, either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    ...
    
    ret = wolfSSL_CTX_load_verify_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs from buffer
    }
    ...
    \endcode  
    
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
    WOLFSSL_API int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
/*!
    \ingroup wolfssl

    \brief This function loads a certificate buffer into the WOLFSSL Context.  It behaves like the non-buffered version, only differing in its ability to be called with a buffer as input instead of a file.  The buffer is provided by the in argument of size sz.  format specifies the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the certificate to be loaded.
    \param sz the size of the input buffer.
    \param format the format of the certificate located in the input buffer (in).  Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    ...
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading certificate from buffer
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
    WOLFSSL_API int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
/*!
    \ingroup wolfssl

    \brief This function loads a private key buffer into the SSL Context.  It behaves like the non-buffered version, only differing in its ability to be called with a buffer as input instead of a file.  The buffer is provided by the in argument of size sz.  format specifies the format type of the buffer; SSL_FILETYPE_ASN1or SSL_FILETYPE_PEM.  Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return NO_PASSWORD will be returned if the key file is encrypted but no password is provided.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the private key to be loaded.
    \param sz the size of the input buffer.
    \param format the format of the private key located in the input buffer (in).  Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte keyBuff[...];
    ...
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, keyBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading private key from buffer
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
/*!
    \ingroup wolfssl

    \brief This function loads a certificate chain buffer into the WOLFSSL Context.  It behaves like the non-buffered version, only differing in its ability to be called with a buffer as input instead of a file.  The buffer is provided by the in argument of size sz.  The buffer must be in PEM format and start with the subject’s certificate, ending with the root certificate. Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than the receiving buffer.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the PEM-formatted certificate chain to be loaded.
    \param sz the size of the input buffer.
    
    _Example_
    \code
    int ret = 0;
    int sz = 0;
    WOLFSSL_CTX* ctx;
    byte certChainBuff[...];
    ...
    ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx, certChainBuff, sz);
    if (ret != SSL_SUCCESS) {
    	// error loading certificate chain from buffer
    }
    ...
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
    WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX*,
                                                    const unsigned char*, long);

    /* SSL versions */
/*!
    \ingroup wolfssl

    \brief This function loads a certificate buffer into the WOLFSSL object.  It behaves like the non-buffered version, only differing in its ability to be called with a buffer as input instead of a file.  The buffer is provided by the in argument of size sz.  format specifies the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing certificate to load.
    \param sz size of the certificate located in buffer.
    \param format format of the certificate to be loaded. Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int buffSz;
    int ret;
    byte certBuff[...];
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_use_certificate_buffer(ssl, certBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate from buffer
    }
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
    WOLFSSL_API int wolfSSL_use_certificate_buffer(WOLFSSL*, const unsigned char*,
                                               long, int);
/*!
    \ingroup wolfssl

    \brief This function loads a private key buffer into the WOLFSSL object.  It behaves like the non-buffered version, only differing in its ability to be called with a buffer as input instead of a file.  The buffer is provided by the in argument of size sz.  format specifies the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please see the examples for proper usage.
    
    \return SSL_SUCCESS upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return NO_PASSWORD will be returned if the key file is encrypted but no password is provided.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing private key to load.
    \param sz size of the private key located in buffer.
    \param format format of the private key to be loaded.  Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int buffSz;
    int ret;
    byte keyBuff[...];
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_use_PrivateKey_buffer(ssl, keyBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load private key from buffer
    }
    \endcode
    
    \sa wolfSSL_use_PrivateKey
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
    WOLFSSL_API int wolfSSL_use_PrivateKey_buffer(WOLFSSL*, const unsigned char*,
                                               long, int);
    WOLFSSL_API int wolfSSL_use_certificate_chain_buffer_format(WOLFSSL*,
                                               const unsigned char*, long, int);
/*!
    \ingroup wolfssl

    \brief This function loads a certificate chain buffer into the WOLFSSL object.  It behaves like the non-buffered version, only differing in its ability to be called with a buffer as input instead of a file.  The buffer is provided by the in argument of size sz.  The buffer must be in PEM format and start with the subject’s certificate, ending with the root certificate. Please see the examples for proper usage.
    
    \return SSL_SUCCES upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than the receiving buffer.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing certificate to load.
    \param sz size of the certificate located in buffer.
    
    _Example_
    \code
    int buffSz;
    int ret;
    byte certChainBuff[...];
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_use_certificate_chain_buffer(ssl, certChainBuff, buffSz);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate chain from buffer
    }
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_NTRUPrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
*/
    WOLFSSL_API int wolfSSL_use_certificate_chain_buffer(WOLFSSL*,
                                               const unsigned char*, long);
/*!
    \ingroup wolfssl

    \brief This function unloads any certificates or keys that SSL owns.
    
    \return SSL_SUCCESS - returned if the function executed successfully.
    \return BAD_FUNC_ARG - returned if the WOLFSSL object is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    int unloadKeys = wolfSSL_UnloadCertsKeys(ssl);
    if(unloadKeys != SSL_SUCCESS){
	    // Failure case.
    }
    
    \sa wolfSSL_CTX_UnloadCAs
*/
    WOLFSSL_API int wolfSSL_UnloadCertsKeys(WOLFSSL*);

    #if defined(OPENSSL_EXTRA) && defined(KEEP_OUR_CERT)
        WOLFSSL_API WOLFSSL_X509* wolfSSL_get_certificate(WOLFSSL* ssl);
    #endif
#endif

/*!
    \ingroup wolfssl

    \brief This function turns on grouping of handshake messages where possible.
    
    \return SSL_SUCCESS will be returned upon success.
    \return BAD_FUNC_ARG will be returned if the input context is null.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_group_messages(ctx);
    if (ret != SSL_SUCCESS) {
	    // failed to set handshake message grouping
    }
    \endcode
    
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX*);
/*!
    \ingroup wolfssl

    \brief This function turns on grouping of handshake messages where possible.
    
    \return SSL_SUCCESS will be returned upon success.
    \return BAD_FUNC_ARG will be returned if the input context is null.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_group_messages(ssl);
    if (ret != SSL_SUCCESS) {
	// failed to set handshake message grouping
    }
    \endcode
    
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_new
*/
WOLFSSL_API int wolfSSL_set_group_messages(WOLFSSL*);


#ifdef HAVE_FUZZER
enum fuzzer_type {
    FUZZ_HMAC      = 0,
    FUZZ_ENCRYPT   = 1,
    FUZZ_SIGNATURE = 2,
    FUZZ_HASH      = 3,
    FUZZ_HEAD      = 4
};

typedef int (*CallbackFuzzer)(WOLFSSL* ssl, const unsigned char* buf, int sz,
        int type, void* fuzzCtx);

/*!
    \ingroup wolfssl

    \brief This function sets the fuzzer callback.
    
    \return none No returns.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cbf a CallbackFuzzer type that is a function pointer of the form: int (*CallbackFuzzer)(WOLFSSL* ssl, const unsigned char* buf, int sz, int type, void* fuzzCtx);
    \param fCtx a void pointer type that will be set to the fuzzerCtx member of the WOLFSSL structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* fCtx;

    int callbackFuzzerCB(WOLFSSL* ssl, const unsigned char* buf, int sz, 
				int type, void* fuzzCtx){
    // function definition
    }
    …
    wolfSSL_SetFuzzerCb(ssl, callbackFuzzerCB, fCtx);
    \endcode
    
    \sa CallbackFuzzer
*/
WOLFSSL_API void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx);
#endif


/*!
    \ingroup wolfssl

    \brief This function sets a new dtls cookie secret.
    
    \return 0 returned if the function executed without an error.
    \return BAD_FUNC_ARG returned if there was an argument passed to the function with an unacceptable value.
    \return COOKIE_SECRET_SZ returned if the secret size is 0.
    \return MEMORY_ERROR returned if there was a problem allocating memory for a new cookie secret.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param secret a constant byte pointer representing the secret buffer.
    \param secretSz the size of the buffer.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const* byte secret;
    word32 secretSz; // size of secret
    …
    if(!wolfSSL_DTLS_SetCookieSecret(ssl, secret, secretSz)){
    	// Code block for failure to set DTLS cookie secret
    } else {
    	// Success! Cookie secret is set.
    }
    \endcode
    
    \sa ForceZero
    \sa wc_RNG_GenerateBlock
    \sa XMEMCPY
*/
WOLFSSL_API int   wolfSSL_DTLS_SetCookieSecret(WOLFSSL*,
                                               const unsigned char*,
                                               unsigned int);


/* I/O Callback default errors */
enum IOerrors {
    WOLFSSL_CBIO_ERR_GENERAL    = -1,     /* general unexpected err */
    WOLFSSL_CBIO_ERR_WANT_READ  = -2,     /* need to call read  again */
    WOLFSSL_CBIO_ERR_WANT_WRITE = -2,     /* need to call write again */
    WOLFSSL_CBIO_ERR_CONN_RST   = -3,     /* connection reset */
    WOLFSSL_CBIO_ERR_ISR        = -4,     /* interrupt */
    WOLFSSL_CBIO_ERR_CONN_CLOSE = -5,     /* connection closed or epipe */
    WOLFSSL_CBIO_ERR_TIMEOUT    = -6      /* socket timeout */
};


/* CA cache callbacks */
enum {
    WOLFSSL_SSLV3    = 0,
    WOLFSSL_TLSV1    = 1,
    WOLFSSL_TLSV1_1  = 2,
    WOLFSSL_TLSV1_2  = 3,
    WOLFSSL_USER_CA  = 1,          /* user added as trusted */
    WOLFSSL_CHAIN_CA = 2           /* added to cache from trusted chain */
};

WOLFSSL_API WC_RNG* wolfSSL_GetRNG(WOLFSSL*);

/*!
    \ingroup wolfssl

    \brief This function sets the minimum downgrade version allowed. Applicable only when the connection allows downgrade using (wolfSSLv23_client_method or wolfSSLv23_server_method).
    
    \return SSL_SUCCESS returned if the function returned without error and the minimum version is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure was NULL or if the minimum version is not supported.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param version an integer representation of the version to be set as the minimum: WOLFSSL_SSLV3 = 0, WOLFSSL_TLSV1 = 1, WOLFSSL_TLSV1_1 = 2 or WOLFSSL_TLSV1_2 = 3.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version; // macrop representation
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
    	// Failed to set min version
    }
    \endcode
    
    \sa SetMinVersionHelper
*/
WOLFSSL_API int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);
/*!
    \ingroup wolfssl

    \brief This function sets the minimum downgrade version allowed. Applicable only when the connection allows downgrade using (wolfSSLv23_client_method or wolfSSLv23_server_method).
    
    \return SSL_SUCCESS returned if this function and its subroutine executes without error.
    \return BAD_FUNC_ARG returned if the SSL object is NULL.  In the subroutine this error is thrown if there is not a good version match.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param version an integer representation of the version to be set as the minimum: WOLFSSL_SSLV3 = 0, WOLFSSL_TLSV1 = 1, WOLFSSL_TLSV1_1 = 2 or WOLFSSL_TLSV1_2 = 3.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol method);
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version;  macro representation 
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
	    Failed to set min version
    }
    \endcode
    
    \sa SetMinVersionHelper
*/
WOLFSSL_API int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version);
/*!
    \ingroup wolfssl

    \brief This function returns the size of the WOLFSSL object and will be dependent on build options and settings.  If SHOW_SIZES has been defined when building wolfSSL, this function will also print the sizes of individual objects within the WOLFSSL object (Suites, Ciphers, etc.) to stdout.
    
    \return size This function returns the size of the WOLFSSL object.
    
    \param none No parameters.
    
    _Example_
    \code
    int size = 0;
    size = wolfSSL_GetObjectSize();
    printf(“sizeof(WOLFSSL) = %d\n”, size);
    \endcode
    
    \sa wolfSSL_new
*/
WOLFSSL_API int wolfSSL_GetObjectSize(void);  /* object size based on build */
WOLFSSL_API int wolfSSL_CTX_GetObjectSize(void); 
WOLFSSL_API int wolfSSL_METHOD_GetObjectSize(void);
/*!
    \ingroup wolfssl

    \brief Returns the record layer size of the plaintext input. This is helpful when an application wants to know how many bytes will be sent across the Transport layer, given a specified plaintext input size. This function must be called after the SSL/TLS handshake has been completed.
    
    \return size Upon success, the requested size will be returned
    \return INPUT_SIZE_E will be returned if the input size is greater than the maximum TLS fragment size (see wolfSSL_GetMaxOutputSize())
    \return BAD_FUNC_ARG will be returned upon invalid function argument, or if the SSL/TLS handshake has not been completed yet
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param inSz size of plaintext data.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetMaxOutputSize
*/
WOLFSSL_API int wolfSSL_GetOutputSize(WOLFSSL*, int);
/*!
    \ingroup wolfssl

    \brief Returns the maximum record layer size for plaintext data.  This will correspond to either the maximum SSL/TLS record size as specified by the protocol standard, the maximum TLS fragment size as set by the TLS Max Fragment Length extension. This function is helpful when the application has called wolfSSL_GetOutputSize() and received a INPUT_SIZE_E error. This function must be called after the SSL/TLS handshake has been completed.
    
    \return size Upon success, the maximum output size will be returned
    \return BAD_FUNC_ARG will be returned upon invalid function argument, or if the SSL/TLS handshake has not been completed yet.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetOutputSize
*/
WOLFSSL_API int wolfSSL_GetMaxOutputSize(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function sets the SSL/TLS protocol version for the specified SSL session (WOLFSSL object) using the version as specified by version. This will override the protocol setting for the SSL session (ssl) - originally defined and set by the SSL context (wolfSSL_CTX_new()) method type.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if the input SSL object is NULL or an incorrect protocol version is given for version.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param version SSL/TLS protocol version.  Possible values include WOLFSSL_SSLV3, WOLFSSL_TLSV1, WOLFSSL_TLSV1_1, WOLFSSL_TLSV1_2.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_SetVersion(ssl, WOLFSSL_TLSV1);
    if (ret != SSL_SUCCESS) {
        // failed to set SSL session protocol version
    }
    \endcode
    
    \sa wolfSSL_CTX_new
*/
WOLFSSL_API int wolfSSL_SetVersion(WOLFSSL* ssl, int version);
/*!
    \ingroup wolfssl

    \brief Converts a key in PEM format to DER format.
    
    \return int the function returns the number of bytes written to the buffer on successful execution.
    \return int negative int returned indicating an error.
    
    \param pem a pointer to the PEM encoded certificate.
    \param pemSz the size of the PEM buffer (pem)
    \param buff a pointer to the copy of the buffer member of the DerBuffer struct.
    \param buffSz size of the buffer space allocated in the DerBuffer struct.
    \param pass password passed into the function.
    
    _Example_
    \code
    byte* loadBuf;
    long fileSz = 0;
    byte* bufSz;
    static int LoadKeyFile(byte** keyBuf, word32* keyBufSz, const char* keyFile,
					int typeKey, const char* pasword);
    …
    bufSz = wolfSSL_KeyPemToDer(loadBuf, (int)fileSz, saveBuf,
    (int)fileSz, password);

    if(saveBufSz > 0){
    	// Bytes were written to the buffer.
    }
    \endocde
    
    \sa PemToDer
    \sa wolfssl_decrypt_buffer_key
*/
WOLFSSL_API int wolfSSL_KeyPemToDer(const unsigned char*, int,
                                    unsigned char*, int, const char*);
/*!
    \ingroup wolfssl

    \brief This function converts a PEM formatted certificate to DER format. Calls OpenSSL function PemToDer.
    
    \return buffer returns the bytes written to the buffer.
    
    \param pem pointer PEM formatted certificate.
    \param pemSz size of the certificate.
    \param buff buffer to be copied to DER format.
    \param buffSz size of the buffer.
    \param type Certificate file type found in asn_public.h enum CertType.
    
    _Example_
    \code
    const unsigned char* pem;
    int pemSz;
    unsigned char buff[BUFSIZE];
    int buffSz = sizeof(buff)/sizeof(char);
    int type;   
    ...
    if(wolfSSL_CertPemToDer(pem, pemSz, buff, buffSz, type) <= 0) {
	    // There were bytes written to buffer
    }
    \endcode
    
    \sa PemToDer
*/
WOLFSSL_API int wolfSSL_CertPemToDer(const unsigned char*, int,
                                     unsigned char*, int, int);
#if defined(WOLFSSL_CERT_EXT) || defined(WOLFSSL_PUB_PEM_TO_DER)
    #ifndef WOLFSSL_PEMPUBKEY_TODER_DEFINED
        #ifndef NO_FILESYSTEM
            WOLFSSL_API int wolfSSL_PemPubKeyToDer(const char* fileName,
                                                   unsigned char* derBuf, int derSz);
        #endif
/*!
    \ingroup wolfssl

    \brief Converts the PEM format to DER format.
    
    \return int an int type representing the bytes written to buffer.
    \param <0 returned for an error.
    \param BAD_FUNC_ARG returned if the DER length is incorrect or if the pem buff, or buffSz arguments are NULL.
    
    _Example_
    \code
    unsigned char* pem = “pem file”;
    int pemSz = sizeof(pem)/sizeof(char);
    unsigned char* buff;
    int buffSz;
    ...
    if(wolfSSL_PubKeyPemToDer(pem, pemSz, buff, buffSz)!= SSL_SUCCESS){
	    // Conversion was not successful
    }
    \endcode
    
    \sa wolfSSL_PubKeyPemToDer
    \sa wolfSSL_PemPubKeyToDer
    \sa PemToDer
*/
        WOLFSSL_API int wolfSSL_PubKeyPemToDer(const unsigned char*, int,
                                               unsigned char*, int);
        #define WOLFSSL_PEMPUBKEY_TODER_DEFINED
    #endif /* WOLFSSL_PEMPUBKEY_TODER_DEFINED */
#endif /* WOLFSSL_CERT_EXT || WOLFSSL_PUB_PEM_TO_DER*/

typedef void (*CallbackCACache)(unsigned char* der, int sz, int type);
typedef void (*CbMissingCRL)(const char* url);
typedef int  (*CbOCSPIO)(void*, const char*, int,
                                         unsigned char*, int, unsigned char**);
typedef void (*CbOCSPRespFree)(void*,unsigned char*);

#ifdef HAVE_CRL_IO
typedef int  (*CbCrlIO)(WOLFSSL_CRL* crl, const char* url, int urlSz);
#endif

/* User Atomic Record Layer CallBacks */
typedef int (*CallbackMacEncrypt)(WOLFSSL* ssl, unsigned char* macOut,
       const unsigned char* macIn, unsigned int macInSz, int macContent,
       int macVerify, unsigned char* encOut, const unsigned char* encIn,
       unsigned int encSz, void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Atomic User Record Processing Mac/Encrypt Callback.  The callback should return 0 for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  macOut is the output buffer where the result of the mac should be stored.  macIn is the mac input buffer and macInSz notes the size of the buffer.  macContent and macVerify are needed for wolfSSL_SetTlsHmacInner() and be passed along as is.  encOut is the output buffer where the result on the encryption should be stored.  encIn is the input buffer to encrypt while encSz is the size of the input.  An example callback can be found wolfssl/test.h myMacEncryptCb().
    
    \return none No return.
    
    \param No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX*, CallbackMacEncrypt);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Atomic User Record Processing Mac/Encrypt Callback Context to ctx.
    
    \return none No return.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_GetMacEncryptCtx
*/
WOLFSSL_API void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Atomic User Record Processing Mac/Encrypt Callback Context previously stored with wolfSSL_SetMacEncryptCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_SetMacEncryptCtx
*/
WOLFSSL_API void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

typedef int (*CallbackDecryptVerify)(WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int verify, unsigned int* padSz,
       void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Atomic User Record Processing Decrypt/Verify Callback.  The callback should return 0 for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  decOut is the output buffer where the result of the decryption should be stored.  decIn is the encrypted input buffer and decInSz notes the size of the buffer.  content and verify are needed for wolfSSL_SetTlsHmacInner() and be passed along as is.  padSz is an output variable that should be set with the total value of the padding.  That is, the mac size plus any padding and pad bytes.  An example callback can be found wolfssl/test.h myDecryptVerifyCb().
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX*,
                                               CallbackDecryptVerify);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Atomic User Record Processing Decrypt/Verify Callback Context to ctx.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_GetDecryptVerifyCtx
*/
WOLFSSL_API void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Atomic User Record Processing Decrypt/Verify Callback Context previously stored with wolfSSL_SetDecryptVerifyCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_SetDecryptVerifyCtx
*/
WOLFSSL_API void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup wolfssl

    \brief Allows retrieval of the Hmac/Mac secret from the handshake process.  The verify parameter specifies whether this is for verification of a peer message.
    
    \return pointer If successful the call will return a valid pointer to the secret.  The size of the secret can be obtained from wolfSSL_GetHmacSize().
    \return NULL will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param verify specifies whether this is for verification of a peer message.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetHmacSize
*/
WOLFSSL_API const unsigned char* wolfSSL_GetMacSecret(WOLFSSL*, int);
/*!
    \ingroup wolfssl

    \brief Allows retrieval of the client write key from the handshake process.
    
    \return pointer If successful the call will return a valid pointer to the key.  The size of the key can be obtained from wolfSSL_GetKeySize().
    \return NULL will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
*/
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows retrieval of the client write IV (initialization vector) from the handshake process.
    
    \return pointer If successful the call will return a valid pointer to the IV.  The size of the IV can be obtained from wolfSSL_GetCipherBlockSize().
    \return NULL will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetCipherBlockSize()
    \sa wolfSSL_GetClientWriteKey()
*/
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows retrieval of the server write key from the handshake process.
    
    \return pointer If successful the call will return a valid pointer to the key.  The size of the key can be obtained from wolfSSL_GetKeySize().
    \return NULL will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetServerWriteIV
*/
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows retrieval of the server write IV (initialization vector) from the handshake process.
    
    \return pointer If successful the call will return a valid pointer to the IV.  The size of the IV can be obtained from wolfSSL_GetCipherBlockSize().
    \return NULL will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetClientWriteKey
*/
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows retrieval of the key size from the handshake process.
    
    \return size If successful the call will return the key size in bytes.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
WOLFSSL_API int                  wolfSSL_GetKeySize(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Returns the iv_size member of the specs structure held in the WOLFSSL struct.
    
    \return iv_size returns the value held in ssl->specs.iv_size.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ivSize;
    ...
    ivSize = wolfSSL_GetIVSize(ssl);

    if(ivSize > 0){
    	// ivSize holds the specs.iv_size value.
    }
    \endcode
    
    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
    \sa wolfSSL_GetServerWriteIV
*/
WOLFSSL_API int                  wolfSSL_GetIVSize(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows retrieval of the side of this WOLFSSL connection.
    
    \return success If successful the call will return either WOLFSSL_SERVER_END or WOLFSSL_CLIENT_END depending on the side of WOLFSSL object.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
WOLFSSL_API int                  wolfSSL_GetSide(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to determine if the negotiated protocol version is at least TLS version 1.1 or greater.
    
    \return true/false If successful the call will return 1 for true or 0 for false.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetSide
*/
WOLFSSL_API int                  wolfSSL_IsTLSv1_1(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to determine the negotiated bulk cipher algorithm from the handshake.
    
    \return If successful the call will return one of the following: wolfssl_cipher_null, wolfssl_des, wolfssl_triple_des, wolfssl_aes, wolfssl_aes_gcm, wolfssl_aes_ccm, wolfssl_camellia, wolfssl_hc128, wolfssl_rabbit.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetKeySize
*/
WOLFSSL_API int                  wolfSSL_GetBulkCipher(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to determine the negotiated cipher block size from the handshake.
    
    \return size If successful the call will return the size in bytes of the cipher block size.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
WOLFSSL_API int                  wolfSSL_GetCipherBlockSize(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to determine the negotiated aead mac size from the handshake.  For cipher type WOLFSSL_AEAD_TYPE.
    
    \return size If successful the call will return the size in bytes of the aead mac size.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
WOLFSSL_API int                  wolfSSL_GetAeadMacSize(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to determine the negotiated (h)mac size from the handshake. For cipher types except WOLFSSL_AEAD_TYPE.
    
    \return size If successful the call will return the size in bytes of the (h)mac size.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
WOLFSSL_API int                  wolfSSL_GetHmacSize(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to determine the negotiated (h)mac type from the handshake.  For cipher types except WOLFSSL_AEAD_TYPE.
    
    \return If successful the call will return one of the following: MD5, SHA, SHA256, SHA384.
    \return BAD_FUNC_ARG may be returned for an error state.
    \return SSL_FATAL_ERROR may also be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacSize
*/
WOLFSSL_API int                  wolfSSL_GetHmacType(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to determine the negotiated cipher type from the handshake.
    
    \return If successful the call will return one of the following: WOLFSSL_BLOCK_TYPE, WOLFSSL_STREAM_TYPE, WOLFSSL_AEAD_TYPE.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
WOLFSSL_API int                  wolfSSL_GetCipherType(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Hmac Inner vector for message sending/receiving.  The result is written to inner which should be at least wolfSSL_GetHmacSize() bytes.  The size of the message is specified by sz, content is the type of message, and verify specifies whether this is a verification of a peer message. Valid for cipher types excluding WOLFSSL_AEAD_TYPE.
    
    \return 1 upon success.
    \return BAD_FUNC_ARG will be returned for an error state.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
WOLFSSL_API int                  wolfSSL_SetTlsHmacInner(WOLFSSL*, unsigned char*,
                                                       unsigned int, int, int);

/* Atomic User Needs */
enum {
    WOLFSSL_SERVER_END = 0,
    WOLFSSL_CLIENT_END = 1,
    WOLFSSL_NEITHER_END = 3,
    WOLFSSL_BLOCK_TYPE = 2,
    WOLFSSL_STREAM_TYPE = 3,
    WOLFSSL_AEAD_TYPE = 4,
    WOLFSSL_TLS_HMAC_INNER_SZ = 13      /* SEQ_SZ + ENUM + VERSION_SZ + LEN_SZ */
};

/* for GetBulkCipher and internal use */
enum BulkCipherAlgorithm {
    wolfssl_cipher_null,
    wolfssl_rc4,
    wolfssl_rc2,
    wolfssl_des,
    wolfssl_triple_des,             /* leading 3 (3des) not valid identifier */
    wolfssl_des40,
    wolfssl_idea,
    wolfssl_aes,
    wolfssl_aes_gcm,
    wolfssl_aes_ccm,
    wolfssl_chacha,
    wolfssl_camellia,
    wolfssl_hc128,                  /* wolfSSL extensions */
    wolfssl_rabbit
};


/* for KDF TLS 1.2 mac types */
enum KDF_MacAlgorithm {
    wolfssl_sha256 = 4,     /* needs to match internal MACAlgorithm */
    wolfssl_sha384,
    wolfssl_sha512
};


/* Public Key Callback support */
typedef int (*CallbackEccSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Callback for ECC Signing.  The callback should return 0 for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  in is the input buffer to sign while inSz denotes the length of the input.  out is the output buffer where the result of the signature should be stored.  outSz is an input/output variable that specifies the size of the output buffer upon invocation and the actual size of the signature should be stored there before returning.  keyDer is the ECC Private key in ASN1 format and keySz is the length of the key in bytes.  An example callback can be found wolfssl/test.h myEccSign().
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_SetEccSignCtx
    \sa wolfSSL_GetEccSignCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX*, CallbackEccSign);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Ecc Signing Callback Context to ctx.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_GetEccSignCtx
*/
WOLFSSL_API void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Public Key Ecc Signing Callback Context previously stored with wolfSSL_SetEccSignCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_SetEccSignCtx
*/
WOLFSSL_API void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

typedef int (*CallbackEccVerify)(WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* hash, unsigned int hashSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Callback for ECC Verification.  The callback should return 0 for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  sig is the signature to verify and sigSz denotes the length of the signature.  hash is an input buffer containing the digest of the message and hashSz denotes the length in bytes of the hash.  result is an output variable where the result of the verification should be stored, 1 for success and 0 for failure.  keyDer is the ECC Private key in ASN1 format and keySz is the length of the key in bytes.  An example callback can be found wolfssl/test.h myEccVerify().
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_SetEccVerifyCtx
    \sa wolfSSL_GetEccVerifyCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX*, CallbackEccVerify);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Ecc Verification Callback Context to ctx.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_GetEccVerifyCtx
*/
WOLFSSL_API void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Public Key Ecc Verification Callback Context previously stored with wolfSSL_SetEccVerifyCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_SetEccVerifyCtx
*/
WOLFSSL_API void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

struct ecc_key;
typedef int (*CallbackEccSharedSecret)(WOLFSSL* ssl, struct ecc_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx); /* side is WOLFSSL_CLIENT_END or WOLFSSL_SERVER_END */
WOLFSSL_API void  wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX*, CallbackEccSharedSecret);
WOLFSSL_API void  wolfSSL_SetEccSharedSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccSharedSecretCtx(WOLFSSL* ssl);

struct ed25519_key;
typedef int (*CallbackEd25519Sign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd25519SignCb(WOLFSSL_CTX*,
                                               CallbackEd25519Sign);
WOLFSSL_API void  wolfSSL_SetEd25519SignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd25519SignCtx(WOLFSSL* ssl);

typedef int (*CallbackEd25519Verify)(WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* msg, unsigned int msgSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd25519VerifyCb(WOLFSSL_CTX*,
                                                 CallbackEd25519Verify);
WOLFSSL_API void  wolfSSL_SetEd25519VerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd25519VerifyCtx(WOLFSSL* ssl);

struct curve25519_key;
typedef int (*CallbackX25519SharedSecret)(WOLFSSL* ssl,
        struct curve25519_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx);
        /* side is WOLFSSL_CLIENT_END or WOLFSSL_SERVER_END */
WOLFSSL_API void  wolfSSL_CTX_SetX25519SharedSecretCb(WOLFSSL_CTX*,
        CallbackX25519SharedSecret);
WOLFSSL_API void  wolfSSL_SetX25519SharedSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX25519SharedSecretCtx(WOLFSSL* ssl);

typedef int (*CallbackRsaSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Callback for RSA Signing.  The callback should return 0 for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  in is the input buffer to sign while inSz denotes the length of the input.  out is the output buffer where the result of the signature should be stored.  outSz is an input/output variable that specifies the size of the output buffer upon invocation and the actual size of the signature should be stored there before returning.  keyDer is the RSA Private key in ASN1 format and keySz is the length of the key in bytes.  An example callback can be found wolfssl/test.h myRsaSign().
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_SetRsaSignCtx
    \sa wolfSSL_GetRsaSignCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX*, CallbackRsaSign);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key RSA Signing Callback Context to ctx.
    
    \return none No Returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_GetRsaSignCtx
*/
WOLFSSL_API void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Public Key RSA Signing Callback Context previously stored with wolfSSL_SetRsaSignCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_SetRsaSignCtx
*/
WOLFSSL_API void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

typedef int (*CallbackRsaVerify)(WOLFSSL* ssl,
       unsigned char* sig, unsigned int sigSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Callback for RSA Verification.  The callback should return the number of plaintext bytes for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  sig is the signature to verify and sigSz denotes the length of the signature.  out should be set to the beginning of the verification buffer after the decryption process and any padding.  keyDer is the RSA Public key in ASN1 format and keySz is the length of the key in bytes.  An example callback can be found wolfssl/test.h myRsaVerify().
    
    \return none No returns.
    
    \param none No parameters.
    
    \sa wolfSSL_SetRsaVerifyCtx
    \sa wolfSSL_GetRsaVerifyCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX*, CallbackRsaVerify);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key RSA Verification Callback Context to ctx.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_GetRsaVerifyCtx
*/
WOLFSSL_API void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Public Key RSA Verification Callback Context previously stored with wolfSSL_SetRsaVerifyCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_SetRsaVerifyCtx
*/
WOLFSSL_API void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

#ifdef WC_RSA_PSS
typedef int (*CallbackRsaPssSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       int hash, int mgf,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaPssSignCb(WOLFSSL_CTX*, CallbackRsaPssSign);
WOLFSSL_API void  wolfSSL_SetRsaPssSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaPssSignCtx(WOLFSSL* ssl);

typedef int (*CallbackRsaPssVerify)(WOLFSSL* ssl,
       unsigned char* sig, unsigned int sigSz,
       unsigned char** out,
       int hash, int mgf,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaPssVerifyCb(WOLFSSL_CTX*,
                                                CallbackRsaPssVerify);
WOLFSSL_API void  wolfSSL_SetRsaPssVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaPssVerifyCtx(WOLFSSL* ssl);
#endif

/* RSA Public Encrypt cb */
typedef int (*CallbackRsaEnc)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Callback for RSA Public Encrypt.  The callback should return 0 for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  in is the input buffer to encrypt while inSz denotes the length of the input.  out is the output buffer where the result of the encryption should be stored.  outSz is an input/output variable that specifies the size of the output buffer upon invocation and the actual size of the encryption should be stored there before returning.  keyDer is the RSA Public key in ASN1 format and keySz is the length of the key in bytes.  An example callback can be found wolfssl/test.h myRsaEnc().
    
    \return none No returns.
    
    \param none No parameters.
    
    _Examples_
    \code
    none
    \endcode
    
    \sa wolfSSL_SetRsaEncCtx
    \sa wolfSSL_GetRsaEncCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX*, CallbackRsaEnc);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key RSA Public Encrypt Callback Context to ctx.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_GetRsaEncCtx
*/
WOLFSSL_API void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Public Key RSA Public Encrypt Callback Context previously stored with wolfSSL_SetRsaEncCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_SetRsaEncCtx
*/
WOLFSSL_API void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/* RSA Private Decrypt cb */
typedef int (*CallbackRsaDec)(WOLFSSL* ssl,
       unsigned char* in, unsigned int inSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key Callback for RSA Private Decrypt.  The callback should return the number of plaintext bytes for success or < 0 for an error.  The ssl and ctx pointers are available for the user’s convenience.  in is the input buffer to decrypt and inSz denotes the length of the input.  out should be set to the beginning of the decryption buffer after the decryption process and any padding.  keyDer is the RSA Private key in ASN1 format and keySz is the length of the key in bytes.  An example callback can be found wolfssl/test.h myRsaDec().
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_SetRsaDecCtx
    \sa wolfSSL_GetRsaDecCtx
*/
WOLFSSL_API void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX*, CallbackRsaDec);
/*!
    \ingroup wolfssl

    \brief Allows caller to set the Public Key RSA Private Decrypt Callback Context to ctx.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_GetRsaDecCtx
*/
WOLFSSL_API void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief Allows caller to retrieve the Public Key RSA Private Decrypt Callback Context previously stored with wolfSSL_SetRsaDecCtx().
    
    \return pointer If successful the call will return a valid pointer to the context.
    \return NULL will be returned for a blank context.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_SetRsaDecCtx
*/
WOLFSSL_API void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);


#ifndef NO_CERTS
/*!
    \ingroup wolfssl

    \brief This function registers a callback with the SSL context (WOLFSSL_CTX) to be called when a new CA certificate is loaded into wolfSSL.  The callback is given a buffer with the DER-encoded certificate.
    
    \return none No return.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param callback function to be registered as the CA callback for the wolfSSL context, ctx. The signature of this function must follow that as shown above in the Synopsis section.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;

    // CA callback prototype
    int MyCACallback(unsigned char *der, int sz, int type);

    // Register the custom CA callback with the SSL context
    wolfSSL_CTX_SetCACb(ctx, MyCACallback);

    int MyCACallback(unsigned char* der, int sz, int type)                   
    {
    	// custom CA callback function, DER-encoded cert
        // located in “der” of size “sz” with type “type” 
    }
    \endcode
    
    \sa wolfSSL_CTX_load_verify_locations
*/
    WOLFSSL_API void wolfSSL_CTX_SetCACb(WOLFSSL_CTX*, CallbackCACache);
/*!
    \ingroup CertManager
    \brief Allocates and initializes a new Certificate Manager context.  This context may be used independent of SSL needs.  It may be used to load certificates, verify certificates, and check the revocation status.
    
    \return WOLFSSL_CERT_MANAGER If successful the call will return a valid WOLFSSL_CERT_MANAGER pointer.
    \return NULL will be returned for an error state.
    
    \param none No parameters.
    
    \sa wolfSSL_CertManagerFree
*/
    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);
/*!
    \ingroup CertManager
    \brief Allocates and initializes a new Certificate Manager context.  This context may be used independent of SSL needs.  It may be used to load certificates, verify certificates, and check the revocation status.
    
    \return WOLFSSL_CERT_MANAGER If successful the call will return a valid WOLFSSL_CERT_MANAGER pointer.
    \return NULL will be returned for an error state.
    
    \param none No parameters.
        
    _Example_
    \code
    #import <wolfssl/ssl.h>
    
    WOLFSSL_CERT_MANAGER* cm;

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
	// error creating new cert manager
    }
    \endcode
    
    \sa wolfSSL_CertManagerFree
*/
    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);
/*!
    \ingroup CertManager
    \brief Frees all resources associated with the Certificate Manager context.  Call this when you no longer need to use the Certificate Manager.
    
    \return none
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CERT_MANAGER* cm;
    ...
    wolfSSL_CertManagerFree(cm);
    \endcode
    
    \sa wolfSSL_CertManagerNew
*/
    WOLFSSL_API void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER*);
/*!
    \ingroup CertManager
    \brief Specifies the locations for CA certificate loading into the manager context.  The PEM certificate CAfile may contain several trusted CA certificates.  If CApath is not NULL it specifies a directory containing CA certificates in PEM format.
    
    \return SSL_SUCCESS If successful the call will return.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer is not provided.
    \return SSL_FATAL_ERROR - will be returned upon failure.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param file pointer to the name of the file containing CA certificates to load.
    \param path pointer to the name of a directory path containing CA certificates to load.  The NULL pointer may be used if no certificate directory is desired.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerLoadCA(cm, “path/to/cert-file.pem”, 0);
    if (ret != SSL_SUCCESS) {
	// error loading CA certs into cert manager
    }
    \endcode
    
    \sa wolfSSL_CertManagerVerify
*/
    WOLFSSL_API int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER*, const char* f,
                                                                 const char* d);
/*!
    \ingroup CertManager
    \brief Loads the CA Buffer by calling wolfSSL_CTX_load_verify_buffer and returning that result using a temporary cm so as not to lose the information in the cm passed into the function.
    
    \return SSL_FATAL_ERROR is returned if the WOLFSSL_CERT_MANAGER struct is NULL or if wolfSSL_CTX_new() returns NULL.
    \return SSL_SUCCESS is returned for a successful execution.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param in buffer for cert information.
    \param sz length of the buffer.
    \param format certificate format, either PEM or DER.
    
    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    …
    const unsigned char* in;
    long sz;
    int format;
    …
    if(wolfSSL_CertManagerLoadCABuffer(vp, sz, format) != SSL_SUCCESS){
	    Error returned. Failure case code block.
    }
    \endcode
    
    \sa wolfSSL_CTX_load_verify_buffer
    \sa ProcessChainBuffer
    \sa ProcessBuffer
    \sa cm_pick_method
*/
    WOLFSSL_API int wolfSSL_CertManagerLoadCABuffer(WOLFSSL_CERT_MANAGER*,
                                  const unsigned char* in, long sz, int format);
/*!
    \ingroup CertManager
    \brief This function unloads the CA signer list.
    
    \return SSL_SUCCESS returned on successful execution of the function. 
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E returned if there was a mutex error.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    if(wolfSSL_CertManagerUnloadCAs(ctx->cm) != SSL_SUCCESS){
    	Failure case.
    }
    \endcode
    
    \sa FreeSignerTable
    \sa UnlockMutex
*/
    WOLFSSL_API int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);
#ifdef WOLFSSL_TRUST_PEER_CERT
/*!
    \ingroup CertManager
    \brief The function will free the Trusted Peer linked list and unlocks the trusted peer list.
    
    \return SSL_SUCCESS if the function completed normally.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E mutex  error if tpLock, a member of the WOLFSSL_CERT_MANAGER struct, is 0 (nill).
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    if(wolfSSL_CertManagerUnload_trust_peers(cm) != SSL_SUCCESS){
	    The function did not execute successfully.
    }
    \endcode
    
    \sa UnLockMutex
*/
    WOLFSSL_API int wolfSSL_CertManagerUnload_trust_peers(WOLFSSL_CERT_MANAGER* cm);
#endif
/*!
    \ingroup CertManager
    \brief Specifies the certificate to verify with the Certificate Manager context.  The format can be SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.
    
    \return SSL_SUCCESS If successfull.
    \return ASN_SIG_CONFIRM_E will be returned if the signature could not be verified.
    \return ASN_SIG_OID_E will be returned if the signature type is not supported.
    \return CRL_CERT_REVOKED is an error that is returned if this certificate has been revoked.
    \return CRL_MISSING is an error that is returned if a current issuer CRL is not available.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before the before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after the after date.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer is not provided.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param fname pointer to the name of the file containing the certificates to verify.
    \param format format of the certificate to verify - either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    
    ret = wolfSSL_CertManagerVerify(cm, “path/to/cert-file.pem”, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    error verifying certificate
    }
    \endcode
    
    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerifyBuffer
*/
    WOLFSSL_API int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER*, const char* f,
                                                                    int format);
/*!
    \ingroup CertManager
    \brief Specifies the certificate buffer to verify with the Certificate Manager context.  The format can be SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.
    
    \return SSL_SUCCESS If successful.
    \return ASN_SIG_CONFIRM_E will be returned if the signature could not be verified.
    \return ASN_SIG_OID_E will be returned if the signature type is not supported.
    \return CRL_CERT_REVOKED is an error that is returned if this certificate has been revoked.
    \return CRL_MISSING is an error that is returned if a current issuer CRL is not available.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before the before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after the after date.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer is not provided.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param buff buffer containing the certificates to verify.
    \param sz size of the buffer, buf.
    \param format format of the certificate to verify, located in buf - either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    int ret = 0;
    int sz = 0;
    WOLFSSL_CERT_MANAGER* cm;
    byte certBuff[...];
    ...

    ret = wolfSSL_CertManagerVerifyBuffer(cm, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	error verifying certificate
    }

    \endcode
    
    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerify
*/
    WOLFSSL_API int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* buff, long sz, int format);
/*!
    \ingroup wolfssl

    \brief Check CRL if the option is enabled and compares the cert to the CRL list.
    
    \return SSL_SUCCESS returns if the function returned as expected. If the crlEnabled member of the WOLFSSL_CERT_MANAGER struct is turned on.
    \return MEMORY_E returns if the allocated memory failed.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER is NULL.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER struct.
    \param der pointer to a DER formatted certificate.
    \param sz size of the certificate.
    
    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm;
    byte* der;
    int sz; // size of der
    ...
    if(wolfSSL_CertManagerCheckCRL(cm, der, sz) != SSL_SUCCESS){
    	// Error returned. Deal with failure case.
    }
    \endcode
    
    \sa CheckCertCRL
    \sa ParseCertRelative
    \sa wolfSSL_CertManagerSetCRL_CB
    \sa InitDecodedCert
*/
    WOLFSSL_API int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER*,
                                                        unsigned char*, int sz);
/*!
    \ingroup CertManager
    \brief Turns on Certificate Revocation List checking when verifying certificates with the Certificate Manager.  By default, CRL checking is off.  options include WOLFSSL_CRL_CHECKALL which performs CRL checking on each certificate in the chain versus the Leaf certificate only which is the default.
    
    \return SSL_SUCCESS If successful the call will return.
    \return NOT_COMPILED_IN will be returned if wolfSSL was not built with CRL enabled.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer is not provided.
    \return SSL_FAILURE will be returned if the CRL context cannot be initialized properly.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param options options to use when enabling the Certification Manager, cm.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerEnableCRL(cm, 0);
    if (ret != SSL_SUCCESS) {
    	error enabling cert manager
    }

    ...
    \endcode
    
    \sa wolfSSL_CertManagerDisableCRL
*/
    WOLFSSL_API int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER*,
                                                                   int options);
/*!
    \ingroup CertManager
    \brief Turns off Certificate Revocation List checking when verifying certificates with the Certificate Manager.  By default, CRL checking is off.  You can use this function to temporarily or permanently disable CRL checking with this Certificate Manager context that previously had CRL checking enabled.
    
    \return SSL_SUCCESS If successful the call will return.
    \return BAD_FUNC_ARG is the error that will be returned if a function pointer is not provided.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerDisableCRL(cm);
    if (ret != SSL_SUCCESS) {
    	error disabling cert manager
    }
    ...
    \endcode
    
    \sa wolfSSL_CertManagerEnableCRL
*/
    WOLFSSL_API int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER*);
/*!
    \ingroup CertManager
    \brief Error checks and passes through to LoadCRL() in order to load the cert into the CRL for revocation checking.
    
    \return SSL_SUCCESS if there is no error in wolfSSL_CertManagerLoadCRL and if LoadCRL returns successfully.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER struct is NULL.
    \return SSL_FATAL_ERROR if wolfSSL_CertManagerEnableCRL returns anything other than SSL_SUCCESS.
    \return BAD_PATH_ERROR if the path is NULL.
    \return MEMORY_E if LoadCRL fails to allocate heap memory.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param path a constant char pointer holding the CRL path.
    \param type type of certificate to be loaded.
    \param monitor requests monitoring in LoadCRL().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, 
    int monitor);
    …
    wolfSSL_CertManagerLoadCRL(ssl->ctx->cm, path, type, monitor);
    \endcode
    
    \sa wolfSSL_CertManagerEnableCRL
    \sa wolfSSL_LoadCRL
*/
    WOLFSSL_API int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER*,
                                                         const char*, int, int);
/*!
    \ingroup CertManager
    \brief The function loads the CRL file by calling BufferLoadCRL.
    
    \return SSL_SUCCESS returned if the function completed without errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return SSL_FATAL_ERROR returned if there is an error associated with the WOLFSSL_CERT_MANAGER.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure.
    \param buff a constant byte type and is the buffer.
    \param sz a long int representing the size of the buffer.
    \param type a long integer that holds the certificate type.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CERT_MANAGER* cm;
    const unsigned char* buff; 
    long sz; size of buffer
    int type;  cert type
    ...
    int ret = wolfSSL_CertManagerLoadCRLBuffer(cm, buff, sz, type);
    if(ret == SSL_SUCCESS){
	return ret;
    } else {
    	Failure case.
    }
    \endcode
    
    \sa BufferLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
*/
    WOLFSSL_API int wolfSSL_CertManagerLoadCRLBuffer(WOLFSSL_CERT_MANAGER*,
                                            const unsigned char*, long sz, int);
/*!
    \ingroup CertManager
    \brief This function sets the CRL Certificate Manager callback. If HAVE_CRL is defined and a matching CRL record is not found then the cbMissingCRL is called (set via wolfSSL_CertManagerSetCRL_Cb). This allows you to externally retrieve the CRL and load it.
    
    \return SSL_SUCCESS returned upon successful execution of the function and subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.
    
    \param cm the WOLFSSL_CERT_MANAGER structure holding the information for the certificate.
    \param cb a function pointer to (*CbMissingCRL) that is set to the cbMissingCRL member of the WOLFSSL_CERT_MANAGER.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url){
	    Function body.
    }
    …
    CbMissingCRL cb = CbMissingCRL;
    …
    if(ctx){
        return wolfSSL_CertManagerSetCRL_Cb(ssl->ctx->cm, cb);
    }
    \endcode
    
    \sa CbMissingCRL
    \sa wolfSSL_SetCRL_Cb
*/
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER*,
                                                                  CbMissingCRL);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_IOCb(WOLFSSL_CERT_MANAGER*,
                                                                       CbCrlIO);
#endif
/*!
    \ingroup CertManager
    \brief The function enables the WOLFSSL_CERT_MANAGER’s member, ocspEnabled to signify that the OCSP check option is enabled.
    
    \return SSL_SUCCESS returned on successful execution of the function. The ocspEnabled member of the WOLFSSL_CERT_MANAGER is enabled.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL or if an argument value that is not allowed is passed to a subroutine.
    \return MEMORY_E returned if there is an error allocating memory within this function or a subroutine.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param der a byte pointer to the certificate.
    \param sz an int type representing the size of the DER cert.
    
    _Example_
    \code
    #import <wolfssl/ssl.h>
    
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* der;
    int sz; size of der
    ...
    if(wolfSSL_CertManagerCheckOCSP(cm, der, sz) != SSL_SUCCESS){
	 Failure case.
    }
    \endcode
    
    \sa ParseCertRelative
    \sa CheckCertOCSP
*/
    WOLFSSL_API int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER*,
                                                        unsigned char*, int sz);
/*!
    \ingroup CertManager
    \brief Turns on OCSP if it’s turned off and if compiled with the set option available.
    
    \return SSL_SUCCESS returned if the function call is successful.
    \return BAD_FUNC_ARG if cm struct is NULL.
    \return MEMORY_E if WOLFSSL_OCSP struct value is NULL.
    \return SSL_FAILURE initialization of WOLFSSL_OCSP struct fails to initialize.
    \return NOT_COMPILED_IN build not compiled with correct feature enabled.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using wolfSSL_CertManagerNew().
    \param options used to set values in WOLFSSL_CERT_MANAGER struct.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    int options; 
    …
    if(wolfSSL_CertManagerEnableOCSP(ssl->ctx->cm, options) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode
    
    \sa wolfSSL_CertManagerNew
*/
    WOLFSSL_API int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER*,
                                                                   int options);
/*!
    \ingroup CertManager
    \brief Disables OCSP certificate revocation.
    
    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRL successfully disabled the crlEnabled member of the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL.
    
    \param ssl - a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CertManagerDisableOCSP(ssl) != SSL_SUCCESS){
	    Fail case.
    }
    \endcode
    
    \sa wolfSSL_DisableCRL
*/
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER*);
/*!
    \ingroup CertManager
    \brief The function copies the url to the ocspOverrideURL member of the WOLFSSL_CERT_MANAGER structure.
    
    \return SSL_SUCCESS the function was able to execute as expected.
    \return BAD_FUNC_ARG the WOLFSSL_CERT_MANAGER struct is NULL.
    \return MEMEORY_E Memory was not able to be allocated for the ocspOverrideURL member of the certificate manager.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    const char* url;
    …
    int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
    …
    if(wolfSSL_CertManagerSetOCSPOverrideURL(ssl->ctx->cm, url) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode
    
    \sa ocspOverrideURL
    \sa wolfSSL_SetOCSP_OverrideURL
*/
    WOLFSSL_API int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER*,
                                                                   const char*);
/*!
    \ingroup CertManager
    \brief The function sets the OCSP callback in the WOLFSSL_CERT_MANAGER.
    
    \return SSL_SUCCESS returned on successful execution. The arguments are saved in the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure.
    \param ioCb a function pointer of type CbOCSPIO.
    \param respFreeCb - a function pointer of type CbOCSPRespFree.
    \param ioCbCtx - a void pointer variable to the I/O callback user registered context.
    
    _Example_
    \code
    #include <wolfssl/ssl.h>
    
    wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb, 
    CbOCSPRespFree respFreeCb, void* ioCbCtx){
    …
    return wolfSSL_CertManagerSetOCSP_Cb(ssl->ctx->cm, ioCb, respFreeCb, ioCbCtx);
    \endcode
    
    \sa wolfSSL_CertManagerSetOCSPOverrideURL
    \sa wolfSSL_CertManagerCheckOCSP
    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa wolfSSL_ENableOCSP
    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_SetOCSP_Cb
*/
    WOLFSSL_API int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER*,
                                               CbOCSPIO, CbOCSPRespFree, void*);
/*!
    \ingroup CertManager
    \brief This function turns on OCSP stapling if it is not turned on as well as set the options.
    
    \return SSL_SUCCESS returned if there were no errors and the function executed successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL or otherwise if there was a unpermitted argument value passed to a subroutine.
    \return MEMORY_E returned if there was an issue allocating memory.
    \return SSL_FAILURE returned if the initialization of the OCSP structure failed.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with HAVE_CERTIFICATE_STATUS_REQUEST option.
    
    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, a member of the WOLFSSL_CTX structure.
    
    _Example_
    \code
    int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx){
    …
    return wolfSSL_CertManagerEnableOCSPStapling(ctx->cm);
    \endcode
    
    \sa wolfSSL_CTX_EnableOCSPStapling
*/
    WOLFSSL_API int wolfSSL_CertManagerEnableOCSPStapling(
                                                      WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup wolfssl

    \brief Enables CRL certificate revocation.
    
    \return SSL_SUCCESS the function and subroutines returned with no errors. 
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.
    \return MEMORY_E returned if the allocation of memory failed.
    \return SSL_FAILURE returned if the InitCRL function does not return successfully.
    \return NOT_COMPILED_IN HAVE_CRL was not enabled during the compiling.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param options an integer that is used to determine the setting of crlCheckAll member of the WOLFSSL_CERT_MANAGER structure.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_EnableCRL(ssl, WOLFSSL_CRL_CHECKALL) != SSL_SUCCESS){
	    // Failure case. SSL_SUCCESS was not returned by this function or a subroutine
    }
    \endcode
    
    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
*/
    WOLFSSL_API int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);
/*!
    \ingroup wolfssl

    \brief Disables CRL certificate revocation.
    
    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRL successfully disabled the crlEnabled member of the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_DisableCRL(ssl) != SSL_SUCCESS){
    	// Failure case
    }
    \endcode
    
    \sa wolfSSL_CertManagerDisableCRL
    \sa wolfSSL_CertManagerDisableOCSP
*/
    WOLFSSL_API int wolfSSL_DisableCRL(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief A wrapper function that ends up calling LoadCRL to load the certificate for revocation checking.
    
    \return WOLFSSL_SUCCESS returned if the function and all of the subroutines executed without error.
    \return SSL_FATAL_ERROR returned if one of the subroutines does not return successfully.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER or the WOLFSSL structure are NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param path a constant character pointer that holds the path to the crl file.
    \param type an integer representing the type of certificate.
    \param monitor an integer variable used to verify the monitor path if requested.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* crlPemDir;
    …
    if(wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS){
    	// Failure case. Did not return SSL_SUCCESS.
    }
    \endcode
    
    \sa wolfSSL_CertManagerLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
    \sa LoadCRL
*/
    WOLFSSL_API int wolfSSL_LoadCRL(WOLFSSL*, const char*, int, int);
    WOLFSSL_API int wolfSSL_LoadCRLBuffer(WOLFSSL*,
                                          const unsigned char*, long sz, int);
/*!
    \ingroup wolfssl

    \brief Sets the CRL callback in the WOLFSSL_CERT_MANAGER structure.
    
    \return SSL_SUCCESS returned if the function or subroutine executes without error. The cbMissingCRL member of the WOLFSSL_CERT_MANAGER is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL or WOLFSSL_CERT_MANAGER structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to CbMissingCRL.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url) // required signature
    {
    	// Function body
    }
    …
    int crlCb = wolfSSL_SetCRL_Cb(ssl, cb);
    if(crlCb != SSL_SUCCESS){
    	// The callback was not set properly
    }
    \endcode
    
    \sa CbMissingCRL
    \sa wolfSSL_CertManagerSetCRL_Cb
*/
    WOLFSSL_API int wolfSSL_SetCRL_Cb(WOLFSSL*, CbMissingCRL);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb);
#endif
/*!
    \ingroup wolfssl

    \brief This function enables OCSP certificate verification.
    
    \return SSL_SUCCESS returned if the function and subroutines executes without errors.
    \return BAD_FUNC_ARG returned if an argument in this function or any subroutine receives an invalid argument value.
    \return MEMORY_E returned if there was an error allocating memory for a structure or other variable.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with the HAVE_OCSP option.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param options an integer type passed to wolfSSL_CertMangerENableOCSP() used for settings check.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int options; // initialize to option constant
    …
    int ret = wolfSSL_EnableOCSP(ssl, options);
    if(ret != SSL_SUCCESS){
    	// OCSP is not enabled
    }
    \endcode
    
    \sa wolfSSL_CertManagerEnableOCSP
*/
    WOLFSSL_API int wolfSSL_EnableOCSP(WOLFSSL*, int options);
/*!
    \ingroup wolfssl

    \brief Disables the OCSP certificate revocation option.
    
    \return SSL_SUCCESS returned if the function and its subroutine return with no errors. The ocspEnabled member of the WOLFSSL_CERT_MANAGER structure was successfully set.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(wolfSSL_DisableOCSP(ssl) != SSL_SUCCESS){
	    // Returned with an error. Failure case in this block.
    }
    \endcode
    
    \sa wolfSSL_CertManagerDisableOCSP
*/
    WOLFSSL_API int wolfSSL_DisableOCSP(WOLFSSL*);
/*!
    \ingroup wolfssl

    \brief This function sets the ocspOverrideURL member in the WOLFSSL_CERT_MANAGER structure.
    
    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if a unpermitted argument was passed to a subroutine.
    \return MEMORY_E returned if there was an error allocating memory in the subroutine.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param url a constant char pointer to the url that will be stored in the ocspOverrideURL member of the WOLFSSL_CERT_MANAGER structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char url[URLSZ];
    ...
    if(wolfSSL_SetOCSP_OverrideURL(ssl, url)){
    	// The override url is set to the new value
    }
    \endcode
    
    \sa wolfSSL_CertManagerSetOCSPOverrideURL
*/
    WOLFSSL_API int wolfSSL_SetOCSP_OverrideURL(WOLFSSL*, const char*);
/*!
    \ingroup wolfssl

    \brief This function sets the OCSP callback in the WOLFSSL_CERT_MANAGER structure.
    
    \return SSL_SUCCESS returned if the function executes without error. The ocspIOCb, ocspRespFreeCb, and ocspIOCtx memebers of the CM are set.
    \return BAD_FUNC_ARG returned if the WOLFSSL or WOLFSSL_CERT_MANAGER structures are NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ioCb a function pointer to type CbOCSPIO.
    \param respFreeCb a function pointer to type CbOCSPRespFree which is the call to free the response memory.
    \param ioCbCtx a void pointer that will be held in the ocspIOCtx member of the CM.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int OCSPIO_CB(void* , const char*, int , unsigned char* , int, 
    unsigned char**){  // must have this signature
    // Function Body
    }
    …
    void OCSPRespFree_CB(void* , unsigned char* ){ // must have this signature
    	// function body
    }
    …
    void* ioCbCtx; 
    CbOCSPRespFree CB_OCSPRespFree;

    if(wolfSSL_SetOCSP_Cb(ssl, OCSPIO_CB( pass args ), CB_OCSPRespFree, 
				ioCbCtx) != SSL_SUCCESS){
	    // Callback not set
    }
    \endcode
    
    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
    WOLFSSL_API int wolfSSL_SetOCSP_Cb(WOLFSSL*, CbOCSPIO, CbOCSPRespFree, void*);

/*!
    \ingroup wolfssl

    \brief Enables CRL certificate verification through the CTX.
    
    \return SSL_SUCCESS returned if this function and it’s subroutines execute without errors. 
    \return BAD_FUNC_ARG returned if the CTX struct is NULL or there was otherwise an invalid argument passed in a subroutine.
    \return MEMORY_E returned if there was an error allocating memory during execution of the function.
    \return SSL_FAILURE returned if the crl member of the WOLFSSL_CERT_MANAGER fails to initialize correctly.
    \return NOT_COMPILED_IN wolfSSL was not compiled with the HAVE_CRL option.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_EnableCRL(ssl->ctx, options) != SSL_SUCCESS){
    	// The function failed
    }
    \endcode
    
    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
    \sa wolfSSL_CTX_DisableCRL
*/
    WOLFSSL_API int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);
/*!
    \ingroup wolfssl

    \brief This function disables CRL verification in the CTX structure.
    
    \return SSL_SUCCESS returned if the function executes without error. The crlEnabled member of the WOLFSSL_CERT_MANAGER struct is set to 0.
    \return BAD_FUNC_ARG returned if either the CTX struct or the CM struct has a NULL value.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_DisableCRL(ssl->ctx) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode
    
    \sa wolfSSL_CertManagerDisableCRL
*/
    WOLFSSL_API int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);
/*!
    \ingroup wolfssl

    \brief This function loads CRL into the WOLFSSL_CTX structure through wolfSSL_CertManagerLoadCRL().
    
    \return SSL_SUCCESS - returned if the function and its subroutines execute without error.
    \return BAD_FUNC_ARG - returned if this function or any subroutines are passed NULL structures.
    \return BAD_PATH_ERROR - returned if the path variable opens as NULL.
    \return MEMORY_E - returned if an allocation of memory failed.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param path the path to the certificate.
    \param type an integer variable holding the type of certificate.
    \param monitor an integer variable used to determine if the monitor path is requested.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    const char* path;
    …
    return wolfSSL_CTX_LoadCRL(ctx, path, SSL_FILETYPE_PEM, 0);
    \endcode
    
    \sa wolfSSL_CertManagerLoadCRL
    \sa LoadCRL
*/
    WOLFSSL_API int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX*, const char*, int, int);
    WOLFSSL_API int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX*,
                                            const unsigned char*, long sz, int);
/*!
    \ingroup wolfssl

    \brief This function will set the callback argument to the cbMissingCRL member of the WOLFSSL_CERT_MANAGER structure by calling wolfSSL_CertManagerSetCRL_Cb.
    
    \return SSL_SUCCESS returned for a successful execution. The WOLFSSL_CERT_MANAGER structure’s member cbMssingCRL was successfully set to cb.
    \return BAD_FUNC_ARG returned if WOLFSSL_CTX or WOLFSSL_CERT_MANAGER are NULL.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created with wolfSSL_CTX_new().
    \param cb a pointer to a callback function of type CbMissingCRL. Signature requirement:
	void (*CbMissingCRL)(const char* url);
	
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    void cb(const char* url) // Required signature
    {
    	// Function body
    }
    …
    if (wolfSSL_CTX_SetCRL_Cb(ctx, cb) != SSL_SUCCESS){
    	// Failure case, cb was not set correctly.
    }
    \endcode
    
    \sa wolfSSL_CertManagerSetCRL_Cb
    \sa CbMissingCRL
*/
    WOLFSSL_API int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX*, CbMissingCRL);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX*, CbCrlIO);
#endif
/*!
    \ingroup wolfssl

    \brief This function sets options to configure behavior of OCSP functionality in wolfSSL.  The value of options if formed by or’ing one or more of the following options: WOLFSSL_OCSP_ENABLE - enable OCSP lookups	WOLFSSL_OCSP_URL_OVERRIDE - use the override URL instead of the URL in certificates. The override URL is specified using the wolfSSL_CTX_SetOCSP_OverrideURL() function. This function only sets the OCSP options when wolfSSL has been compiled with OCSP support (--enable-ocsp, #define HAVE_OCSP).
    
    \return SSL_SUCCESS is returned upon success.
    \return SSL_FAILURE is returned upon failure.
    \return NOT_COMPILED_IN is returned when this function has been called, but OCSP support was not enabled when wolfSSL was compiled.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param options value used to set the OCSP options.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_OCSP_set_options(ctx, WOLFSSL_OCSP_ENABLE);
    \endcode
    
    \sa wolfSSL_CTX_OCSP_set_override_url
*/
    WOLFSSL_API int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX*, int options);
/*!
    \ingroup wolfssl

    \brief This function disables OCSP certificate revocation checking by affecting the ocspEnabled member of the WOLFSSL_CERT_MANAGER structure.
    
    \return SSL_SUCCESS returned if the function executes without error. The ocspEnabled member of the CM has been disabled.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(!wolfSSL_CTX_DisableOCSP(ssl->ctx)){
    	// OCSP is not disabled
    }
    \endcode
    
    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_CertManagerDisableOCSP
*/
    WOLFSSL_API int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX*);
/*!
    \ingroup wolfssl

    \brief This function manually sets the URL for OCSP to use.  By default, OCSP will use the URL found in the individual certificate unless the WOLFSSL_OCSP_URL_OVERRIDE option is set using the wolfSSL_CTX_EnableOCSP.
    
    \return SSL_SUCCESS is returned upon success.
    \return SSL_FAILURE is returned upon failure.
    \return NOT_COMPILED_IN is returned when this function has been called, but OCSP support was not enabled when wolfSSL was compiled.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param url pointer to the OCSP URL for wolfSSL to use.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_OCSP_set_override_url(ctx, “custom-url-here”);
    \endcode
    
    \sa wolfSSL_CTX_OCSP_set_options
*/
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX*, const char*);
/*!
    \ingroup wolfssl

    \brief Sets the callback for the OCSP in the WOLFSSL_CTX structure.
    
    \return SSL_SUCCESS returned if the function executed successfully. The ocspIOCb, ocspRespFreeCb, and ocspIOCtx members in the CM were successfully set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX or WOLFSSL_CERT_MANAGER structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ioCb a CbOCSPIO type that is a function pointer.
    \param respFreeCb a CbOCSPRespFree type that is a function pointer.
    \param ioCbCtx a void pointer that will be held in the WOLFSSL_CERT_MANAGER.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    CbOCSPIO ocspIOCb;  
    CbOCSPRespFree ocspRespFreeCb;
    …
    void* ioCbCtx;

    int isSetOCSP = wolfSSL_CTX_SetOCSP_Cb(ctx, ocspIOCb, ocspRespFreeCb, ioCbCtx);

    if(isSetOCSP != SSL_SUCCESS){
    	// The function did not return successfully.
    }
    \endcode
    
    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX*,
                                               CbOCSPIO, CbOCSPRespFree, void*);

/*!
    \ingroup wolfssl

    \brief This function enables OCSP stapling by calling wolfSSL_CertManagerEnableOCSPStapling().
    
    \return SSL_SUCCESS returned if there were no errors and the function executed successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or otherwise if there was a unpermitted argument value passed to a subroutine.
    \return MEMORY_E returned if there was an issue allocating memory.
    \return SSL_FAILURE returned if the initialization of the OCSP structure failed.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with HAVE_CERTIFICATE_STATUS_REQUEST option.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    
    _Example_
    \code
    WOLFSSL* ssl = WOLFSSL_new();
    ssl->method.version; // set to desired protocol
    ...
    if(!wolfSSL_CTX_EnableOCSPStapling(ssl->ctx)){
    	// OCSP stapling is not enabled
    }
    \endcode
    
    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa InitOCSP
*/
    WOLFSSL_API int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX*);
#endif /* !NO_CERTS */


#ifdef SINGLE_THREADED
    WOLFSSL_API int wolfSSL_CTX_new_rng(WOLFSSL_CTX*);
#endif

/* end of handshake frees temporary arrays, if user needs for get_keys or
   psk hints, call KeepArrays before handshake and then FreeArrays when done
   if don't want to wait for object free */
/*!
    \ingroup wolfssl

    \brief Normally, at the end of the SSL handshake, wolfSSL frees temporary arrays.  Calling this function before the handshake begins will prevent wolfSSL from freeing temporary arrays.  Temporary arrays may be needed for things such as wolfSSL_get_keys() or PSK hints. When the user is done with temporary arrays, either wolfSSL_FreeArrays() may be called to free the resources immediately, or alternatively the resources will be freed when the associated SSL object is freed.
    
    \return none No return.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_KeepArrays(ssl);
    \endcode
    
    \sa wolfSSL_FreeArrays
*/
WOLFSSL_API void wolfSSL_KeepArrays(WOLFSSL*);
/*!
    \brief Normally, at the end of the SSL handshake, wolfSSL frees temporary arrays.  If wolfSSL_KeepArrays() has been called before the handshake, wolfSSL will not free temporary arrays.  This function explicitly frees temporary arrays and should be called when the user is done with temporary arrays and does not want to wait for the SSL object to be freed to free these resources.
    
    \return none No return.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_FreeArrays(ssl);
    \endcode
    
    \sa wolfSSL_KeepArrays
*/
WOLFSSL_API void wolfSSL_FreeArrays(WOLFSSL*);

WOLFSSL_API int wolfSSL_KeepHandshakeResources(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_FreeHandshakeResources(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_CTX_UseClientSuites(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_UseClientSuites(WOLFSSL* ssl);

/* async additions */
WOLFSSL_API int wolfSSL_UseAsync(WOLFSSL*, int devId);
WOLFSSL_API int wolfSSL_CTX_UseAsync(WOLFSSL_CTX*, int devId);

/* helpers to get device id and heap */
WOLFSSL_API int   wolfSSL_CTX_GetDevId(WOLFSSL_CTX* ctx, WOLFSSL* ssl);
WOLFSSL_API void* wolfSSL_CTX_GetHeap(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/* TLS Extensions */

/* Server Name Indication */
#ifdef HAVE_SNI

/* SNI types */
enum {
    WOLFSSL_SNI_HOST_NAME = 0
};

/*!
    \ingroup wolfssl

    \brief This function enables the use of Server Name Indication in the SSL object passed in the 'ssl' parameter. It means that the SNI extension will be sent on ClientHello by wolfSSL client and wolfSSL server will respond ClientHello + SNI with either ServerHello + blank SNI or alert fatal in case of SNI mismatch.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ssl is NULL, data is NULL, type is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been passed in data. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the server name data.
    \param size size of the server name data.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != 0) {
        // sni usage failed
    }
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseSNI
*/
WOLFSSL_API int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type,
                                         const void* data, unsigned short size);
/*!
    \ingroup wolfssl

    \brief This function enables the use of Server Name Indication for SSL objects created from the SSL context passed in the 'ctx' parameter. It means that the SNI extension will be sent on ClientHello by wolfSSL clients and wolfSSL servers will respond ClientHello + SNI with either ServerHello + blank SNI or alert fatal in case of SNI mismatch.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ctx is NULL, data is NULL, type is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param type indicates which type of server name is been passed in data. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the server name data.
    \param size size of the server name data.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != 0) {
        // sni usage failed
    }
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSNI
*/
WOLFSSL_API int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
                                         const void* data, unsigned short size);

#ifndef NO_WOLFSSL_SERVER

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

/*!
    \ingroup wolfssl

    \brief This function is called on the server side to configure the behavior of the SSL session using Server Name Indication in the SSL object passed in the 'ssl' parameter. The options are explained below.
    
    \return none No returns.
    
    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been passed in data. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param options a bitwise semaphore with the chosen options. The available options are: enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01, WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }; Normally the server will abort the handshake by sending a fatal-level unrecognized_name(112) alert if the hostname provided by the client mismatch with the servers.
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH With this option set, the server will not send a SNI response instead of aborting the session.
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH - With this option set, the server will send a SNI response as if the host names match instead of aborting the session.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != 0) {
        // sni usage failed
    }
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME, WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_SNI_SetOptions
*/
WOLFSSL_API void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, unsigned char type,
                                                         unsigned char options);
/*!
    \ingroup wolfssl

    \brief This function is called on the server side to configure the behavior of the SSL sessions using Server Name Indication for SSL objects created from the SSL context passed in the 'ctx' parameter. The options are explained below.
    
    \return none No returns.
    
    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param type indicates which type of server name is been passed in data. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param options a bitwise semaphore with the chosen options. The available options are: enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01, WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }; Normally the server will abort the handshake by sending a fatal-level unrecognized_name(112) alert if the hostname provided by the client mismatch with the servers.
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH With this option set, the server will not send a SNI response instead of aborting the session.
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH With this option set, the server will send a SNI response as if the host names match instead of aborting the session.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
       // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != 0) {
        // sni usage failed
    }
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME, WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endocde
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_SetOptions
*/
WOLFSSL_API void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx,
                                     unsigned char type, unsigned char options);

/* SNI status */
enum {
    WOLFSSL_SNI_NO_MATCH   = 0,
    WOLFSSL_SNI_FAKE_MATCH = 1, /**< @see WOLFSSL_SNI_ANSWER_ON_MISMATCH */
    WOLFSSL_SNI_REAL_MATCH = 2,
    WOLFSSL_SNI_FORCE_KEEP = 3  /** Used with -DWOLFSSL_ALWAYS_KEEP_SNI */
};

/*!
    \ingroup wolfssl

    \brief This function gets the status of an SNI object.
    
    \return value This function returns the byte value of the SNI struct’s status member if the SNI is not NULL.
    \return 0 if the SNI object is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param type the SNI type.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
    …
    Byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = (char*)&type;
    AssertIntEQ(WOLFSSL_SNI_NO_MATCH, wolfSSL_SNI_Status(ssl, type));
    …
    \endcode
    
    \sa TLSX_SNI_Status
    \sa TLSX_SNI_find
    \sa TLSX_Find
*/
WOLFSSL_API unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type);

/*!
    \ingroup wolfssl

    \brief This function is called on the server side to retrieve the Server Name Indication provided by the client in a SSL session.
    
    \return size the size of the provided SNI data.
    
    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been retrieved in data. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the data provided by the client.
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != 0) {
        // sni usage failed
    }
    if (wolfSSL_accept(ssl) == SSL_SUCCESS) {
        void *data = NULL;
        unsigned short size = wolfSSL_SNI_GetRequest(ssl, 0, &data);
    }
    \endcode
    
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
*/
WOLFSSL_API unsigned short wolfSSL_SNI_GetRequest(WOLFSSL *ssl,
                                               unsigned char type, void** data);
/*!
    \ingroup wolfssl

    \brief This function is called on the server side to retrieve the Server Name Indication provided by the client from the Client Hello message sent by the client to start a session. It does not requires context or session setup to retrieve the SNI.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of this cases: buffer is NULL, bufferSz <= 0, sni is NULL, inOutSz is NULL or <= 0
    \return BUFFER_ERROR is the error returned when there is a malformed Client Hello message.
    \return INCOMPLETE_DATA is the error returned when there is not enough data to complete the extraction.
    
    \param buffer pointer to the data provided by the client (Client Hello).
    \param bufferSz size of the Client Hello message.
    \param type indicates which type of server name is been retrieved from the buffer. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param sni pointer to where the output is going to be stored.
    \param inOutSz pointer to the output size, this value will be updated to MIN("SNI's length", inOutSz).
    
    _Example_
    \code
    unsigned char buffer[1024] = {0};
    unsigned char result[32]   = {0};
    int           length       = 32;
    // read Client Hello to buffer...
    ret = wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer), 0, result, &length));
    if (ret != SSL_SUCCESS) {
        // sni retrieve failed
    }
    \endcode
    
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_GetRequest
*/
WOLFSSL_API int wolfSSL_SNI_GetFromBuffer(
                 const unsigned char* clientHello, unsigned int helloSz,
                 unsigned char type, unsigned char* sni, unsigned int* inOutSz);

#endif
#endif

/* Application-Layer Protocol Negotiation */
#ifdef HAVE_ALPN

/* ALPN status code */
enum {
    WOLFSSL_ALPN_NO_MATCH = 0,
    WOLFSSL_ALPN_MATCH    = 1,
    WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 2,
    WOLFSSL_ALPN_FAILED_ON_MISMATCH = 4,
};

enum {
    WOLFSSL_MAX_ALPN_PROTO_NAME_LEN = 255,
    WOLFSSL_MAX_ALPN_NUMBER = 257
};

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
typedef int (*CallbackALPNSelect)(WOLFSSL* ssl, const unsigned char** out,
    unsigned char* outLen, const unsigned char* in, unsigned int inLen,
    void *arg);
#endif

/*!
    \ingroup wolfssl

    \brief Setup ALPN use for a wolfSSL session.
    
    \return SSL_SUCCESS: upon success.
    \return BAD_FUNC_ARG Returned if ssl or protocol_name_list is null or protocol_name_listSz is too large or options contain something not supported.
    \return MEMORY_ERROR Error allocating memory for protocol list.
    \return SSL_FAILURE upon failure.
    
    \param ssl The wolfSSL session to use.
    \param protocol_name_list List of protocol names to use.  Comma delimited string is required.
    \param protocol_name_listSz Size of the list of protocol names.
    \param options WOLFSSL_ALPN_CONTINUE_ON_MISMATCH or WOLFSSL_ALPN_FAILED_ON_MISMATCH.
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    char alpn_list[] = {};

    if(wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list), 
    WOLFSSL_APN_FAILED_ON_MISMATCH) != SSL_SUCCESS)
    {
       // Error setting session ticket
    }
    \endcode
    
    \sa TLSX_UseALPN
*/
WOLFSSL_API int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
                                unsigned int protocol_name_listSz,
                                unsigned char options);
                                
/*!
    \ingroup wolfssl

    \brief This function gets the protocol name set by the server.
    
    \return SSL_SUCCESS returned on successful execution where no errors were thrown.
    \return SSL_FATAL_ERROR returned if the extension was not found or if there was no protocol match with peer. There will also be an error thrown if there is more than one protocol name accepted.
    \return SSL_ALPN_NOT_FOUND returned signifying that no protocol match with peer was found.
    \return BAD_FUNC_ARG returned if there was a NULL argument passed into the function.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param protocol_name a pointer to a char that represents the protocol name and will be held in the ALPN structure.
    \param size a word16 type that represents the size of the protocol_name.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int err;
    char* protocol_name = NULL;
    Word16 protocol_nameSz = 0;
    err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);

    if(err == SSL_SUCCESS){
	    // Sent ALPN protocol
    }
    \endcode
    
    \sa TLSX_ALPN_GetRequest
    \sa TLSX_Find
*/
WOLFSSL_API int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name,
                                         unsigned short *size);
/*!
    \ingroup wolfssl

    \brief This function copies the alpn_client_list data from the SSL object to the buffer.
    
    \return SSL_SUCCESS returned if the function executed without error.  The alpn_client_list member of the SSL object has been copied to the list parameter.
    \return BAD_FUNC_ARG returned if the list or listSz parameter is NULL.
    \return BUFFER_ERROR returned if there will be a problem with the list buffer (either it’s NULL or the size is 0).
    \return MEMORY_ERROR returned if there was a problem dynamically allocating memory.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param list a pointer to the buffer. The data from the SSL object will be copied into it.
    \param listSz the buffer size.
    
    _Example_
    \code
    #import <wolfssl/ssl.h>
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #ifdef HAVE_ALPN
    char* list = NULL;
    word16 listSz = 0;
    …
    err = wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz);

    if(err == SSL_SUCCESS){
	    List of protocols names sent by client
    }
    \endcode
    
    \sa wolfSSL_UseALPN
*/
WOLFSSL_API int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list,
                                             unsigned short *listSz);
WOLFSSL_API int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char **list);
#endif /* HAVE_ALPN */

/* Maximum Fragment Length */
#ifdef HAVE_MAX_FRAGMENT

/* Fragment lengths */
enum {
    WOLFSSL_MFL_2_9  = 1, /*  512 bytes */
    WOLFSSL_MFL_2_10 = 2, /* 1024 bytes */
    WOLFSSL_MFL_2_11 = 3, /* 2048 bytes */
    WOLFSSL_MFL_2_12 = 4, /* 4096 bytes */
    WOLFSSL_MFL_2_13 = 5  /* 8192 bytes *//* wolfSSL ONLY!!! */
};

#ifndef NO_WOLFSSL_CLIENT

/*!
    \ingroup wolfssl

    \brief This function is called on the client side to enable the use of Maximum Fragment Length in the SSL object passed in the 'ssl' parameter. It means that the Maximum Fragment Length extension will be sent on ClientHello by wolfSSL clients.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ssl is NULL, mfl is out of range.
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param mfl indicates witch is the Maximum Fragment Length requested for the session. The available options are: enum { WOLFSSL_MFL_2_9  = 1, /*  512 bytes WOLFSSL_MFL_2_10 = 2, /* 1024 bytes WOLFSSL_MFL_2_11 = 3, /* 2048 bytes WOLFSSL_MFL_2_12 = 4, /* 4096 bytes WOLFSSL_MFL_2_13 = 5  /* 8192 bytes /* wolfSSL ONLY!!! };
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
WOLFSSL_API int wolfSSL_UseMaxFragment(WOLFSSL* ssl, unsigned char mfl);
/*!
    \ingroup wolfssl

    \brief This function is called on the client side to enable the use of Maximum Fragment Length for SSL objects created from the SSL context passed in the 'ctx' parameter. It means that the Maximum Fragment Length extension will be sent on ClientHello by wolfSSL clients.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ctx is NULL, mfl is out of range.
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param mfl indicates which is the Maximum Fragment Length requested for the session. The available options are: enum { WOLFSSL_MFL_2_9  = 1, /* 512 bytes WOLFSSL_MFL_2_10 = 2, /* 1024 bytes WOLFSSL_MFL_2_11 = 3, /* 2048 bytes WOLFSSL_MFL_2_12 = 4, /* 4096 bytes WOLFSSL_MFL_2_13 = 5  /* 8192 bytes/* wolfSSL ONLY!!! };
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
WOLFSSL_API int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, unsigned char mfl);

#endif
#endif

/* Truncated HMAC */
#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_WOLFSSL_CLIENT

/*!
    \ingroup wolfssl

    \brief This function is called on the client side to enable the use of Truncated HMAC in the SSL object passed in the 'ssl' parameter. It means that the Truncated HMAC extension will be sent on ClientHello by wolfSSL clients.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ssl is NULL
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ssl pointer to a SSL object, created with wolfSSL_new()
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseTruncatedHMAC(ssl);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
WOLFSSL_API int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function is called on the client side to enable the use of Truncated HMAC for SSL objects created from the SSL context passed in the 'ctx' parameter. It means that the Truncated HMAC extension will be sent on ClientHello by wolfSSL clients.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ctx is NULL
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseTruncatedHMAC(ctx);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
WOLFSSL_API int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx);

#endif
#endif

/* Certificate Status Request */
/* Certificate Status Type */
enum {
    WOLFSSL_CSR_OCSP = 1
};

/* Certificate Status Options (flags) */
enum {
    WOLFSSL_CSR_OCSP_USE_NONCE = 0x01
};

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
#ifndef NO_WOLFSSL_CLIENT

/*!
    \ingroup wolfssl

    \brief Stapling eliminates the need to contact the CA. Stapling lowers the cost of certificate revocation check presented in OCSP.
    
    \return SSL_SUCCESS returned if TLSX_UseCertificateStatusRequest executes without error.
    \return MEMORY_E returned if there is an error with the allocation of memory.
    \return BAD_FUNC_ARG returned if there is an argument that has a NULL or otherwise unacceptable value passed into the function.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param status_type a byte type that is passed through to TLSX_UseCertificateStatusRequest() and stored in the CertificateStatusRequest structure.
    \param options a byte type that is passed through to TLSX_UseCertificateStatusRequest() and stored in the CertificateStatusRequest structure.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR2_OCSP, 
    WOLFSSL_CSR2_OCSP_USE_NONCE) != SSL_SUCCESS){ 	
	    // Failed case.
    }
    \endcode
    
    \sa TLSX_UseCertificateStatusRequest
    \sa wolfSSL_CTX_UseOCSPStapling
*/
WOLFSSL_API int wolfSSL_UseOCSPStapling(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \ingroup wolfssl

    \brief This function requests the certificate status during the handshake.
    
    \return SSL_SUCCESS returned if the function and subroutines execute without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or otherwise if a unpermitted value is passed to a subroutine.
    \return MEMORY_E returned if the function or subroutine failed to properly allocate memory.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param status_type a byte type that is passed through to TLSX_UseCertificateStatusRequest() and stored in the CertificateStatusRequest structure.
    \param options a byte type that is passed through to TLSX_UseCertificateStatusRequest() and stored in the CertificateStatusRequest structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte statusRequest = 0; // Initialize status request
    …
    switch(statusRequest){
    	case WOLFSSL_CSR_OCSP:
    		if(wolfSSL_CTX_UseOCSPStapling(ssl->ctx, WOLFSSL_CSR_OCSP, 
    WOLF_CSR_OCSP_USE_NONCE) != SSL_SUCCESS){
    // UseCertificateStatusRequest failed
    }
    // Continue switch cases
    \endcode
    
    \sa wolfSSL_UseOCSPStaplingV2
    \sa wolfSSL_UseOCSPStapling
    \sa TLSX_UseCertificateStatusRequest
*/
WOLFSSL_API int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

#endif
#endif

/* Certificate Status Request v2 */
/* Certificate Status Type */
enum {
    WOLFSSL_CSR2_OCSP = 1,
    WOLFSSL_CSR2_OCSP_MULTI = 2
};

/* Certificate Status v2 Options (flags) */
enum {
    WOLFSSL_CSR2_OCSP_USE_NONCE = 0x01
};

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
#ifndef NO_WOLFSSL_CLIENT

/*!
    \ingroup wolfssl

    \brief The function sets the status type and options for OCSP.
    
    \return SSL_SUCCESS - returned if the function and subroutines executed without error.
    \return MEMORY_E - returned if there was an allocation of memory error.
    \return BAD_FUNC_ARG - returned if a NULL or otherwise unaccepted argument was passed to the function or a subroutine.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param status_type a byte type that loads the OCSP status type.
    \param options a byte type that holds the OCSP options, set in wolfSSL_SNI_SetOptions() and wolfSSL_CTX_SNI_SetOptions().
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if (wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP_MULTI, 0) != SSL_SUCCESS){
    	// Did not execute properly. Failure case code block.
    }
    \endcode
    
    \sa TLSX_UseCertificatStatusRequestV2
    \sa wolfSSL_SNI_SetOptions
    \sa wolfSSL_CTX_SNI_SetOptions
*/
WOLFSSL_API int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \ingroup wolfssl

    \brief Creates and initializes the certificate status request for OCSP Stapling.
    
    \return SSL_SUCCESS if the function and subroutines executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or if the side variable is not client side.
    \return MEMORY_E returned if the allocation of memory failed.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param status_type a byte type that is located in the CertificatStatusRequest structure and must be either WOLFSSL_CSR2_OCSP or WOLFSSL_CSR2_OCSP_MULTI.
    \param options a byte type that will be held in CertificateStatusRequestItemV2 struct.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx  = wolfSSL_CTX_new( protocol method );
    byte status_type;
    byte options;
    ...
    if(wolfSSL_CTX_UseOCSPStaplingV2(ctx, status_type, options); != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode
    
    \sa TLSX_UseCertificateStatusRequestV2
    \sa wc_RNG_GenerateBlock
    \sa TLSX_Push
*/
WOLFSSL_API int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

#endif
#endif

/* Named Groups */
enum {
#if 0 /* Not Supported */
    WOLFSSL_ECC_SECT163K1 = 1,
    WOLFSSL_ECC_SECT163R1 = 2,
    WOLFSSL_ECC_SECT163R2 = 3,
    WOLFSSL_ECC_SECT193R1 = 4,
    WOLFSSL_ECC_SECT193R2 = 5,
    WOLFSSL_ECC_SECT233K1 = 6,
    WOLFSSL_ECC_SECT233R1 = 7,
    WOLFSSL_ECC_SECT239K1 = 8,
    WOLFSSL_ECC_SECT283K1 = 9,
    WOLFSSL_ECC_SECT283R1 = 10,
    WOLFSSL_ECC_SECT409K1 = 11,
    WOLFSSL_ECC_SECT409R1 = 12,
    WOLFSSL_ECC_SECT571K1 = 13,
    WOLFSSL_ECC_SECT571R1 = 14,
#endif
    WOLFSSL_ECC_SECP160K1 = 15,
    WOLFSSL_ECC_SECP160R1 = 16,
    WOLFSSL_ECC_SECP160R2 = 17,
    WOLFSSL_ECC_SECP192K1 = 18,
    WOLFSSL_ECC_SECP192R1 = 19,
    WOLFSSL_ECC_SECP224K1 = 20,
    WOLFSSL_ECC_SECP224R1 = 21,
    WOLFSSL_ECC_SECP256K1 = 22,
    WOLFSSL_ECC_SECP256R1 = 23,
    WOLFSSL_ECC_SECP384R1 = 24,
    WOLFSSL_ECC_SECP521R1 = 25,
    WOLFSSL_ECC_BRAINPOOLP256R1 = 26,
    WOLFSSL_ECC_BRAINPOOLP384R1 = 27,
    WOLFSSL_ECC_BRAINPOOLP512R1 = 28,
    WOLFSSL_ECC_X25519    = 29,
#ifdef WOLFSSL_TLS13
    /* Not implemented. */
    WOLFSSL_ECC_X448      = 30,

    WOLFSSL_FFDHE_2048    = 256,
    WOLFSSL_FFDHE_3072    = 257,
    WOLFSSL_FFDHE_4096    = 258,
    WOLFSSL_FFDHE_6144    = 259,
    WOLFSSL_FFDHE_8192    = 260,
#endif
};

#ifdef HAVE_SUPPORTED_CURVES
#ifndef NO_WOLFSSL_CLIENT

/*!
    \ingroup wolfssl

    \brief This function is called on the client side to enable the use of Supported Elliptic Curves Extension in the SSL object passed in the 'ssl' parameter. It means that the supported curves enabled will be sent on ClientHello by wolfSSL clients. This function can be called more than one time to enable multiple curves.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ssl is NULL, name is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param name indicates which curve will be supported for the session. The available options are: enum { WOLFSSL_ECC_SECP160R1 = 0x10, WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15, WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18, WOLFSSL_ECC_SECP521R1 = 0x19 };
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSupportedCurve
*/
WOLFSSL_API int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, unsigned short name);
/*!
    \ingroup wolfssl

    \brief This function is called on the client side to enable the use of Supported Elliptic Curves Extension for SSL objects created from the SSL context passed in the 'ctx' parameter. It means that the supported curves enabled will be sent on ClientHello by wolfSSL clients. This function can be called more than one time to enable multiple curves.
    
    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these cases: ctx is NULL, name is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.
    
    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param name indicates which curve will be supported for the session. The available options are: enum { WOLFSSL_ECC_SECP160R1 = 0x10, WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15, WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18, WOLFSSL_ECC_SECP521R1 = 0x19 };
    
    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSupportedCurve
*/
WOLFSSL_API int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           unsigned short name);

#endif
#endif

#ifdef WOLFSSL_TLS13
WOLFSSL_API int wolfSSL_UseKeyShare(WOLFSSL* ssl, unsigned short group);
WOLFSSL_API int wolfSSL_NoKeyShares(WOLFSSL* ssl);
#endif


/* Secure Renegotiation */
#ifdef HAVE_SECURE_RENEGOTIATION

/*!
    \ingroup wolfssl

    \brief This function forces secure renegotiation for the supplied WOLFSSL structure.  This is not recommended.

    \return SSL_SUCCESS Successfully set secure renegotiation.
    \return BAD_FUNC_ARG Returns error if ssl is null.
    \return MEMORY_E Returns error if unable to allocate memory for secure renegotiation.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS)
    {
        // Error setting secure renegotiation
    }
    \endcode
    
    \sa TLSX_Find
    \sa TLSX_UseSecureRenegotiation
*/
WOLFSSL_API int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function executes a secure renegotiation handshake; this is user forced as wolfSSL discourages this functionality.
    
    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure was NULL or otherwise if an unacceptable argument was passed in a subroutine.
    \return SECURE_RENEGOTIATION_E returned if there was an error with renegotiating the handshake.
    \return SSL_FATAL_ERROR returned if there was an error with the server or client configuration and the renegotiation could not be completed. See wolfSSL_negotiate().
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_Rehandshake(ssl) != SSL_SUCCESS){
	    // There was an error and the rehandshake is not successful.
    }
    \endcode
    
    \sa wolfSSL_negotiate
    \sa wc_InitSha512
    \sa wc_InitSha384
    \sa wc_InitSha256
    \sa wc_InitSha
    \sa wc_InitMd5
*/
WOLFSSL_API int wolfSSL_Rehandshake(WOLFSSL* ssl);

#endif

/* Session Ticket */
#ifdef HAVE_SESSION_TICKET

#ifndef NO_WOLFSSL_CLIENT
/*!
    \ingroup wolfssl

    \brief Force provided WOLFSSL structure to use session ticket. The constant HAVE_SESSION_TICKET should be defined and the constant NO_WOLFSSL_CLIENT should not be defined to use this function.
    
    \return SSL_SUCCESS Successfully set use session ticket.
    \return BAD_FUNC_ARG Returned if ssl is null.
    \return MEMORY_E Error allocating memory for setting session ticket.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSessionTicket(ssl) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode
    
    \sa TLSX_UseSessionTicket
*/
WOLFSSL_API int wolfSSL_UseSessionTicket(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function sets wolfSSL context to use a session ticket.
    
    \return SSL_SUCCESS Function executed successfully.
    \return BAD_FUNC_ARG Returned if ctx is null.
    \return MEMORY_E Error allocating memory in internal function.
    
    \param ctx The WOLFSSL_CTX structure to use.
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL_METHOD method = // Some wolfSSL method ;
    ctx = wolfSSL_CTX_new(method);

    if(wolfSSL_CTX_UseSessionTicket(ctx) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode
    
    \sa TLSX_UseSessionTicket
*/
WOLFSSL_API int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);
/*!
    \ingroup wolfssl

    \brief This function copies the ticket member of the Session structure to the buffer.
    
    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if one of the arguments was NULL or if the bufSz argument was 0.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a byte pointer representing the memory buffer.
    \param bufSz a word32 pointer representing the buffer size.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buf;
    word32 bufSz;  // Initialize with buf size
    …
    if(wolfSSL_get_SessionTicket(ssl, buf, bufSz) <= 0){
	    // Nothing was written to the buffer
    } else {
	    // the buffer holds the content from ssl->session.ticket
    }
    \endcode
    
    \sa wolfSSL_UseSessionTicket
    \sa wolfSSL_set_SessionTicket
*/
WOLFSSL_API int wolfSSL_get_SessionTicket(WOLFSSL*, unsigned char*, unsigned int*);
/*!
    \ingroup wolfssl

    \brief This function sets the ticket member of the WOLFSSL_SESSION structure within the WOLFSSL struct. The buffer passed into the function is copied to memory.
    
    \return SSL_SUCCESS returned on successful execution of the function. The function returned without errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL. This will also be thrown if the buf argument is NULL but the bufSz argument is not zero.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a byte pointer that gets loaded into the ticket member of the session structure.
    \param bufSz a word32 type that represents the size of the buffer.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buffer; // File to load
    word32 bufSz;
    ...
    if(wolfSSL_KeepArrays(ssl, buffer, bufSz) != SSL_SUCCESS){
    	// There was an error loading the buffer to memory.
    }
    \endcode
    
    \sa wolfSSL_set_SessionTicket_cb
*/
WOLFSSL_API int wolfSSL_set_SessionTicket(WOLFSSL*, const unsigned char*, unsigned int);
typedef int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*);
/*!
    \ingroup wolfssl

    \brief This function sets the session ticket callback. The type CallbackSessionTicket is a function pointer with the signature of:	int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*)
    
    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to the type CallbackSessionTicket.
    \param ctx a void pointer to the session_ticket_ctx member of the WOLFSSL structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int sessionTicketCB(WOLFSSL* ssl, const unsigned char* ticket, int ticketSz,
				void* ctx){ … }
    wolfSSL_set_SessionTicket_cb(ssl, sessionTicketCB, (void*)”initial session”);
    \endcode
    
    \sa wolfSSL_set_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
*/
WOLFSSL_API int wolfSSL_set_SessionTicket_cb(WOLFSSL*,
                                                  CallbackSessionTicket, void*);
#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER

#define WOLFSSL_TICKET_NAME_SZ 16
#define WOLFSSL_TICKET_IV_SZ   16
#define WOLFSSL_TICKET_MAC_SZ  32

enum TicketEncRet {
    WOLFSSL_TICKET_RET_FATAL  = -1,  /* fatal error, don't use ticket */
    WOLFSSL_TICKET_RET_OK     =  0,  /* ok, use ticket */
    WOLFSSL_TICKET_RET_REJECT,       /* don't use ticket, but not fatal */
    WOLFSSL_TICKET_RET_CREATE        /* existing ticket ok and create new one */
};

typedef int (*SessionTicketEncCb)(WOLFSSL*,
                                 unsigned char key_name[WOLFSSL_TICKET_NAME_SZ],
                                 unsigned char iv[WOLFSSL_TICKET_IV_SZ],
                                 unsigned char mac[WOLFSSL_TICKET_MAC_SZ],
                                 int enc, unsigned char*, int, int*, void*);
/*!
    \ingroup wolfssl

    \brief This function sets the session ticket key encrypt callback function for a server to support session tickets as specified in RFC 5077.
    
    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure. This is caused by passing invalid arguments to the function.
    
    \param ctx pointer to the WOLFSSL_CTX object, created with wolfSSL_CTX_new().
    \param cb user callback function to encrypt/decrypt session tickets
    \param ssl(Callback) pointer to the WOLFSSL object, created with wolfSSL_new()
    \param key_name(Callback) unique key name for this ticket context, should be randomly generated
    \param iv(Callback) unique IV for this ticket, up to 128 bits, should be randomly generated
    \param mac(Callback) up to 256 bit mac for this ticket
    \param enc(Callback) if this encrypt parameter is true the user should fill in key_name, iv, mac, and encrypt the ticket in-place of length inLen and set the resulting output length in *outLen.  Returning WOLFSSL_TICKET_RET_OK tells wolfSSL that the encryption was successful. If this encrypt parameter is false, the user should perform a decrypt of the ticket in-place of length inLen using key_name, iv, and mac. The resulting decrypt length should be set in *outLen. Returning WOLFSSL_TICKET_RET_OK tells wolfSSL to proceed using the decrypted ticket. Returning WOLFSSL_TICKET_RET_CREATE tells wolfSSL to use the decrypted ticket but also to generate a new one to send to the client, helpful if recently rolled keys and don’t want to force a full handshake.  Returning WOLFSSL_TICKET_RET_REJECT tells wolfSSL to reject this ticket, perform a full handshake, and create a new standard session ID for normal session resumption. Returning WOLFSSL_TICKET_RET_FATAL tells wolfSSL to end the connection attempt with a fatal error.
    \param ticket(Callback) the input/output buffer for the encrypted ticket. See the enc parameter
    \param inLen(Callback) the input length of the ticket parameter
    \param outLen(Callback) the resulting output length of the ticket parameter. When entering the callback outLen will indicate the maximum size available in the ticket buffer.
    \param userCtx(Callback) the user context set with wolfSSL_CTX_set_TicketEncCtx()
    
    _Example_
    \code
    See wolfssl/test.h myTicketEncCb() used by the example server and example echoserver.
    \endcode
    
    \sa wolfSSL_CTX_set_TicketHint
    \sa wolfSSL_CTX_set_TicketEncCtx
*/
WOLFSSL_API int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb);
/*!
    \ingroup wolfssl

    \brief This function sets the session ticket hint relayed to the client.  For server side use.
    
    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure.  This is caused by passing invalid arguments to the function.
    
    \param ctx pointer to the WOLFSSL_CTX object, created with wolfSSL_CTX_new().
    \param hint number of seconds the ticket might be valid for.  Hint to client.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_set_TicketEncCb
*/
WOLFSSL_API int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int);
/*!
    \ingroup wolfssl

    \brief This function sets the session ticket encrypt user context for the callback.  For server side use.
    
    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure.  This is caused by passing invalid arguments to the function.
    
    \param ctx pointer to the WOLFSSL_CTX object, created with wolfSSL_CTX_new().
    \param userCtx the user context for the callback
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_CTX_set_TicketEncCb
*/
WOLFSSL_API int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void*);

#endif /* NO_WOLFSSL_SERVER */

#endif /* HAVE_SESSION_TICKET */

#ifdef HAVE_QSH
/* Quantum-safe Crypto Schemes */
enum {
    WOLFSSL_NTRU_EESS439 = 0x0101, /* max plaintext length of 65  */
    WOLFSSL_NTRU_EESS593 = 0x0102, /* max plaintext length of 86  */
    WOLFSSL_NTRU_EESS743 = 0x0103, /* max plaintext length of 106 */
    WOLFSSL_LWE_XXX  = 0x0201,     /* Learning With Error encryption scheme */
    WOLFSSL_HFE_XXX  = 0x0301,     /* Hidden Field Equation scheme */
    WOLFSSL_NULL_QSH = 0xFFFF      /* QSHScheme is not used */
};


/* test if the connection is using a QSH secure connection return 1 if so */
/*!
    \ingroup wolfssl

    \brief Checks if QSH is used in the supplied SSL session.
    
    \return 0 Not used
    \return 1 Is used
    
    \param ssl Pointer to the SSL session to check.
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_isQSH(ssl) == 1)
    {
        // SSL is using QSH. 
    }
    \endcode
    
    \sa wolfSSL_UseSupportedQSH
*/
WOLFSSL_API int wolfSSL_isQSH(WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function sets the ssl session to use supported QSH provided by name.
    
    \return SSL_SUCCESS Successfully set supported QSH.
    \return BAD_FUNC_ARG ssl is null or name is invalid.
    \return MEMORY_E Error allocating memory for operation.
    
    \param ssl Pointer to ssl session to use.
    \param name Name of a supported QSH.  Valid names are WOLFSSL_NTRU_EESS439, WOLFSSL_NTRU_EESS593, or WOLFSSL_NTRU_EESS743.
    
    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method ;
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    word16 qsh_name = WOLFSSL_NTRU_EESS439;

    if(wolfSSL_UseSupportedQSH(ssl,qsh_name) != SSL_SUCCESS)
    {
        // Error setting QSH
    }
    \endcode
    
    \sa TLSX_UseQSHScheme
*/
WOLFSSL_API int wolfSSL_UseSupportedQSH(WOLFSSL* ssl, unsigned short name);
#ifndef NO_WOLFSSL_CLIENT
    /* user control over sending client public key in hello
       when flag = 1 will send keys if flag is 0 or function is not called
       then will not send keys in the hello extension */
/*!
    \ingroup wolfssl

    \brief If the flag is 1 keys will be sent in hello. If flag is 0 then the keys will not be sent during hello.
    
    \return 0 on success.
    \return BAD_FUNC_ARG if the WOLFSSL structure is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param flag an unsigned char input to determine if the keys will be sent during hello.
    
    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char flag = 1; // send keys
    ...
    if(!wolfSSL_UseClientQSHKeys(ssl, flag)){
    	// The keys will be sent during hello.
    }
    \endcode
    
    \sa wolfSSL_UseALPN
    \sa wolfSSL_UseSupportedQSH
    \sa wolfSSL_isQSH
*/
    WOLFSSL_API int wolfSSL_UseClientQSHKeys(WOLFSSL* ssl, unsigned char flag);
#endif

#endif /* QSH */

/* TLS Extended Master Secret Extension */
WOLFSSL_API int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx);


#define WOLFSSL_CRL_MONITOR   0x01   /* monitor this dir flag */
#define WOLFSSL_CRL_START_MON 0x02   /* start monitoring flag */


/* notify user the handshake is done */
typedef int (*HandShakeDoneCb)(WOLFSSL*, void*);
/*!
    \ingroup wolfssl

    \brief This function sets the handshake done callback. The hsDoneCb and hsDoneCtx members of the WOLFSSL structure are set in this function.
    
    \return SSL_SUCCESS returned if the function executed without an error. The hsDoneCb and hsDoneCtx members of the WOLFSSL struct are set.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer of type HandShakeDoneCb with the signature of the form: int (*HandShakeDoneCb)(WOLFSSL*, void*);
    \param user_ctx a void pointer to the user registered context.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int myHsDoneCb(WOLFSSL* ssl, void* user_ctx){
        // callback function
    }
    …
    wolfSSL_SetHsDoneCb(ssl, myHsDoneCb, NULL);
    \endcode
    
    \sa HandShakeDoneCb
*/
WOLFSSL_API int wolfSSL_SetHsDoneCb(WOLFSSL*, HandShakeDoneCb, void*);


/*!
    \ingroup wolfssl

    \brief This function prints the statistics from the session.
    
    \return SSL_SUCCESS returned if the function and subroutines return without error. The session stats have been successfully retrieved and printed.
    \return BAD_FUNC_ARG returned if the subroutine wolfSSL_get_session_stats() was passed an unacceptable argument.
    \return BAD_MUTEX_E returned if there was a mutex error in the subroutine.
    
    \param none No parameters.
    
    _Example_
    \code
    // You will need to have a session object to retrieve stats from.
    if(wolfSSL_PrintSessionStats(void) != SSL_SUCCESS	){
        // Did not print session stats
    }

    \endcode
    
    \sa wolfSSL_get_session_stats
*/
WOLFSSL_API int wolfSSL_PrintSessionStats(void);
/*!
    \ingroup wolfssl

    \brief This function gets the statistics for the session.
    
    \return SSL_SUCCESS returned if the function and subroutines return without error. The session stats have been successfully retrieved and printed.
    \return BAD_FUNC_ARG returned if the subroutine wolfSSL_get_session_stats() was passed an unacceptable argument.
    \return BAD_MUTEX_E returned if there was a mutex error in the subroutine.
    
    \param active a word32 pointer representing the total current sessions.
    \param total a word32 pointer representing the total sessions.
    \param peak a word32 pointer representing the peak sessions.
    \param maxSessions a word32 pointer representing the maximum sessions.
    
    _Example_
    \code
    int wolfSSL_PrintSessionStats(void){
    …
    ret = wolfSSL_get_session_stats(&totalSessionsNow, &totalSessionsSeen, &peak,
&maxSessions);
    …
    return ret;
    \endcode
    
    \sa get_locked_session_stats
    \sa wolfSSL_PrintSessionStats
*/
WOLFSSL_API int wolfSSL_get_session_stats(unsigned int* active,
                                          unsigned int* total,
                                          unsigned int* peak,
                                          unsigned int* maxSessions);
/* External facing KDF */
/*!
    \ingroup wolfssl

    \brief This function copies the values of cr and sr then passes through to PRF (pseudo random function) and returns that value.
    
    \return 0 on success
    \return BUFFER_E returned if there will be an error with the size of the buffer.
    \return MEMORY_E returned if a subroutine failed to allocate dynamic memory.
    
    \param ms the master secret held in the Arrays structure.
    \param msLen the length of the master secret.
    \param pms the pre-master secret held in the Arrays structure.
    \param pmsLen the length of the pre-master secret.
    \param cr the client random.
    \param sr the server random.
    \param tls1_2 signifies that the version is at least tls version 1.2.
    \param hash_type signifies the hash type.
    
    _Example_
    \code
    WOLFSSL* ssl;

    called in MakeTlsMasterSecret and retrieves the necessary information as follows:

    int MakeTlsMasterSecret(WOLFSSL* ssl){
	int ret;
	ret = wolfSSL_makeTlsMasterSecret(ssl->arrays->masterSecret, SECRET_LEN,
    ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
    ssl->arrays->clientRandom, ssl->arrays->serverRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    return ret;

    }
    \endcode
    
    \sa PRF
    \sadoPRF
    \sa p_hash
    \sa MakeTlsMasterSecret
*/
WOLFSSL_API
int wolfSSL_MakeTlsMasterSecret(unsigned char* ms, unsigned int msLen,
                               const unsigned char* pms, unsigned int pmsLen,
                               const unsigned char* cr, const unsigned char* sr,
                               int tls1_2, int hash_type);

WOLFSSL_API
int wolfSSL_MakeTlsExtendedMasterSecret(unsigned char* ms, unsigned int msLen,
                              const unsigned char* pms, unsigned int pmsLen,
                              const unsigned char* sHash, unsigned int sHashLen,
                              int tls1_2, int hash_type);

/*!
    \ingroup wolfssl

    \brief An external facing wrapper to derive TLS Keys.
    
    \return 0 returned on success.
    \return BUFFER_E returned if the sum of labLen and seedLen (computes total size) exceeds the maximum size.
    \return MEMORY_E returned if the allocation of memory failed.
    
    \param key_data a byte pointer that is allocateded in DeriveTlsKeys and passed through to PRF to hold the final hash.
    \param keyLen a word32 type that is derived in DeriveTlsKeys from the WOLFSSL structure’s specs member.
    \param ms a constant pointer type holding the master secret held in the arrays structure within the WOLFSSL structure.
    \param msLen a word32 type that holds the length of the master secret in an enumerated define, SECRET_LEN.
    \param sr a constant byte pointer to the serverRandom member of the arrays structure within the WOLFSSL structure.
    \param cr a constant byte pointer to the clientRandom member of the arrays structure within the WOLFSSL structure.
    \param tls1_2 an integer type returned from IsAtLeastTLSv1_2().
    \param hash_type an integer type held in the WOLFSSL structure.
    
    _Example_
    \code
    int DeriveTlsKeys(WOLFSSL* ssl){
    int ret;
    …
    ret = wolfSSL_DeriveTlsKeys(key_data, length, ssl->arrays->masterSecret,
    SECRET_LEN, ssl->arrays->clientRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    }
    \endcode
    
    \sa PRF
    \sa doPRF
    \sa DeriveTlsKeys
    \sa IsAtLeastTLSv1_2
*/
WOLFSSL_API
int wolfSSL_DeriveTlsKeys(unsigned char* key_data, unsigned int keyLen,
                               const unsigned char* ms, unsigned int msLen,
                               const unsigned char* sr, const unsigned char* cr,
                               int tls1_2, int hash_type);

#ifdef WOLFSSL_CALLBACKS

/* used internally by wolfSSL while OpenSSL types aren't */
#include <wolfssl/callbacks.h>

typedef int (*HandShakeCallBack)(HandShakeInfo*);
typedef int (*TimeoutCallBack)(TimeoutInfo*);

/* wolfSSL connect extension allowing HandShakeCallBack and/or TimeoutCallBack
   for diagnostics */
/*!
    \ingroup wolfssl

    \brief wolfSSL_connect_ex() is an extension that allows a HandShake Callback to be set.  This can be useful in embedded systems for debugging support when a debugger isn’t available and sniffing is impractical.  The HandShake Callback will be called whether or not a handshake error occurred.  No dynamic memory is used since the maximum number of SSL packets is known.  Packet names can be accessed through packetNames[]. The connect extension also allows a Timeout Callback to be set along with a timeout value.  This is useful if the user doesn’t want to wait for the TCP stack to timeout. This extension can be called with either, both, or neither callbacks.
    
    \return SSL_SUCCESS upon success.
    \return GETTIME_ERROR will be returned if gettimeofday() encountered an error.
    \return SETITIMER_ERROR will be returned if setitimer() encountered an error.
    \return SIGACT_ERROR will be returned if sigaction() encountered an error.
    \return SSL_FATAL_ERROR will be returned if the underlying SSL_connect() call encountered an error.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_accept_ex
*/
WOLFSSL_API int wolfSSL_connect_ex(WOLFSSL*, HandShakeCallBack, TimeoutCallBack,
                                 Timeval);
/*!
    \ingroup wolfssl

    \brief wolfSSL_accept_ex() is an extension that allows a HandShake Callback to be set.  This can be useful in embedded systems for debugging support when a debugger isn’t available and sniffing is impractical.  The HandShake Callback will be called whether or not a handshake error occurred.  No dynamic memory is used since the maximum number of SSL packets is known.  Packet names can be accessed through packetNames[]. The connect extension also allows a Timeout Callback to be set along with a timeout value.  This is useful if the user doesn’t want to wait for the TCP stack to timeout. This extension can be called with either, both, or neither callbacks.
    
    \return SSL_SUCCESS upon success.
    \return GETTIME_ERROR will be returned if gettimeofday() encountered an error.
    \return SETITIMER_ERROR will be returned if setitimer() encountered an error.
    \return SIGACT_ERROR will be returned if sigaction() encountered an error.
    \return SSL_FATAL_ERROR will be returned if the underlying SSL_accept() call encountered an error.
    
    \param none No parameters.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wolfSSL_connect_ex
*/
WOLFSSL_API int wolfSSL_accept_ex(WOLFSSL*, HandShakeCallBack, TimeoutCallBack,
                                Timeval);

#endif /* WOLFSSL_CALLBACKS */


#ifdef WOLFSSL_HAVE_WOLFSCEP
    WOLFSSL_API void wolfSSL_wolfSCEP(void);
#endif /* WOLFSSL_HAVE_WOLFSCEP */

#ifdef WOLFSSL_HAVE_CERT_SERVICE
    WOLFSSL_API void wolfSSL_cert_service(void);
#endif

#if defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
WOLFSSL_API char* wolfSSL_ASN1_TIME_to_string(WOLFSSL_ASN1_TIME* time,
                                                            char* buf, int len);
#endif /* WOLFSSL_MYSQL_COMPATIBLE */

#ifdef OPENSSL_EXTRA

#ifndef NO_FILESYSTEM
/*!
    \ingroup wolfssl

    \brief This is used to set the internal file pointer for a BIO.
    
    \return SSL_SUCCESS On successfully setting file pointer.
    \return SSL_FAILURE If an error case was encountered.
    
    \param bio WOLFSSL_BIO structure to set pair.
    \param fp file pointer to set in bio.
    \param c close file behavior flag.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, fp, BIO_CLOSE);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_get_fp
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c);
/*!
    \ingroup wolfssl

    \brief This is used to get the internal file pointer for a BIO.
    
    \return SSL_SUCCESS On successfully getting file pointer.
    \return SSL_FAILURE If an error case was encountered.
    
    \param bio WOLFSSL_BIO structure to set pair.
    \param fp file pointer to set in bio.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_get_fp(bio, &fp);
    // check ret value
    \endcode
    
    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
WOLFSSL_API long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp);
#endif

WOLFSSL_API unsigned long wolfSSL_ERR_peek_last_error_line(const char **file, int *line);
WOLFSSL_API long wolfSSL_ctrl(WOLFSSL* ssl, int cmd, long opt, void* pt);
WOLFSSL_API long wolfSSL_CTX_ctrl(WOLFSSL_CTX* ctx, int cmd, long opt,void* pt);

#ifndef NO_CERTS
/*!
    \ingroup wolfssl

    \brief This function checks that the private key is a match with the certificate being used.
    
    \return SSL_SUCCESS On successfully match.
    \return SSL_FAILURE If an error case was encountered.
    \return <0 All error cases other than SSL_FAILURE are negative values.

    \param ssl WOLFSSL structure to check.
    
    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create and set up ssl
    ret  = wolfSSL_check_private_key(ssl);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API int wolfSSL_check_private_key(const WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function looks for and returns the extension matching the passed in NID value.
    
    \return pointer If successful a STACK_OF(WOLFSSL_ASN1_OBJECT) pointer is returned.
    \return NULL If extension is not found or error is encountered.
    
    \param x509 certificate to get parse through for extension.
    \param nid extension OID to be found.
    \param c if not NULL is set to -2 for multiple extensions found -1 if not found, 0 if found and not critical and 1 if found and critical.
    \param idx if NULL return first extension matched otherwise if not stored in x509 start at idx.
    
    _Example_
    \code
    const WOLFSSL_X509* x509;
    int c;
    int idx = 0;
    STACK_OF(WOLFSSL_ASN1_OBJECT)* sk;

    sk = wolfSSL_X509_get_ext_d2i(x509, NID_basic_constraints, &c, &idx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode
    
    \sa wolfSSL_sk_ASN1_OBJECT_free
*/
WOLFSSL_API void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509,
                                                     int nid, int* c, int* idx);
/*!
    \ingroup wolfssl

    \brief This function returns the hash of the DER certificate.
    
    \return SSL_SUCCESS On successfully creating a hash.
    \return SSL_FAILURE Returned on bad input or unsuccessful hash.
    
    \param x509 certificate to get the hash of.
    \param digest the hash algorithm to use.
    \param buf buffer to hold hash.
    \param len length of buffer.
    
    _Example_
    \code
    WOLFSSL_X509* x509;
    unsigned char buffer[64];
    unsigned int bufferSz;
    int ret;

    ret = wolfSSL_X509_digest(x509, wolfSSL_EVP_sha256(), buffer, &bufferSz);
    //check ret value
    \endcode
    
    \sa none
*/
WOLFSSL_API int wolfSSL_X509_digest(const WOLFSSL_X509* x509,
        const WOLFSSL_EVP_MD* digest, unsigned char* buf, unsigned int* len);
/*!
    \ingroup wolfssl

    \brief his is used to set the certificate for WOLFSSL structure to use during a handshake.
    
    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL argument passed in.
    
    \param ssl WOLFSSL structure to set certificate in.
    \param x509 certificate to use.
    
    _Example_
    \code WOLFSSL* ssl;
    WOLFSSL_X509* x509
    int ret;
    // create ssl object and x509
    ret  = wolfSSL_use_certificate(ssl, x509);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API int wolfSSL_use_certificate(WOLFSSL* ssl, WOLFSSL_X509* x509);
/*!
    \ingroup wolfssl

    \brief This is used to set the certificate for WOLFSSL structure to use during a handshake. A DER formatted buffer is expected.
    
    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL argument passed in.
    
    \param ssl WOLFSSL structure to set certificate in.
    \param der DER certificate to use.
    \param derSz size of the DER buffer passed in.
    
    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* der;
    int derSz;
    int ret;
    // create ssl object and set DER variables
    ret  = wolfSSL_use_certificate_ASN1(ssl, der, derSz);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                     int derSz);
/*!
    \ingroup wolfssl

    \brief This is used to set the private key for the WOLFSSL structure.
    
    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL ssl passed in. All error cases will be negative values.
    
    \param ssl WOLFSSL structure to set argument in.
    \param pkey private key to use.
    
    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_EVP_PKEY* pkey;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey(ssl, pkey);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/                                                                     
WOLFSSL_API int wolfSSL_use_PrivateKey(WOLFSSL* ssl, WOLFSSL_EVP_PKEY* pkey);
/*!
    \ingroup wolfssl

    \brief This is used to set the private key for the WOLFSSL structure. A DER formatted key buffer is expected.
    
    \return SSL_SUCCESS On successful setting parsing and setting the private key.
    \return SSL_FAILURE If an NULL ssl passed in. All error cases will be negative values.
    
    \param pri type of private key.
    \param ssl WOLFSSL structure to set argument in.
    \param der buffer holding DER key.
    \param derSz size of der buffer.
    
    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey_ASN1(1, ssl, pkey, pkeySz);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
WOLFSSL_API int wolfSSL_use_PrivateKey_ASN1(int pri, WOLFSSL* ssl,
                                            unsigned char* der, long derSz);
WOLFSSL_API WOLFSSL_EVP_PKEY *wolfSSL_get_privatekey(const WOLFSSL *ssl);
#ifndef NO_RSA
/*!
    \ingroup wolfssl

    \brief This is used to set the private key for the WOLFSSL structure. A DER formatted RSA key buffer is expected.
    
    \return SSL_SUCCESS On successful setting parsing and setting the private key.
    \return SSL_FAILURE If an NULL ssl passed in. All error cases will be negative values.
    
    \param ssl WOLFSSL structure to set argument in.
    \param der buffer holding DER key.
    \param derSz size of der buffer.
    
    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up RSA private key
    ret  = wolfSSL_use_RSAPrivateKey_ASN1(ssl, pkey, pkeySz);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
WOLFSSL_API int wolfSSL_use_RSAPrivateKey_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                long derSz);
#endif
#endif /* NO_CERTS */

/*!
    \ingroup wolfssl

    \brief This function duplicates the parameters in dsa to a newly created WOLFSSL_DH structure.
    
    \return WOLFSSL_DH If duplicated returns WOLFSSL_DH structure
    \return NULL upon failure
    
    \param dsa WOLFSSL_DSA structure to duplicate.
    
    _Example_
    \code
    WOLFSSL_DH* dh;
    WOLFSSL_DSA* dsa;
    // set up dsa
    dh = wolfSSL_DSA_dup_DH(dsa);

    // check dh is not null
    \endcode
    
    \sa none
*/
WOLFSSL_API WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *r);

/*!
    \ingroup wolfssl

    \brief This is used to get the master key after completing a handshake.
    
    \return >0 On successfully getting data returns a value greater than 0
    \return 0  If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer size needed is returned
    
    \param ses WOLFSSL_SESSION structure to get master secret buffer from.
    \param out buffer to hold data.
    \param outSz size of out buffer passed in. (if 0 function will return max buffer size needed)
    
    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret(ses, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_SESSION_get_master_secret(ses, buffer, bufferSz);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API int wolfSSL_SESSION_get_master_key(const WOLFSSL_SESSION* ses,
        unsigned char* out, int outSz);
/*!
    \ingroup wolfssl

    \brief This is used to get the master secret key length.
    
    \return size Returns master secret key size.
    
    \param ses WOLFSSL_SESSION structure to get master secret buffer from.
    
    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret_length(ses);
    buffer = malloc(bufferSz);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API int wolfSSL_SESSION_get_master_key_length(const WOLFSSL_SESSION* ses);

/*!
    \ingroup wolfssl

    \brief This is a setter function for the WOLFSSL_X509_STORE structure in ctx.
    
    \return none No return.
    
    \param ctx pointer to the WOLFSSL_CTX structure for setting cert store pointer.
    \param str pointer to the WOLFSSL_X509_STORE to set in ctx.
    
    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx and st
    st = wolfSSL_CTX_set_cert_store(ctx, st);
    //use st
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);
/*!
    \ingroup wolfssl

    \brief This function get the DER buffer from bio and converts it to a WOLFSSL_X509 structure.
    
    \return pointer returns a WOLFSSL_X509 structure pointer on success.
    \return Null returns NULL on failure
    
    \param bio pointer to the WOLFSSL_BIO structure that has the DER certificate buffer.
    \param x509 pointer that get set to new WOLFSSL_X509 structure created.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // load DER into bio
    x509 = wolfSSL_d2i_X509_bio(bio, NULL);
    Or
    wolfSSL_d2i_X509_bio(bio, &x509);
    // use x509 returned (check for NULL)
    \endcode
    
    \sa none
*/
WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509** x509);
/*!
    \ingroup wolfssl

    \brief This is a getter function for the WOLFSSL_X509_STORE structure in ctx.
    
    \return WOLFSSL_X509_STORE* On successfully getting the pointer.
    \return NULL Returned if NULL arguments are passed in.
    
    \param ctx pointer to the WOLFSSL_CTX structure for getting cert store pointer.
    
    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx
    st = wolfSSL_CTX_get_cert_store(ctx);
    //use st
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_cert_store
*/
WOLFSSL_API WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(WOLFSSL_CTX* ctx);

/*!
    \ingroup wolfssl

    \brief Gets the number of pending bytes to read. If BIO type is BIO_BIO then is the number to read from pair. If BIO contains an SSL object then is pending data from SSL object (wolfSSL_pending(ssl)). If is BIO_MEMORY type then returns the size of memory buffer.
    
    \return >=0 number of pending bytes.
    
    \param bio pointer to the WOLFSSL_BIO structure that has already been created.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    int pending;
    bio = wolfSSL_BIO_new();
    …
    pending = wolfSSL_BIO_ctrl_pending(bio);
    \endcode
    
    \sa wolfSSL_BIO_make_bio_pair
    \sa wolfSSL_BIO_new
*/
WOLFSSL_API size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *b);
/*!
    \ingroup wolfssl

    \brief This is used to get the random data sent by the server during the handshake.
    
    \return >0 On successfully getting data returns a value greater than 0
    \return 0  If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer size needed is returned
    
    \param ssl WOLFSSL structure to get clients random data buffer from.
    \param out buffer to hold random data.
    \param outSz size of out buffer passed in. (if 0 function will return max buffer size needed)
    
    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_server_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_server_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API size_t wolfSSL_get_server_random(const WOLFSSL *ssl,
                                             unsigned char *out, size_t outlen);
/*!
    \ingroup wolfssl

    \brief This is used to get the random data sent by the client during the handshake.
    
    \return >0 On successfully getting data returns a value greater than 0
    \return 0 If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer size needed is returned
    
    \param ssl WOLFSSL structure to get clients random data buffer from.
    \param out buffer to hold random data.
    \param outSz size of out buffer passed in. (if 0 function will return max buffer size needed)
    
    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_client_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_client_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode
    
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API size_t wolfSSL_get_client_random(const WOLFSSL* ssl,
                                              unsigned char* out, size_t outSz);
/*!
    \ingroup wolfssl

    \brief This is a getter function for the password callback set in ctx.
    
    \return func On success returns the callback function.
    \return NULL If ctx is NULL then NULL is returned.
    
    \param ctx WOLFSSL_CTX structure to get call back from.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    Pem_password_cb cb;
    // setup ctx
    cb = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use cb
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX *ctx);
/*!
    \ingroup wolfssl

    \brief This is a getter function for the password callback user data set in ctx.
    
    \return pointer On success returns the user data pointer.
    \return NULL If ctx is NULL then NULL is returned.
    
    \param ctx WOLFSSL_CTX structure to get user data from.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    // setup ctx
    data = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use data
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_API void *wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx);
WOLFSSL_API int wolfSSL_CTX_use_PrivateKey(WOLFSSL_CTX *ctx, WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509(WOLFSSL_BIO *bp, WOLFSSL_X509 **x, pem_password_cb *cb, void *u);
/*!
    \ingroup wolfssl

    \brief This function behaves the same as wolfSSL_PEM_read_bio_X509. AUX signifies containing extra information such as trusted/rejected use cases and friendly name for human readability.
    
    \return WOLFSSL_X509 on successfully parsing the PEM buffer a WOLFSSL_X509 structure is returned.
    \return Null if failed to parse PEM buffer.
    
    \param bp WOLFSSL_BIO structure to get PEM buffer from.
    \param x if setting WOLFSSL_X509 by function side effect.
    \param cb password callback.
    \param u NULL terminated user password.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // setup bio
    X509 = wolfSSL_PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    //check x509 is not null and then use it
    \endcode
    
    \sa wolfSSL_PEM_read_bio_X509
*/
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_AUX
        (WOLFSSL_BIO *bp, WOLFSSL_X509 **x, pem_password_cb *cb, void *u);

/*lighttp compatibility */

#include <wolfssl/openssl/asn1.h>
struct WOLFSSL_X509_NAME_ENTRY {
    WOLFSSL_ASN1_OBJECT* object; /* not defined yet */
    WOLFSSL_ASN1_STRING  data;
    WOLFSSL_ASN1_STRING* value;  /* points to data, for lighttpd port */
    int set;
    int size;
};

#if defined(HAVE_LIGHTY) || defined(WOLFSSL_MYSQL_COMPATIBLE) \
                         || defined(HAVE_STUNNEL) \
                         || defined(WOLFSSL_NGINX) \
                         || defined(WOLFSSL_HAPROXY) \
                         || defined(OPENSSL_EXTRA)
WOLFSSL_API void wolfSSL_X509_NAME_free(WOLFSSL_X509_NAME *name);
WOLFSSL_API char wolfSSL_CTX_use_certificate(WOLFSSL_CTX *ctx, WOLFSSL_X509 *x);
WOLFSSL_API int wolfSSL_BIO_read_filename(WOLFSSL_BIO *b, const char *name);
/* These are to be merged shortly */
WOLFSSL_API const char *  wolfSSL_OBJ_nid2sn(int n);
WOLFSSL_API int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o);
WOLFSSL_API int wolfSSL_OBJ_sn2nid(const char *sn);
WOLFSSL_API void wolfSSL_CTX_set_verify_depth(WOLFSSL_CTX *ctx,int depth);
WOLFSSL_API void wolfSSL_set_verify_depth(WOLFSSL *ssl,int depth);
WOLFSSL_API void* wolfSSL_get_app_data( const WOLFSSL *ssl);
WOLFSSL_API int wolfSSL_set_app_data(WOLFSSL *ssl, void *arg);
WOLFSSL_API WOLFSSL_ASN1_OBJECT * wolfSSL_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY *ne);
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY *wolfSSL_X509_NAME_get_entry(WOLFSSL_X509_NAME *name, int loc);
WOLFSSL_API void wolfSSL_sk_X509_NAME_pop_free(STACK_OF(WOLFSSL_X509_NAME)* sk, void f (WOLFSSL_X509_NAME*));
WOLFSSL_API unsigned char *wolfSSL_SHA1(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API int wolfSSL_X509_check_private_key(WOLFSSL_X509*, WOLFSSL_EVP_PKEY*);
WOLFSSL_API STACK_OF(WOLFSSL_X509_NAME) *wolfSSL_dup_CA_list( STACK_OF(WOLFSSL_X509_NAME) *sk );

/* end lighttpd*/
#endif
#endif

#if defined(HAVE_STUNNEL) || defined(HAVE_LIGHTY) \
                          || defined(WOLFSSL_MYSQL_COMPATIBLE) \
                          || defined(WOLFSSL_HAPROXY) \
                          || defined(OPENSSL_EXTRA)

WOLFSSL_API char* wolfSSL_OBJ_nid2ln(int n);
WOLFSSL_API int wolfSSL_OBJ_txt2nid(const char *sn);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_file(const char *filename, const char *mode);
/*!
    \ingroup wolfssl

    \brief Initializes the WOLFSSL_CTX structure’s dh member with the Diffie-Hellman parameters.
    
    \return SSL_SUCCESS returned if the function executed successfully.
    \return BAD_FUNC_ARG returned if the ctx or dh structures are NULL.
    \return SSL_FATAL_ERROR returned if there was an error setting a structure value.
    \return MEMORY_E returned if their was a failure to allocate memory.
    
    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param dh a pointer to a WOLFSSL_DH structure.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL_DH* dh;
    …
    return wolfSSL_CTX_set_tmp_dh(ctx, dh);
    \endcode
    
    \sa wolfSSL_BN_bn2bin
*/
WOLFSSL_API long wolfSSL_CTX_set_tmp_dh(WOLFSSL_CTX*, WOLFSSL_DH*);
WOLFSSL_API WOLFSSL_DH *wolfSSL_PEM_read_bio_DHparams(WOLFSSL_BIO *bp,
    WOLFSSL_DH **x, pem_password_cb *cb, void *u);
/*!
    \ingroup wolfssl

    \brief This function get the DSA parameters from a PEM buffer in bio.
    
    \return WOLFSSL_DSA on successfully parsing the PEM buffer a WOLFSSL_DSA structure is created and returned. 
    \return Null if failed to parse PEM buffer.
    
    \param bio pointer to the WOLFSSL_BIO structure for getting PEM memory pointer.
    \param x pointer to be set to new WOLFSSL_DSA structure.
    \param cb password callback function.
    \param u null terminated password string.
    
    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_DSA* dsa;
    // setup bio
    dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL);

    // check dsa is not NULL and then use dsa
    \endcode
    
    \sa none
*/
WOLFSSL_API WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp,
    WOLFSSL_DSA **x, pem_password_cb *cb, void *u);
WOLFSSL_API int wolfSSL_PEM_write_bio_X509(WOLFSSL_BIO *bp, WOLFSSL_X509 *x);
WOLFSSL_API long wolfSSL_CTX_get_options(WOLFSSL_CTX* ctx);



#endif /* HAVE_STUNNEL || HAVE_LIGHTY */


#if defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

#include <wolfssl/openssl/crypto.h>

/* SNI received callback type */
typedef int (*CallbackSniRecv)(WOLFSSL *ssl, int *ret, void* exArg);

WOLFSSL_API int wolfSSL_CRYPTO_set_mem_ex_functions(void *(*m) (size_t, const char *, int),
    void *(*r) (void *, size_t, const char *, int), void (*f) (void *));

WOLFSSL_API WOLFSSL_DH *wolfSSL_DH_generate_parameters(int prime_len, int generator,
    void (*callback) (int, int, void *), void *cb_arg);

WOLFSSL_API int wolfSSL_DH_generate_parameters_ex(WOLFSSL_DH*, int, int,
                           void (*callback) (int, int, void *));

WOLFSSL_API void wolfSSL_ERR_load_crypto_strings(void);

/*!
    \ingroup wolfssl

    \brief This function returns the absolute value of the last error from WOLFSSL_ERROR encountered.
    
    \return error Returns absolute value of last error.
    
    \param none No parameters.
    
    _Example_
    \code
    unsigned long err;
    ...
    err = wolfSSL_ERR_peek_last_error();
    // inspect err value
    \endcode
    
    \sa wolfSSL_ERR_print_errors_fp
*/
WOLFSSL_API unsigned long wolfSSL_ERR_peek_last_error(void);

WOLFSSL_API int wolfSSL_FIPS_mode(void);

WOLFSSL_API int wolfSSL_FIPS_mode_set(int r);

WOLFSSL_API int wolfSSL_RAND_set_rand_method(const void *meth);

WOLFSSL_API int wolfSSL_CIPHER_get_bits(const WOLFSSL_CIPHER *c, int *alg_bits);

WOLFSSL_API int wolfSSL_sk_X509_NAME_num(const STACK_OF(WOLFSSL_X509_NAME) *s);

WOLFSSL_API int wolfSSL_sk_X509_num(const STACK_OF(WOLFSSL_X509) *s);

WOLFSSL_API int wolfSSL_X509_NAME_print_ex(WOLFSSL_BIO*,WOLFSSL_X509_NAME*,int,
        unsigned long);

WOLFSSL_API WOLFSSL_ASN1_BIT_STRING* wolfSSL_X509_get0_pubkey_bitstr(
                            const WOLFSSL_X509*);

WOLFSSL_API int        wolfSSL_CTX_add_session(WOLFSSL_CTX*, WOLFSSL_SESSION*);

WOLFSSL_API WOLFSSL_CTX* wolfSSL_get_SSL_CTX(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_version(WOLFSSL*);

WOLFSSL_API int wolfSSL_get_state(const WOLFSSL*);

WOLFSSL_API void* wolfSSL_sk_X509_NAME_value(const STACK_OF(WOLFSSL_X509_NAME)*, int);

WOLFSSL_API void* wolfSSL_sk_X509_value(STACK_OF(WOLFSSL_X509)*, int);
/*!
    \ingroup wolfssl

    \brief This function gets the peer’s certificate chain.
    
    \return pointer returns a pointer to the peer’s Certificate stack.
    \return NULL returned if no peer certificate.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    wolfSSL_connect(ssl);
    STACK_OF(WOLFSSL_X509)* chain = wolfSSL_get_peer_cert_chain(ssl);
    ifchain){
	    // You have a pointer to the peer certificate chain
    }
    \endcode
    
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLFSSL_API STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL*);

WOLFSSL_API void* wolfSSL_SESSION_get_ex_data(const WOLFSSL_SESSION*, int);

WOLFSSL_API int   wolfSSL_SESSION_set_ex_data(WOLFSSL_SESSION*, int, void*);

WOLFSSL_API int wolfSSL_SESSION_get_ex_new_index(long,void*,void*,void*,
        CRYPTO_free_func*);

WOLFSSL_API int wolfSSL_X509_NAME_get_sz(WOLFSSL_X509_NAME*);


WOLFSSL_API const unsigned char* wolfSSL_SESSION_get_id(WOLFSSL_SESSION*,
        unsigned int*);

WOLFSSL_API int wolfSSL_set_tlsext_host_name(WOLFSSL *, const char *);

WOLFSSL_API const char* wolfSSL_get_servername(WOLFSSL *, unsigned char);

WOLFSSL_API WOLFSSL_CTX* wolfSSL_set_SSL_CTX(WOLFSSL*,WOLFSSL_CTX*);

WOLFSSL_API VerifyCallback wolfSSL_CTX_get_verify_callback(WOLFSSL_CTX*);

WOLFSSL_API void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX *,
        CallbackSniRecv);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_servername_callback(WOLFSSL_CTX *,
        CallbackSniRecv);

WOLFSSL_API void wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX *, void*);

WOLFSSL_API void WOLFSSL_ERR_remove_thread_state(void*);

#ifndef NO_FILESYSTEM
WOLFSSL_API void wolfSSL_print_all_errors_fp(XFILE *fp);
#endif

/*!
    \ingroup wolfssl

    \brief This function resets option bits of WOLFSSL_CTX object.
    
    \return option new option bits
    
    \param ctx pointer to the SSL context.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1);
    \endcode
    
    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_API long wolfSSL_CTX_clear_options(WOLFSSL_CTX*, long);

WOLFSSL_API void wolfSSL_THREADID_set_callback(void (*threadid_func)(void*));

WOLFSSL_API void wolfSSL_THREADID_set_numeric(void* id, unsigned long val);

WOLFSSL_API STACK_OF(WOLFSSL_X509)* wolfSSL_X509_STORE_get1_certs(
                               WOLFSSL_X509_STORE_CTX*, WOLFSSL_X509_NAME*);

WOLFSSL_API void wolfSSL_sk_X509_pop_free(STACK_OF(WOLFSSL_X509)* sk, void f (WOLFSSL_X509*));
#endif /* HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

#if defined(HAVE_STUNNEL) || defined(WOLFSSL_MYSQL_COMPATIBLE) \
                          || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

WOLFSSL_API int wolfSSL_CTX_get_verify_mode(WOLFSSL_CTX* ctx);

#endif

#ifdef WOLFSSL_JNI
/*!
    \ingroup wolfssl

    \brief This function sets the jObjectRef member of the WOLFSSL structure.
    
    \return SSL_SUCCESS returned if jObjectRef is properly set to objPtr.
    \return SSL_FAILURE returned if the function did not properly execute and jObjectRef is not set.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param objPtr a void pointer that will be set to jObjectRef.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new();
    void* objPtr = &obj;
    ...
    if(wolfSSL_set_jobject(ssl, objPtr)){ 
    	// The success case
    }
    \endcode
    
    \sa wolfSSL_get_jobject
*/
WOLFSSL_API int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr);
/*!
    \ingroup wolfssl

    \brief This function returns the jObjectRef member of the WOLFSSL structure.
    
    \return value If the WOLFSSL struct is not NULL, the function returns the jObjectRef value.
    \return NULL returned if the WOLFSSL struct is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL(ctx);
    ...
    void* jobject = wolfSSL_get_jobject(ssl);

    if(jobject != NULL){
    	// Success case
    }
    \endcode
    
    \sa wolfSSL_set_jobject
*/
WOLFSSL_API void* wolfSSL_get_jobject(WOLFSSL* ssl);
#endif /* WOLFSSL_JNI */


#ifdef WOLFSSL_ASYNC_CRYPT
WOLFSSL_API int wolfSSL_AsyncPoll(WOLFSSL* ssl, WOLF_EVENT_FLAG flags);
WOLFSSL_API int wolfSSL_CTX_AsyncPoll(WOLFSSL_CTX* ctx, WOLF_EVENT** events, int maxEvents,
    WOLF_EVENT_FLAG flags, int* eventCount);
#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_CTX_set1_curves_list(WOLFSSL_CTX* ctx, char* names);

typedef void (*SSL_Msg_Cb)(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg);

WOLFSSL_API int wolfSSL_CTX_set_msg_callback(WOLFSSL_CTX *ctx, SSL_Msg_Cb cb);
/*!
    \ingroup wolfssl

    \brief This function sets a callback in the ssl. The callback is to observe handshake messages. NULL value of cb resets the callback.
    
    \return SSL_SUCCESS On success.
    \return SSL_FAILURE If an NULL ssl passed in.
    
    \param ssl WOLFSSL structure to set callback argument.
    
    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    \endcode
    
    \sa wolfSSL_set_msg_callback_arg
*/
WOLFSSL_API int wolfSSL_set_msg_callback(WOLFSSL *ssl, SSL_Msg_Cb cb);
WOLFSSL_API int wolfSSL_CTX_set_msg_callback_arg(WOLFSSL_CTX *ctx, void* arg);
/*!
    \ingroup wolfssl

    \brief This function sets associated callback context value in the ssl. The value is handed over to the callback argument.
    
    \return none No return.
    
    \param ssl WOLFSSL structure to set callback argument.
    
    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    wolfSSL_set_msg_callback(ssl, arg);
    \endcode
    
    \sa wolfSSL_set_msg_callback
*/
WOLFSSL_API int wolfSSL_set_msg_callback_arg(WOLFSSL *ssl, void* arg);
#endif

#ifdef OPENSSL_EXTRA
WOLFSSL_API unsigned long wolfSSL_ERR_peek_error_line_data(const char **file,
    int *line, const char **data, int *flags);
#endif

#if defined WOLFSSL_NGINX || defined WOLFSSL_HAPROXY
/* Not an OpenSSL API. */
WOLFSSL_LOCAL int wolfSSL_get_ocsp_response(WOLFSSL* ssl, byte** response);
/* Not an OpenSSL API. */
WOLFSSL_LOCAL char* wolfSSL_get_ocsp_url(WOLFSSL* ssl);
/* Not an OpenSSL API. */
WOLFSSL_API int wolfSSL_set_ocsp_url(WOLFSSL* ssl, char* url);

WOLFSSL_API STACK_OF(WOLFSSL_CIPHER) *wolfSSL_get_ciphers_compat(const WOLFSSL *ssl);
WOLFSSL_API void wolfSSL_OPENSSL_config(char *config_name);
WOLFSSL_API int wolfSSL_X509_get_ex_new_index(int idx, void *arg, void *a,
    void *b, void *c);
WOLFSSL_API void *wolfSSL_X509_get_ex_data(WOLFSSL_X509 *x509, int idx);
WOLFSSL_API int wolfSSL_X509_set_ex_data(WOLFSSL_X509 *x509, int idx,
    void *data);

WOLFSSL_API int wolfSSL_X509_NAME_digest(const WOLFSSL_X509_NAME *data,
    const WOLFSSL_EVP_MD *type, unsigned char *md, unsigned int *len);

WOLFSSL_API long wolfSSL_SSL_CTX_get_timeout(const WOLFSSL_CTX *ctx);
WOLFSSL_API int wolfSSL_SSL_CTX_set_tmp_ecdh(WOLFSSL_CTX *ctx,
    WOLFSSL_EC_KEY *ecdh);
WOLFSSL_API int wolfSSL_SSL_CTX_remove_session(WOLFSSL_CTX *,
    WOLFSSL_SESSION *c);

WOLFSSL_API WOLFSSL_BIO *wolfSSL_SSL_get_rbio(const WOLFSSL *s);
WOLFSSL_API WOLFSSL_BIO *wolfSSL_SSL_get_wbio(const WOLFSSL *s);
WOLFSSL_API int wolfSSL_SSL_do_handshake(WOLFSSL *s);
WOLFSSL_API int wolfSSL_SSL_in_init(WOLFSSL *a); /* #define in OpenSSL */
WOLFSSL_API WOLFSSL_SESSION *wolfSSL_SSL_get0_session(const WOLFSSL *s);
WOLFSSL_API int wolfSSL_X509_check_host(WOLFSSL_X509 *x, const char *chk,
    size_t chklen, unsigned int flags, char **peername);

WOLFSSL_API int wolfSSL_i2a_ASN1_INTEGER(WOLFSSL_BIO *bp,
    const WOLFSSL_ASN1_INTEGER *a);

#ifdef HAVE_SESSION_TICKET
WOLFSSL_API int wolfSSL_CTX_set_tlsext_ticket_key_cb(WOLFSSL_CTX *, int (*)(
    WOLFSSL *ssl, unsigned char *name, unsigned char *iv,
    WOLFSSL_EVP_CIPHER_CTX *ectx, WOLFSSL_HMAC_CTX *hctx, int enc));
#endif

#ifdef HAVE_OCSP
WOLFSSL_API int wolfSSL_CTX_get_extra_chain_certs(WOLFSSL_CTX* ctx,
    STACK_OF(X509)** chain);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx,
    int(*)(WOLFSSL*, void*));

WOLFSSL_API int wolfSSL_X509_STORE_CTX_get1_issuer(WOLFSSL_X509 **issuer,
    WOLFSSL_X509_STORE_CTX *ctx, WOLFSSL_X509 *x);

WOLFSSL_API void wolfSSL_X509_email_free(STACK_OF(WOLFSSL_STRING) *sk);
WOLFSSL_API STACK_OF(WOLFSSL_STRING) *wolfSSL_X509_get1_ocsp(WOLFSSL_X509 *x);

WOLFSSL_API int wolfSSL_X509_check_issued(WOLFSSL_X509 *issuer,
    WOLFSSL_X509 *subject);

WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_dup(WOLFSSL_X509 *x);

WOLFSSL_API char* wolfSSL_sk_WOLFSSL_STRING_value(
    STACK_OF(WOLFSSL_STRING)* strings, int idx);
#endif /* HAVE_OCSP */

WOLFSSL_API int PEM_write_bio_WOLFSSL_X509(WOLFSSL_BIO *bio,
    WOLFSSL_X509 *cert);

#endif /* WOLFSSL_NGINX */

WOLFSSL_API void wolfSSL_get0_alpn_selected(const WOLFSSL *ssl,
        const unsigned char **data, unsigned int *len);
WOLFSSL_API int wolfSSL_select_next_proto(unsigned char **out,
        unsigned char *outlen,
        const unsigned char *in, unsigned int inlen,
        const unsigned char *client,
        unsigned int client_len);
WOLFSSL_API void wolfSSL_CTX_set_alpn_select_cb(WOLFSSL_CTX *ctx,
        int (*cb) (WOLFSSL *ssl,
            const unsigned char **out,
            unsigned char *outlen,
            const unsigned char *in,
            unsigned int inlen,
            void *arg), void *arg);
WOLFSSL_API void wolfSSL_CTX_set_next_protos_advertised_cb(WOLFSSL_CTX *s,
        int (*cb) (WOLFSSL *ssl,
            const unsigned char **out,
            unsigned int *outlen,
            void *arg), void *arg);
WOLFSSL_API void wolfSSL_CTX_set_next_proto_select_cb(WOLFSSL_CTX *s,
        int (*cb) (WOLFSSL *ssl,
            unsigned char **out,
            unsigned char *outlen,
            const unsigned char *in,
            unsigned int inlen,
            void *arg), void *arg);
WOLFSSL_API void wolfSSL_get0_next_proto_negotiated(const WOLFSSL *s, const unsigned char **data,
        unsigned *len);


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
WOLFSSL_API const unsigned char *SSL_SESSION_get0_id_context(
        const WOLFSSL_SESSION *sess, unsigned int *sid_ctx_length);
WOLFSSL_API size_t SSL_get_finished(const WOLFSSL *s, void *buf, size_t count);
WOLFSSL_API size_t SSL_get_peer_finished(const WOLFSSL *s, void *buf, size_t count);
#endif

WOLFSSL_API int SSL_SESSION_set1_id(WOLFSSL_SESSION *s, const unsigned char *sid, unsigned int sid_len);
WOLFSSL_API int SSL_SESSION_set1_id_context(WOLFSSL_SESSION *s, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
WOLFSSL_API void *X509_get0_tbs_sigalg(const WOLFSSL_X509 *x);
WOLFSSL_API void X509_ALGOR_get0(WOLFSSL_ASN1_OBJECT **paobj, int *pptype, const void **ppval, const void *algor);
WOLFSSL_API void *X509_get_X509_PUBKEY(void * x);
WOLFSSL_API int X509_PUBKEY_get0_param(WOLFSSL_ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, void **pa, WOLFSSL_EVP_PKEY *pub);
WOLFSSL_API int EVP_PKEY_bits(WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int i2d_X509(WOLFSSL_X509 *x, unsigned char **out);
WOLFSSL_API int i2t_ASN1_OBJECT(char *buf, int buf_len, WOLFSSL_ASN1_OBJECT *a);
WOLFSSL_API void SSL_CTX_set_tmp_dh_callback(WOLFSSL_CTX *ctx, WOLFSSL_DH *(*dh) (WOLFSSL *ssl, int is_export, int keylength));
WOLFSSL_API STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void);
WOLFSSL_API int X509_STORE_load_locations(WOLFSSL_X509_STORE *ctx, const char *file, const char *dir);
WOLFSSL_API int wolfSSL_sk_SSL_CIPHER_num(const void * p);
WOLFSSL_API int wolfSSL_sk_SSL_COMP_zero(WOLFSSL_STACK* st);
WOLFSSL_API WOLFSSL_CIPHER* wolfSSL_sk_SSL_CIPHER_value(void *ciphers, int idx);
WOLFSSL_API void ERR_load_SSL_strings(void);

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_SSL_H */
