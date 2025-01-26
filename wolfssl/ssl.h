/* ssl.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
    \file ../wolfssl/ssl.h
    \brief Header file containing key wolfSSL API
*/

/* wolfSSL API */

#ifndef WOLFSSL_SSL_H
#define WOLFSSL_SSL_H


/* for users not using preprocessor flags*/
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/pkcs12.h>

#if defined(HAVE_OCSP) || defined(HAVE_CRL) || (defined(WOLFSSL_CUSTOM_OID) && \
    defined(WOLFSSL_ASN_TEMPLATE) && defined(HAVE_OID_DECODING)) || \
    defined(WC_ASN_UNKNOWN_EXT_CB)
#include "wolfssl/wolfcrypt/asn.h"
#endif

/* For the types */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
#include <wolfssl/openssl/compat_types.h>
#endif

#ifdef HAVE_WOLF_EVENT
    #include <wolfssl/wolfcrypt/wolfevent.h>
#endif

 #ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

/* used internally by wolfSSL while OpenSSL types aren't */
#include <wolfssl/callbacks.h>

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

#ifdef OPENSSL_ALL
    #if !defined(WOLFSSL_HAVE_BIO_ADDR) && !defined(WOLFSSL_NO_SOCK)
    #define WOLFSSL_HAVE_BIO_ADDR
    #endif
    #if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_DTLS_MTU)
    #define WOLFSSL_DTLS_MTU
    #endif
#endif

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    #include <wolfssl/openssl/bn.h>
    #ifndef WOLFCRYPT_ONLY
        #include <wolfssl/openssl/hmac.h>
    #endif
    #if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
        #include <wolfssl/openssl/cmac.h>
    #endif
#endif

#ifdef OPENSSL_COEXIST
    /* mode to allow wolfSSL and OpenSSL to coexist without symbol conflicts */

    #ifndef NO_OLD_SSL_NAMES
        #define NO_OLD_SSL_NAMES
    #endif
    #ifndef NO_OLD_WC_NAMES
        #define NO_OLD_WC_NAMES
    #endif

    #ifdef TEST_OPENSSL_COEXIST
        /*
        ./configure --enable-opensslcoexist \
            CFLAGS="-I/usr/local/opt/openssl/include -DTEST_OPENSSL_COEXIST" \
            LDFLAGS="-L/usr/local/opt/openssl/lib -lcrypto"
        */
        #include <openssl/ssl.h>
        #include <openssl/rand.h>
        #include <openssl/err.h>
        #include <openssl/ec.h>
        #include <openssl/hmac.h>
        #include <openssl/bn.h>
        #include <openssl/crypto.h>

        #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
            FIPS_VERSION3_GE(5,2,0))
        #include <openssl/aes.h>
        #include <openssl/blowfish.h>
        #include <openssl/camellia.h>
        #include <openssl/cast.h>
        #include <openssl/cmac.h>
        #include <openssl/cmp.h>
        #include <openssl/cms.h>
        #include <openssl/conf_api.h>
        #include <openssl/core_object.h>
        #include <openssl/decoder.h>
        #include <openssl/des.h>
        #include <openssl/dh.h>
        #include <openssl/dsa.h>
        #include <openssl/ecdh.h>
        #include <openssl/ecdsa.h>
        #include <openssl/encoder.h>
        #include <openssl/engine.h>
        #include <openssl/ess.h>
        #include <openssl/fipskey.h>
        #include <openssl/fips_names.h>
        #include <openssl/hmac.h>
        #include <openssl/hpke.h>
        #include <openssl/http.h>
        #include <openssl/idea.h>
        #include <openssl/kdf.h>
        #include <openssl/md2.h>
        #include <openssl/md4.h>
        #include <openssl/md5.h>
        #include <openssl/mdc2.h>
        #include <openssl/modes.h>
        #include <openssl/ocsp.h>
        #include <openssl/ossl_typ.h>
        #include <openssl/param_build.h>
        #include <openssl/params.h>
        #include <openssl/pem2.h>
        #include <openssl/pem.h>
        #include <openssl/pkcs12.h>
        #include <openssl/pkcs7.h>
        #include <openssl/proverr.h>
        #include <openssl/provider.h>
        #include <openssl/rand.h>
        #include <openssl/rc2.h>
        #include <openssl/rc4.h>
        #include <openssl/rc5.h>
        #include <openssl/ripemd.h>
        #include <openssl/rsa.h>
        #if defined(HAVE_FIPS_VERSION) && FIPS_VERSION3_LT(6,0,0)
            /* clear conflicting name */
            #undef RSA_PKCS1_PADDING_SIZE
        #endif
        #include <openssl/seed.h>
        #include <openssl/self_test.h>
        #include <openssl/sha.h>
        #include <openssl/srp.h>
        #include <openssl/srtp.h>
        #include <openssl/ssl.h>
        #include <openssl/store.h>
        #include <openssl/txt_db.h>
        #include <openssl/ui.h>
        #include <openssl/whrlpool.h>
        #endif /* !HAVE_SELFTEST && (!HAVE_FIPS || FIPS_VERSION3_GE(5,2,0)) */

    #endif

#elif (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    #include <wolfssl/openssl/rsa.h>

    /* We need the old SSL names */
    #if defined(NO_OLD_SSL_NAMES) && !defined(OPENSSL_COEXIST)
        #undef NO_OLD_SSL_NAMES
    #endif
    #if defined(NO_OLD_WC_NAMES) && !defined(OPENSSL_COEXIST)
        #undef NO_OLD_WC_NAMES
    #endif
#endif

#ifdef __cplusplus
    extern "C" {
#endif


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || defined(WOLFSSL_WPAS_SMALL)
#ifndef WOLFSSL_LOCAL_X509_STORE
#define WOLFSSL_LOCAL_X509_STORE
#endif
#endif

/* LHASH is implemented as a stack */
typedef struct WOLFSSL_STACK WOLFSSL_LHASH;
#ifndef WOLF_LHASH_OF
    #define WOLF_LHASH_OF(x) WOLFSSL_LHASH
#endif

#ifndef WOLF_STACK_OF
    #define WOLF_STACK_OF(x) WOLFSSL_STACK
#endif
#ifndef DECLARE_STACK_OF
    #define DECLARE_STACK_OF(x) WOLF_STACK_OF(x);
#endif

#ifndef WOLFSSL_TYPE_DEFINED
#define WOLFSSL_TYPE_DEFINED
typedef struct WOLFSSL          WOLFSSL;
#endif
typedef struct WOLFSSL_SESSION  WOLFSSL_SESSION;
typedef struct WOLFSSL_METHOD   WOLFSSL_METHOD;
#ifndef WOLFSSL_CTX_TYPE_DEFINED
#define WOLFSSL_CTX_TYPE_DEFINED
typedef struct WOLFSSL_CTX      WOLFSSL_CTX;
#endif

typedef struct WOLFSSL_STACK      WOLFSSL_STACK;
typedef struct WOLFSSL_X509       WOLFSSL_X509;
typedef struct WOLFSSL_X509_ACERT WOLFSSL_X509_ACERT;
typedef struct WOLFSSL_X509_NAME  WOLFSSL_X509_NAME;
typedef struct WOLFSSL_X509_NAME_ENTRY  WOLFSSL_X509_NAME_ENTRY;
typedef struct WOLFSSL_X509_PUBKEY WOLFSSL_X509_PUBKEY;
typedef struct WOLFSSL_X509_ALGOR WOLFSSL_X509_ALGOR;
typedef struct WOLFSSL_X509_CHAIN WOLFSSL_X509_CHAIN;
typedef struct WC_PKCS12          WOLFSSL_X509_PKCS12;
typedef struct WOLFSSL_X509_INFO  WOLFSSL_X509_INFO;

typedef struct WOLFSSL_CERT_MANAGER WOLFSSL_CERT_MANAGER;
typedef struct WOLFSSL_SOCKADDR     WOLFSSL_SOCKADDR;
typedef struct WOLFSSL_CRL          WOLFSSL_CRL;
typedef struct WOLFSSL_X509_STORE_CTX WOLFSSL_X509_STORE_CTX;

typedef struct WOLFSSL_BY_DIR_HASH  WOLFSSL_BY_DIR_HASH;
typedef struct WOLFSSL_BY_DIR_entry WOLFSSL_BY_DIR_entry;
typedef struct WOLFSSL_BY_DIR       WOLFSSL_BY_DIR;

/* redeclare guard */
#define WOLFSSL_TYPES_DEFINED

#include <wolfssl/wolfio.h>

/* The WOLFSSL_RSA type is required in all build configurations. */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
#include <wolfssl/openssl/rsa.h>
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
typedef struct WOLFSSL_EC_BUILTIN_CURVE WOLFSSL_EC_BUILTIN_CURVE;
/* WOLFSSL_EC_METHOD is just an alias of WOLFSSL_EC_GROUP for now */
typedef struct WOLFSSL_EC_GROUP       WOLFSSL_EC_METHOD;
#define WOLFSSL_EC_TYPE_DEFINED
#endif

#ifndef WOLFSSL_ECDSA_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_ECDSA_SIG      WOLFSSL_ECDSA_SIG;
#define WOLFSSL_ECDSA_TYPE_DEFINED
#endif

typedef struct WOLFSSL_CIPHER         WOLFSSL_CIPHER;
typedef struct WOLFSSL_X509_LOOKUP    WOLFSSL_X509_LOOKUP;
typedef struct WOLFSSL_X509_LOOKUP_METHOD WOLFSSL_X509_LOOKUP_METHOD;
typedef struct WOLFSSL_CRL            WOLFSSL_X509_CRL;
typedef struct WOLFSSL_X509_STORE     WOLFSSL_X509_STORE;
typedef struct WOLFSSL_X509_VERIFY_PARAM WOLFSSL_X509_VERIFY_PARAM;
typedef struct WOLFSSL_BIO_METHOD     WOLFSSL_BIO_METHOD;
typedef struct WOLFSSL_X509_EXTENSION WOLFSSL_X509_EXTENSION;
typedef struct WOLFSSL_ASN1_OBJECT    WOLFSSL_ASN1_OBJECT;
typedef struct WOLFSSL_ASN1_OTHERNAME WOLFSSL_ASN1_OTHERNAME;
#ifndef OPENSSL_COEXIST
typedef struct WOLFSSL_ASN1_OTHERNAME OTHERNAME;
#endif
typedef struct WOLFSSL_X509V3_CTX     WOLFSSL_X509V3_CTX;
typedef struct WOLFSSL_v3_ext_method  WOLFSSL_v3_ext_method;
typedef struct WOLFSSL_OBJ_NAME       WOLFSSL_OBJ_NAME;

typedef struct WOLFSSL_ASN1_STRING      WOLFSSL_ASN1_STRING;
typedef struct WOLFSSL_dynlock_value    WOLFSSL_dynlock_value;
#ifndef WOLFSSL_DH_TYPE_DEFINED /* guard on redeclaration */
typedef struct WOLFSSL_DH               WOLFSSL_DH;
#define WOLFSSL_DH_TYPE_DEFINED /* guard on redeclaration */
#endif
typedef struct WOLFSSL_ASN1_BIT_STRING  WOLFSSL_ASN1_BIT_STRING;
typedef struct WOLFSSL_ASN1_TYPE        WOLFSSL_ASN1_TYPE;
typedef struct WOLFSSL_X509_ATTRIBUTE   WOLFSSL_X509_ATTRIBUTE;

typedef struct WOLFSSL_GENERAL_NAME WOLFSSL_GENERAL_NAME;
typedef struct WOLFSSL_AUTHORITY_KEYID  WOLFSSL_AUTHORITY_KEYID;
typedef struct WOLFSSL_BASIC_CONSTRAINTS WOLFSSL_BASIC_CONSTRAINTS;
typedef struct WOLFSSL_ACCESS_DESCRIPTION WOLFSSL_ACCESS_DESCRIPTION;
typedef struct WOLFSSL_DIST_POINT_NAME WOLFSSL_DIST_POINT_NAME;
typedef struct WOLFSSL_DIST_POINT WOLFSSL_DIST_POINT;

typedef struct WOLFSSL_CONF_CTX     WOLFSSL_CONF_CTX;

typedef int (*WOLFSSL_X509_STORE_CTX_get_crl_cb)(WOLFSSL_X509_STORE_CTX *,
        WOLFSSL_X509_CRL **, WOLFSSL_X509 *);
typedef int (*WOLFSSL_X509_STORE_CTX_check_crl_cb)(WOLFSSL_X509_STORE_CTX *,
        WOLFSSL_X509_CRL *);

#define WOLFSSL_V_ASN1_BIT_STRING                0x03
#define WOLFSSL_V_ASN1_INTEGER                   0x02
#define WOLFSSL_V_ASN1_NEG                       0x100
#define WOLFSSL_V_ASN1_NEG_INTEGER               (2 | WOLFSSL_V_ASN1_NEG)
#define WOLFSSL_V_ASN1_NEG_ENUMERATED            (10 | WOLFSSL_V_ASN1_NEG)

/* Type for ASN1_print_ex */
#define WOLFSSL_ASN1_STRFLGS_ESC_2253           1
#define WOLFSSL_ASN1_STRFLGS_ESC_CTRL           2
#define WOLFSSL_ASN1_STRFLGS_ESC_MSB            4
#define WOLFSSL_ASN1_STRFLGS_ESC_QUOTE          8
#define WOLFSSL_ASN1_STRFLGS_UTF8_CONVERT       0x10
#define WOLFSSL_ASN1_STRFLGS_IGNORE_TYPE        0x20
#define WOLFSSL_ASN1_STRFLGS_SHOW_TYPE          0x40
#define WOLFSSL_ASN1_STRFLGS_DUMP_ALL           0x80
#define WOLFSSL_ASN1_STRFLGS_DUMP_UNKNOWN       0x100
#define WOLFSSL_ASN1_STRFLGS_DUMP_DER           0x200
#define WOLFSSL_ASN1_STRFLGS_RFC2253            (WOLFSSL_ASN1_STRFLGS_ESC_2253 | \
                                          WOLFSSL_ASN1_STRFLGS_ESC_CTRL | \
                                          WOLFSSL_ASN1_STRFLGS_ESC_MSB | \
                                          WOLFSSL_ASN1_STRFLGS_UTF8_CONVERT | \
                                          WOLFSSL_ASN1_STRFLGS_DUMP_UNKNOWN | \
                                          WOLFSSL_ASN1_STRFLGS_DUMP_DER)

#define WOLFSSL_MBSTRING_UTF8                    0x1000
#define WOLFSSL_MBSTRING_ASC                     0x1001
#define WOLFSSL_MBSTRING_BMP                     0x1002
#define WOLFSSL_MBSTRING_UNIV                    0x1004

#define WOLFSSL_V_ASN1_EOC                      0
#define WOLFSSL_V_ASN1_BOOLEAN                  1
#define WOLFSSL_V_ASN1_OCTET_STRING             4
#define WOLFSSL_V_ASN1_NULL                     5
#define WOLFSSL_V_ASN1_OBJECT                   6
#define WOLFSSL_V_ASN1_UTF8STRING               12
#define WOLFSSL_V_ASN1_SEQUENCE                 16
#define WOLFSSL_V_ASN1_SET                      17
#define WOLFSSL_V_ASN1_PRINTABLESTRING          19
#define WOLFSSL_V_ASN1_T61STRING                20
#define WOLFSSL_V_ASN1_IA5STRING                22
#define WOLFSSL_V_ASN1_UTCTIME                  23
#define WOLFSSL_V_ASN1_GENERALIZEDTIME          24
#define WOLFSSL_V_ASN1_UNIVERSALSTRING          28
#define WOLFSSL_V_ASN1_BMPSTRING                30


#define WOLFSSL_V_ASN1_CONSTRUCTED              0x20

#define WOLFSSL_ASN1_STRING_FLAG_BITS_LEFT       0x008
#define WOLFSSL_ASN1_STRING_FLAG_NDEF            0x010
#define WOLFSSL_ASN1_STRING_FLAG_CONT            0x020
#define WOLFSSL_ASN1_STRING_FLAG_MSTRING         0x040
#define WOLFSSL_ASN1_STRING_FLAG_EMBED           0x080

/* X.509 PKI size limits from RFC2459 (appendix A) */
/* internally our limit is CTC_NAME_SIZE (64) - overridden with WC_CTC_NAME_SIZE */
#define WOLFSSL_ub_name                    CTC_NAME_SIZE /* 32768 */
#define WOLFSSL_ub_common_name             CTC_NAME_SIZE /* 64 */
#define WOLFSSL_ub_locality_name           CTC_NAME_SIZE /* 128 */
#define WOLFSSL_ub_state_name              CTC_NAME_SIZE /* 128 */
#define WOLFSSL_ub_organization_name       CTC_NAME_SIZE /* 64 */
#define WOLFSSL_ub_organization_unit_name  CTC_NAME_SIZE /* 64 */
#define WOLFSSL_ub_title                   CTC_NAME_SIZE /* 64 */
#define WOLFSSL_ub_email_address           CTC_NAME_SIZE /* 128 */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || defined(HAVE_CURL)

struct WOLFSSL_OBJ_NAME {
    int type;
    int alias;
    const char *name;
    const char *data;
};

struct WOLFSSL_AUTHORITY_KEYID {
    WOLFSSL_ASN1_STRING *keyid;
    WOLFSSL_ASN1_OBJECT *issuer;
    WOLFSSL_ASN1_INTEGER *serial;
};

struct WOLFSSL_BASIC_CONSTRAINTS {
    int ca;
    WOLFSSL_ASN1_INTEGER *pathlen;
};

#endif /* OPENSSL_EXTRA*/

#define WOLFSSL_ASN1_UTCTIME          WOLFSSL_ASN1_TIME
#define WOLFSSL_ASN1_GENERALIZEDTIME  WOLFSSL_ASN1_TIME

struct WOLFSSL_ASN1_STRING {
    char strData[CTC_NAME_SIZE];
    int length;
    int type; /* type of string i.e. CTC_UTF8 */
    int nid;
    char* data;
    long flags;
    unsigned int   isDynamic:1; /* flag for if data pointer dynamic (1 is yes 0 is no) */
};

#define WOLFSSL_MAX_SNAME 40


#define WOLFSSL_ASN1_DYNAMIC 0x1
#define WOLFSSL_ASN1_DYNAMIC_DATA 0x2

struct WOLFSSL_ASN1_OTHERNAME {
    WOLFSSL_ASN1_OBJECT* type_id;
    WOLFSSL_ASN1_TYPE*   value;
};

struct WOLFSSL_GENERAL_NAME {
    int type;
    union {
        char* ptr;
        WOLFSSL_ASN1_OTHERNAME* otherName;
        WOLFSSL_ASN1_STRING* rfc822Name;
        WOLFSSL_ASN1_STRING* dNSName;
        WOLFSSL_ASN1_TYPE* x400Address;
        WOLFSSL_X509_NAME* directoryName;
        WOLFSSL_ASN1_STRING* uniformResourceIdentifier;
        WOLFSSL_ASN1_STRING* iPAddress;
        WOLFSSL_ASN1_OBJECT* registeredID;

        WOLFSSL_ASN1_STRING* ip;
        WOLFSSL_X509_NAME* dirn;
        WOLFSSL_ASN1_STRING* ia5;
        WOLFSSL_ASN1_OBJECT* rid;
        WOLFSSL_ASN1_TYPE* other;
    } d; /* dereference */
};

struct WOLFSSL_DIST_POINT_NAME {
    int type;

    /* name 'name.fullname' needs to remain the same, in some ports the elements
     * of the structure are accessed directly */
    union {
        WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* fullname;
    } name;
};

struct WOLFSSL_DIST_POINT {
    /* name 'distpoint' needs to remain the same, in some ports the elements of
     * the structure are accessed directly */
    WOLFSSL_DIST_POINT_NAME* distpoint;
};

struct WOLFSSL_ACCESS_DESCRIPTION {
    WOLFSSL_ASN1_OBJECT*  method;
    WOLFSSL_GENERAL_NAME* location;
};

struct WOLFSSL_X509V3_CTX {
    WOLFSSL_X509* x509;
};

struct WOLFSSL_ASN1_OBJECT {
    void*  heap;
    const unsigned char* obj;
    /* sName is short name i.e sha256 rather than oid (null terminated) */
    char   sName[WOLFSSL_MAX_SNAME];
    int    type; /* oid */
    int    grp;  /* type of OID, i.e. oidCertPolicyType */
    int    nid;
    unsigned int  objSz;
#if defined(OPENSSL_EXTRA)
    int ca;
    WOLFSSL_ASN1_INTEGER *pathlen;
#endif
    unsigned char dynamic; /* Use WOLFSSL_ASN1_DYNAMIC and WOLFSSL_ASN1_DYNAMIC_DATA
                            * to determine what needs to be freed. */

#if defined(WOLFSSL_APACHE_HTTPD)
    WOLFSSL_GENERAL_NAME* gn;
#endif

    struct d { /* dereferenced */
        WOLFSSL_ASN1_STRING* dNSName;
        WOLFSSL_ASN1_STRING  ia5_internal;
        WOLFSSL_ASN1_STRING* ia5; /* points to ia5_internal */
#if defined(OPENSSL_ALL)
        WOLFSSL_ASN1_STRING* uniformResourceIdentifier;
        WOLFSSL_ASN1_STRING  iPAddress_internal;
        WOLFSSL_ASN1_OTHERNAME* otherName; /* added for Apache httpd */
#endif
        WOLFSSL_ASN1_STRING* iPAddress; /* points to iPAddress_internal */
    } d;
};

/* wrap ASN1 types */
struct WOLFSSL_ASN1_TYPE {
    int type;
    union {
        char *ptr;
        WOLFSSL_ASN1_STRING*     asn1_string;
        WOLFSSL_ASN1_OBJECT*     object;
        WOLFSSL_ASN1_INTEGER*    integer;
        WOLFSSL_ASN1_BIT_STRING* bit_string;
        WOLFSSL_ASN1_STRING*     octet_string;
        WOLFSSL_ASN1_STRING*     printablestring;
        WOLFSSL_ASN1_STRING*     ia5string;
        WOLFSSL_ASN1_UTCTIME*    utctime;
        WOLFSSL_ASN1_GENERALIZEDTIME* generalizedtime;
        WOLFSSL_ASN1_STRING*     utf8string;
        WOLFSSL_ASN1_STRING*     set;
        WOLFSSL_ASN1_STRING*     sequence;
    } value;
};

struct WOLFSSL_X509_ATTRIBUTE {
    WOLFSSL_ASN1_OBJECT *object;
    WOLFSSL_ASN1_TYPE *value;
    WOLF_STACK_OF(WOLFSSL_ASN1_TYPE) *set;
};

struct WOLFSSL_EVP_PKEY {
    void* heap;
    int type;         /* openssh dereference */
    int save_type;    /* openssh dereference */
    int pkey_sz;
    wolfSSL_Ref ref;

    union {
        char* ptr; /* der format of key */
    } pkey;
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    #ifndef NO_RSA
    WOLFSSL_RSA* rsa;
    #endif
    #ifndef NO_DSA
    WOLFSSL_DSA* dsa;
    #endif
    #ifdef HAVE_ECC
    WOLFSSL_EC_KEY* ecc;
    #endif
    #ifndef NO_DH
    WOLFSSL_DH* dh;
    #endif
    WC_RNG rng;
    #ifdef HAVE_HKDF
    const WOLFSSL_EVP_MD* hkdfMd;
    byte* hkdfSalt;
    word32 hkdfSaltSz;
    byte* hkdfKey;
    word32 hkdfKeySz;
    byte* hkdfInfo;
    word32 hkdfInfoSz;
    int hkdfMode;
    #endif
    #if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    WOLFSSL_CMAC_CTX* cmacCtx;
    #endif
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
#ifdef HAVE_ECC
    int pkey_curve;
#endif
    word16 pkcs8HeaderSz;

    /* option bits */
    WC_BITFIELD ownDh:1;  /* if struct owns DH  and should free it */
    WC_BITFIELD ownEcc:1; /* if struct owns ECC and should free it */
    WC_BITFIELD ownDsa:1; /* if struct owns DSA and should free it */
    WC_BITFIELD ownRsa:1; /* if struct owns RSA and should free it */
};


#define WOLFSSL_ALWAYS_CHECK_SUBJECT 0x1
#define WOLFSSL_NO_WILDCARDS         0x2
#define WOLFSSL_NO_PARTIAL_WILDCARDS 0x4
#define WOLFSSL_MULTI_LABEL_WILDCARDS 0x8
/* Custom to wolfSSL, OpenSSL compat goes up to 0x20 */
#define WOLFSSL_LEFT_MOST_WILDCARD_ONLY 0x40


typedef struct WOLFSSL_BUFFER_INFO {
    unsigned char* buffer;
    word32 length;
} WOLFSSL_BUFFER_INFO;

typedef struct WOLFSSL_BUF_MEM {
    char*  data;   /* dereferenced */
    size_t length; /* current length */
    size_t max;    /* maximum length */
} WOLFSSL_BUF_MEM;


typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*);
typedef int (*WOLFSSL_X509_STORE_CTX_verify_cb)(int, WOLFSSL_X509_STORE_CTX *);

struct WOLFSSL_X509_STORE_CTX {
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    WOLFSSL_X509_STORE* store;    /* Store full of a CA cert chain */
    WOLFSSL_X509* current_cert;   /* current X509 (OPENSSL_EXTRA) */
    #if defined(WOLFSSL_ASIO) || defined(OPENSSL_EXTRA)
    WOLFSSL_X509* current_issuer; /* asio dereference */
    #endif
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
    WOLFSSL_X509_CHAIN* sesChain; /* pointer to WOLFSSL_SESSION peer chain */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    WOLFSSL_STACK* chain;
    #ifdef OPENSSL_EXTRA
    WOLFSSL_X509_VERIFY_PARAM* param; /* certificate validation parameter */
    #endif
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

    char* domain;                /* subject CN domain name */
#ifdef HAVE_EX_DATA
    WOLFSSL_CRYPTO_EX_DATA ex_data;  /* external data */
#endif
#if defined(WOLFSSL_APACHE_HTTPD) || defined(OPENSSL_EXTRA)
    int depth;                   /* used in X509_STORE_CTX_*_depth */
#endif
    void* userCtx;               /* user ctx */
    int   error;                 /* current error */
    int   error_depth;           /* index of cert depth for this error */
    int   discardSessionCerts;   /* so verify callback can flag for discard */
    int   totalCerts;            /* number of peer cert buffers */
    WOLFSSL_BUFFER_INFO* certs;  /* peer certs */
    WOLFSSL_X509_STORE_CTX_verify_cb verify_cb; /* verify callback */
    void* heap;
    int   flags;

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    WOLF_STACK_OF(WOLFSSL_X509)* owned;  /* Certs owned by this CTX */
    WOLF_STACK_OF(WOLFSSL_X509)* ctxIntermediates; /* Intermediates specified
                                                    * on store ctx init */
    WOLF_STACK_OF(WOLFSSL_X509)* setTrustedSk;/* A trusted stack override
                                               * set with
                                               * X509_STORE_CTX_trusted_stack */
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
};


#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)

struct WOLFSSL_X509_PKEY {
    WOLFSSL_EVP_PKEY* dec_pkey; /* dereferenced by Apache */
    void* heap;
};
typedef struct WOLFSSL_X509_PKEY WOLFSSL_X509_PKEY;

struct WOLFSSL_X509_INFO {
    WOLFSSL_X509      *x509;
    WOLFSSL_X509_CRL  *crl;
    WOLFSSL_X509_PKEY  *x_pkey; /* dereferenced by Apache */
    EncryptedInfo     enc_cipher;
    int               enc_len;
    char              *enc_data;
    int               num;
};

#define WOLFSSL_EVP_PKEY_DEFAULT WC_EVP_PKEY_RSA /* default key type */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    #define wolfSSL_SSL_MODE_RELEASE_BUFFERS    0x00000010U
    #define wolfSSL_SSL_CTRL_SET_TMP_ECDH       4
#endif

struct WOLFSSL_X509_ALGOR {
    WOLFSSL_ASN1_OBJECT* algorithm;
    WOLFSSL_ASN1_TYPE* parameter;
};

struct WOLFSSL_X509_PUBKEY {
    WOLFSSL_X509_ALGOR* algor;
    WOLFSSL_EVP_PKEY* pkey;
    int pubKeyOID;
};

enum BIO_TYPE {
    WOLFSSL_BIO_UNDEF  = 0,
    WOLFSSL_BIO_BUFFER = 1,
    WOLFSSL_BIO_SOCKET = 2,
    WOLFSSL_BIO_SSL    = 3,
    WOLFSSL_BIO_MEMORY = 4,
    WOLFSSL_BIO_BIO    = 5,
    WOLFSSL_BIO_FILE   = 6,
    WOLFSSL_BIO_BASE64 = 7,
    WOLFSSL_BIO_MD     = 8,
    WOLFSSL_BIO_DGRAM  = 9
};

enum BIO_FLAGS {
    WOLFSSL_BIO_FLAG_BASE64_NO_NL = 0x01,
    WOLFSSL_BIO_FLAG_READ         = 0x02,
    WOLFSSL_BIO_FLAG_WRITE        = 0x04,
    WOLFSSL_BIO_FLAG_IO_SPECIAL   = 0x08,
    WOLFSSL_BIO_FLAG_RETRY        = 0x10,
    WOLFSSL_BIO_FLAG_MEM_RDONLY   = 0x200
};

enum BIO_CB_OPS {
    WOLFSSL_BIO_CB_FREE   = 0x01,
    WOLFSSL_BIO_CB_READ   = 0x02,
    WOLFSSL_BIO_CB_WRITE  = 0x03,
    WOLFSSL_BIO_CB_PUTS   = 0x04,
    WOLFSSL_BIO_CB_GETS   = 0x05,
    WOLFSSL_BIO_CB_CTRL   = 0x06,
    WOLFSSL_BIO_CB_RETURN = 0x80
};

/* custom method with user set callbacks */
typedef int  (*wolfSSL_BIO_meth_write_cb)(WOLFSSL_BIO*, const char*, int);
typedef int  (*wolfSSL_BIO_meth_read_cb)(WOLFSSL_BIO *, char *, int);
typedef int  (*wolfSSL_BIO_meth_puts_cb)(WOLFSSL_BIO*, const char*);
typedef int  (*wolfSSL_BIO_meth_gets_cb)(WOLFSSL_BIO*, char*, int);
typedef long (*wolfSSL_BIO_meth_ctrl_get_cb)(WOLFSSL_BIO*, int, long, void*);
typedef int  (*wolfSSL_BIO_meth_create_cb)(WOLFSSL_BIO*);
typedef int  (*wolfSSL_BIO_meth_destroy_cb)(WOLFSSL_BIO*);

typedef int wolfSSL_BIO_info_cb(WOLFSSL_BIO *, int, int);
typedef long (*wolfssl_BIO_meth_ctrl_info_cb)(WOLFSSL_BIO*, int, wolfSSL_BIO_info_cb*);

/* wolfSSL BIO_METHOD type */
#ifndef MAX_BIO_METHOD_NAME
#define MAX_BIO_METHOD_NAME 256
#endif
struct WOLFSSL_BIO_METHOD {
    byte type;               /* method type */
    char name[MAX_BIO_METHOD_NAME];
    wolfSSL_BIO_meth_write_cb writeCb;
    wolfSSL_BIO_meth_read_cb readCb;
    wolfSSL_BIO_meth_puts_cb putsCb;
    wolfSSL_BIO_meth_gets_cb getsCb;
    wolfSSL_BIO_meth_ctrl_get_cb ctrlCb;
    wolfSSL_BIO_meth_create_cb createCb;
    wolfSSL_BIO_meth_destroy_cb freeCb;
    wolfssl_BIO_meth_ctrl_info_cb ctrlInfoCb;
};

#define WOLFSSL_BIO_METHOD_INIT(bio_type) \
    { bio_type, { 0 }, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }

/* wolfSSL BIO type */
typedef long (*wolf_bio_info_cb)(WOLFSSL_BIO *bio, int event, const char *parg,
                                 int iarg, long larg, long return_value);

typedef struct WOLFSSL_COMP_METHOD {
    int type;            /* stunnel dereference */
} WOLFSSL_COMP_METHOD;

typedef struct WOLFSSL_COMP {
    int id;
    const char *name;
    WOLFSSL_COMP_METHOD *method;
} WOLFSSL_COMP;

#define WOLFSSL_X509_L_FILE_LOAD  0x1
#define WOLFSSL_X509_L_ADD_DIR    0x2
#define WOLFSSL_X509_L_ADD_STORE  0x3
#define WOLFSSL_X509_L_LOAD_STORE 0x4

struct WOLFSSL_X509_LOOKUP_METHOD {
    int type;
};

struct WOLFSSL_X509_LOOKUP {
    WOLFSSL_X509_STORE *store;
    int type;
    WOLFSSL_BY_DIR* dirs;
};

struct WOLFSSL_X509_STORE {
    int                   cache;          /* stunnel dereference */
    WOLFSSL_CERT_MANAGER* cm;
    WOLFSSL_X509_LOOKUP   lookup;
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || \
    defined(WOLFSSL_WPAS_SMALL)
    int                   isDynamic;
    WOLFSSL_X509_VERIFY_PARAM* param;    /* certificate validation parameter */
#endif
#ifdef OPENSSL_ALL
    WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* objs; /* object stack cache */
#endif
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    WOLFSSL_X509_STORE_CTX_verify_cb verify_cb;
    WOLFSSL_X509_STORE_CTX_get_crl_cb get_crl_cb;
#endif
#ifdef HAVE_EX_DATA
    WOLFSSL_CRYPTO_EX_DATA ex_data;
#endif
#if (defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || \
        defined(WOLFSSL_WPAS_SMALL)) && defined(HAVE_CRL)
    WOLFSSL_X509_CRL *crl; /* points to cm->crl */
#endif
    wolfSSL_Ref     ref;
    WOLF_STACK_OF(WOLFSSL_X509)* certs;
    WOLF_STACK_OF(WOLFSSL_X509)* trusted;
    WOLF_STACK_OF(WOLFSSL_X509)* owned;
    word32 numAdded; /* Number of objs in objs that are in certs sk */
};

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
#define WOLFSSL_USE_CHECK_TIME 0x2
#define WOLFSSL_NO_CHECK_TIME  0x200000
#define WOLFSSL_PARTIAL_CHAIN  0x80000
#define WOLFSSL_HOST_NAME_MAX  256

#define WOLFSSL_VPARAM_DEFAULT          0x1
#define WOLFSSL_VPARAM_OVERWRITE        0x2
#define WOLFSSL_VPARAM_RESET_FLAGS      0x4
#define WOLFSSL_VPARAM_LOCKED           0x8
#define WOLFSSL_VPARAM_ONCE             0x10

#ifndef WOLFSSL_MAX_IPSTR
    #define WOLFSSL_MAX_IPSTR 46 /* max ip size IPv4 mapped IPv6 */
#endif

struct WOLFSSL_X509_VERIFY_PARAM {
    const char    *name;
    time_t         check_time;
    unsigned int   inherit_flags;
    unsigned long  flags;
    char           hostName[WOLFSSL_HOST_NAME_MAX];
    unsigned int   hostFlags;
    char           ipasc[WOLFSSL_MAX_IPSTR];
};
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

typedef struct WOLFSSL_X509_REVOKED {
    WOLFSSL_ASN1_INTEGER* serialNumber;          /* stunnel dereference */
} WOLFSSL_X509_REVOKED;

typedef enum {
    WOLFSSL_X509_LU_NONE = 0,
    WOLFSSL_X509_LU_X509,
    WOLFSSL_X509_LU_CRL
} WOLFSSL_X509_LOOKUP_TYPE;

typedef struct WOLFSSL_X509_OBJECT {
    WOLFSSL_X509_LOOKUP_TYPE type;
    union {
        char* ptr;
        WOLFSSL_X509 *x509;
        WOLFSSL_X509_CRL* crl;           /* stunnel dereference */
    } data;
} WOLFSSL_X509_OBJECT;

#define WOLFSSL_ASN1_BOOLEAN                int

typedef char* WOLFSSL_STRING;

typedef struct WOLFSSL_RAND_METHOD {
    /* seed = Data to mix into the random generator.
     * len = Number of bytes to mix from seed. */
    int  (*seed)(const void* seed, int len);
    /* buf = Buffer to store random bytes in.
    * len = Number of bytes to store in buf. */
    int  (*bytes)(unsigned char* buf, int len);
    void (*cleanup)(void);
    /* add = Data to mix into the random generator.
     * len = Number of bytes to mix from add.
     * entropy = Estimate of randomness contained in seed.
     *           Should be between 0 and len. */
    int  (*add)(const void* add, int len, double entropy);
    /* buf = Buffer to store pseudorandom bytes in.
     * len = Number of bytes to store in buf. */
    int  (*pseudorand)(unsigned char *buf, int len);
    int  (*status)(void);
} WOLFSSL_RAND_METHOD;

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */


typedef struct WOLFSSL_ALERT {
    int code;
    int level;
} WOLFSSL_ALERT;

typedef struct WOLFSSL_ALERT_HISTORY {
    WOLFSSL_ALERT last_rx;
    WOLFSSL_ALERT last_tx;
} WOLFSSL_ALERT_HISTORY;


/* Valid Alert types from page 16/17
 * Add alert string to the function wolfSSL_alert_type_string_long in src/ssl.c
 */
enum AlertDescription {
    invalid_alert                   =  -1,
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
    unknown_ca                      =  48,
    access_denied                   =  49,
    decode_error                    =  50,
    decrypt_error                   =  51,
    #ifdef WOLFSSL_MYSQL_COMPATIBLE
    /* catch name conflict for enum protocol with MYSQL build */
    wc_protocol_version             =  70,
    #else
    protocol_version                =  70,
    #endif
    insufficient_security           =  71,
    internal_error                  =  80,
    inappropriate_fallback          =  86,
    user_canceled                   =  90,
    no_renegotiation                = 100,
    missing_extension               = 109,
    unsupported_extension           = 110, /**< RFC 5246, section 7.2.2 */
    unrecognized_name               = 112, /**< RFC 6066, section 3 */
    bad_certificate_status_response = 113, /**< RFC 6066, section 8 */
    unknown_psk_identity            = 115, /**< RFC 4279, section 2 */
    certificate_required            = 116, /**< RFC 8446, section 8.2 */
    no_application_protocol         = 120
};

#ifdef WOLFSSL_MYSQL_COMPATIBLE
#define wolfssl_alert_protocol_version wc_protocol_version
#else
#define wolfssl_alert_protocol_version protocol_version
#endif

enum AlertLevel {
    alert_none = 0, /* Used to indicate no alert level is set */
    alert_warning = 1,
    alert_fatal   = 2
};

enum SNICbReturn {
    warning_return = alert_warning,
    fatal_return = alert_fatal,
    noack_return
};

/* WS_RETURN_CODE macro
 * Some OpenSSL APIs specify "0" as the return value when an error occurs.
 * However, some corresponding wolfSSL APIs return negative values. Such
 * functions should use this macro to fill this gap. Users who want them
 * to return the same return value as OpenSSL can define
 * WOLFSSL_ERR_CODE_OPENSSL.
 * Give rc a variable that contains the potentially negative
 * wolfSSL-defined return value or the return value itself, and
 * give fail_rc the openSSL-defined return value.
 * Note that this macro replaces only negative return values with the
 * specified value.
 * Since wolfSSL 4.7.0, the following functions use this macro:
 * - wolfSSL_CTX_load_verify_locations
 * - wolfSSL_X509_LOOKUP_load_file
 * - wolfSSL_EVP_PKEY_cmp
 */
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    #define WS_RETURN_CODE(rc, fail_rc) \
      (((rc) < 0) ? (int)(fail_rc) : (int)(rc))
#else
    #define WS_RETURN_CODE(rc, fail_rc)  (rc)
#endif
#define WS_RC(rc) \
    (((rc) == 1) ? 1 : 0)
#define WC_TO_WS_RC(ret) \
    (((ret) == 0) ? 1 : (ret))

/* Maximum master key length (SECRET_LEN) */
#define WOLFSSL_MAX_MASTER_KEY_LENGTH 48
/* Maximum number of groups that can be set */
#ifdef HAVE_PQC
#define WOLFSSL_MAX_GROUP_COUNT       36
#else
#define WOLFSSL_MAX_GROUP_COUNT       10
#endif

#if defined(HAVE_SECRET_CALLBACK) && defined(WOLFSSL_TLS13)
enum Tls13Secret {
    CLIENT_EARLY_TRAFFIC_SECRET,
    CLIENT_HANDSHAKE_TRAFFIC_SECRET,
    SERVER_HANDSHAKE_TRAFFIC_SECRET,
    CLIENT_TRAFFIC_SECRET,
    SERVER_TRAFFIC_SECRET,
    EARLY_EXPORTER_SECRET,
    EXPORTER_SECRET
};
#endif

#ifndef WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS
#define WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS 10
#endif

typedef WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);

/* CTX Method Constructor Functions */

#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfTLS_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLS_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfTLS_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLS_server_method(void);
#endif
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD* wolfSSLv23_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_server_method(void);
#endif

#ifndef NO_OLD_TLS

#ifdef OPENSSL_EXTRA
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_server_method(void);
#endif
#endif /* OPENSSL_EXTRA */

#ifdef WOLFSSL_ALLOW_SSLV3
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_server_method(void);
#endif
#endif /* WOLFSSL_ALLOW_SSLV3 */

#ifdef WOLFSSL_ALLOW_TLSV10
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_server_method(void);
#endif
#endif /* WOLFSSL_ALLOW_TLSV10 */

    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);
#endif

#endif /* NO_OLD_TLS */

#ifndef WOLFSSL_NO_TLS12
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_client_method_ex(void* heap);
    WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_server_method_ex(void* heap);
    WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);
#endif
#endif /* !WOLFSSL_NO_TLS12 */

#ifdef WOLFSSL_TLS13
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_client_method_ex(void* heap);
    WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_server_method_ex(void* heap);
    WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_server_method(void);
#endif
#endif /* WOLFSSL_TLS13 */

#ifdef WOLFSSL_DTLS

    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_server_method(void);
#endif

#ifndef NO_OLD_TLS
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_server_method(void);
#endif
#endif /* !NO_OLD_TLS */

#ifndef WOLFSSL_NO_TLS12
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_method(void);
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);
#endif
#endif /* !WOLFSSL_NO_TLS12 */

#ifdef WOLFSSL_DTLS13
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_3_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_3_client_method(void);
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_3_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_3_server_method(void);
#endif
#if defined(WOLFSSL_EITHER_SIDE) || defined(OPENSSL_EXTRA)
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_3_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_3_method(void);
#endif
    WOLFSSL_API int wolfSSL_dtls13_has_pending_msg(WOLFSSL *ssl);
#endif /* WOLFSSL_DTLS13 */

#endif /* WOLFSSL_DTLS */

#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH)
WOLFSSL_API int wolfSSL_CTX_GenerateEchConfig(WOLFSSL_CTX* ctx,
    const char* publicName, word16 kemId, word16 kdfId, word16 aeadId);

WOLFSSL_API int wolfSSL_CTX_GetEchConfigs(WOLFSSL_CTX* ctx, byte* output,
    word32* outputLen);

WOLFSSL_API void wolfSSL_CTX_SetEchEnable(WOLFSSL_CTX* ctx, byte enable);

WOLFSSL_API int wolfSSL_SetEchConfigsBase64(WOLFSSL* ssl, char* echConfigs64,
    word32 echConfigs64Len);

WOLFSSL_API int wolfSSL_SetEchConfigs(WOLFSSL* ssl, const byte* echConfigs,
    word32 echConfigsLen);

WOLFSSL_API int wolfSSL_GetEchConfigs(WOLFSSL* ssl, byte* echConfigs,
    word32* echConfigsLen);

WOLFSSL_API void wolfSSL_SetEchEnable(WOLFSSL* ssl, byte enable);
#endif /* WOLFSSL_TLS13 && HAVE_ECH */

#ifdef HAVE_POLY1305
    WOLFSSL_API int wolfSSL_use_old_poly(WOLFSSL* ssl, int value);
#endif

#ifdef WOLFSSL_SESSION_EXPORT
WOLFSSL_API int wolfSSL_tls_import(WOLFSSL* ssl, const unsigned char* buf,
        unsigned int sz);
WOLFSSL_API int wolfSSL_tls_export(WOLFSSL* ssl, unsigned char* buf,
        unsigned int* sz);

#ifdef WOLFSSL_DTLS

#ifndef WOLFSSL_DTLS_EXPORT_TYPES
typedef int (*wc_dtls_export)(WOLFSSL* ssl,
                   unsigned char* exportBuffer, unsigned int sz, void* userCtx);
#define WOLFSSL_DTLS_EXPORT_TYPES
#endif /* WOLFSSL_DTLS_EXPORT_TYPES */

WOLFSSL_API int wolfSSL_dtls_import(WOLFSSL* ssl, const unsigned char* buf,
                                                               unsigned int sz);
WOLFSSL_API int wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx,
                                                           wc_dtls_export func);
WOLFSSL_API int wolfSSL_dtls_set_export(WOLFSSL* ssl, wc_dtls_export func);
WOLFSSL_API int wolfSSL_dtls_export(WOLFSSL* ssl, unsigned char* buf,
                                                              unsigned int* sz);
WOLFSSL_API int wolfSSL_dtls_export_state_only(WOLFSSL* ssl, unsigned char* buf,
                                                              unsigned int* sz);
#endif /* WOLFSSL_DTLS */
#endif /* WOLFSSL_SESSION_EXPORT */

#ifdef WOLFSSL_STATIC_MEMORY
#ifndef WOLFSSL_MEM_GUARD
#define WOLFSSL_MEM_GUARD
    typedef struct WOLFSSL_MEM_STATS      WOLFSSL_MEM_STATS;
    typedef struct WOLFSSL_MEM_CONN_STATS WOLFSSL_MEM_CONN_STATS;
#endif
WOLFSSL_API int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx,
                                            wolfSSL_method_func method,
                                            unsigned char* buf, unsigned int sz,
                                            int flag, int max);
WOLFSSL_API int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx,
                                                 WOLFSSL_MEM_STATS* mem_stats);
WOLFSSL_API int wolfSSL_is_static_memory(WOLFSSL* ssl,
                                            WOLFSSL_MEM_CONN_STATS* mem_stats);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)

WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_use_certificate_file(
    WOLFSSL_CTX* ctx, const char* file, int format);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_file(
    WOLFSSL_CTX* ctx, const char* file, int format);
#ifdef WOLFSSL_DUAL_ALG_CERTS
WOLFSSL_API int wolfSSL_CTX_use_AltPrivateKey_file(
    WOLFSSL_CTX* ctx, const char* file, int format);
#endif /* WOLFSSL_DUAL_ALG_CERTS */
#endif /* !NO_FILESYSTEM && !NO_CERTS */

#ifndef NO_CERTS
#define WOLFSSL_LOAD_FLAG_NONE          0x00000000
#define WOLFSSL_LOAD_FLAG_IGNORE_ERR    0x00000001
#define WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY 0x00000002
#define WOLFSSL_LOAD_FLAG_PEM_CA_ONLY   0x00000004
#if defined(WOLFSSL_QT) || defined(WOLFSSL_IGNORE_BAD_CERT_PATH)
#define WOLFSSL_LOAD_FLAG_IGNORE_BAD_PATH_ERR 0x00000008
#endif
#if defined(WOLFSSL_QT)
#define WOLFSSL_LOAD_FLAG_IGNORE_ZEROFILE     0x00000010
#endif

#ifndef WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS
#define WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS WOLFSSL_LOAD_FLAG_NONE
#endif

WOLFSSL_API long wolfSSL_get_verify_depth(WOLFSSL* ssl);
WOLFSSL_API long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx);
WOLFSSL_API void wolfSSL_CTX_set_verify_depth(WOLFSSL_CTX *ctx,int depth);
#endif /* !NO_CERTS */

#define WOLFSSL_CIPHER_SUITE_FLAG_NONE          0x0
#define WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS     0x1

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)

WOLFSSL_API int wolfSSL_CTX_load_verify_locations_ex(
    WOLFSSL_CTX* ctx, const char* file, const char* path, word32 flags);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_load_verify_locations(
    WOLFSSL_CTX* ctx, const char* file, const char* path);
WOLFSSL_API int wolfSSL_CTX_load_verify_locations_compat(
    WOLFSSL_CTX* ctx, const char* file, const char* path);
#ifndef _WIN32
WOLFSSL_API const char** wolfSSL_get_system_CA_dirs(word32* num);
#endif /* !_WIN32 */
WOLFSSL_API int wolfSSL_CTX_load_system_CA_certs(WOLFSSL_CTX* ctx);
#ifdef WOLFSSL_TRUST_PEER_CERT
WOLFSSL_API int wolfSSL_CTX_trust_peer_cert(
    WOLFSSL_CTX* ctx, const char* file, int type);
WOLFSSL_API int wolfSSL_trust_peer_cert(
    WOLFSSL* ssl, const char* file, int type);
#endif
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_file(
    WOLFSSL_CTX* ctx, const char* file);
WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_file_format(
    WOLFSSL_CTX* ctx, const char* file, int format);
WOLFSSL_API int wolfSSL_CTX_use_RSAPrivateKey_file(
    WOLFSSL_CTX* ctx,const char* file, int format);

WOLFSSL_ABI WOLFSSL_API int wolfSSL_use_certificate_file(
    WOLFSSL* ssl, const char* file, int format);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_use_PrivateKey_file(
    WOLFSSL* ssl, const char* file, int format);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_use_certificate_chain_file(
    WOLFSSL* ssl, const char* file);
WOLFSSL_API int wolfSSL_use_certificate_chain_file_format(
    WOLFSSL* ssl, const char* file, int format);
WOLFSSL_API int wolfSSL_use_RSAPrivateKey_file(
    WOLFSSL* ssl, const char* file, int format);

#ifdef WOLFSSL_DER_LOAD
    WOLFSSL_API int wolfSSL_CTX_der_load_verify_locations(
        WOLFSSL_CTX* ctx, const char* file, int format);
#endif
#endif /* !NO_FILESYSTEM && !NO_CERTS */

WOLFSSL_API WOLFSSL_CTX* wolfSSL_CTX_new_ex(WOLFSSL_METHOD* method, void* heap);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD* method);
WOLFSSL_API int wolfSSL_CTX_up_ref(WOLFSSL_CTX* ctx);
#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_set_ecdh_auto(WOLFSSL* ssl, int onoff);
WOLFSSL_API int wolfSSL_CTX_set_ecdh_auto(WOLFSSL_CTX* ctx, int onoff);
WOLFSSL_API int wolfSSL_CTX_set_dh_auto(WOLFSSL_CTX* ctx, int onoff);
WOLFSSL_API int wolfSSL_get_signature_nid(WOLFSSL* ssl, int* nid);
WOLFSSL_API int wolfSSL_get_signature_type_nid(const WOLFSSL* ssl, int* nid);
WOLFSSL_API int wolfSSL_get_peer_signature_nid(WOLFSSL* ssl, int* nid);
WOLFSSL_API int wolfSSL_get_peer_signature_type_nid(const WOLFSSL* ssl,
        int* nid);
WOLFSSL_API int  wolfSSL_CTX_set1_sigalgs_list(WOLFSSL_CTX* ctx,
                                               const char* list);
WOLFSSL_API int  wolfSSL_set1_sigalgs_list(WOLFSSL* ssl, const char* list);
#endif
WOLFSSL_ABI WOLFSSL_API WOLFSSL* wolfSSL_new(WOLFSSL_CTX* ctx);
WOLFSSL_API WOLFSSL_CTX* wolfSSL_get_SSL_CTX(const WOLFSSL* ssl);
WOLFSSL_API WOLFSSL_X509_VERIFY_PARAM* wolfSSL_CTX_get0_param(WOLFSSL_CTX* ctx);
WOLFSSL_API WOLFSSL_X509_VERIFY_PARAM* wolfSSL_get0_param(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_set1_param(WOLFSSL_CTX* ctx, WOLFSSL_X509_VERIFY_PARAM *vpm);
WOLFSSL_API int  wolfSSL_is_server(WOLFSSL* ssl);
WOLFSSL_API WOLFSSL* wolfSSL_write_dup(WOLFSSL* ssl);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_set_fd(WOLFSSL* ssl, int fd);
#ifdef WOLFSSL_DTLS
WOLFSSL_API int wolfSSL_set_dtls_fd_connected(WOLFSSL* ssl, int fd);
#endif
WOLFSSL_API int  wolfSSL_set_write_fd (WOLFSSL* ssl, int fd);
WOLFSSL_API int  wolfSSL_set_read_fd (WOLFSSL* ssl, int fd);
WOLFSSL_API char* wolfSSL_get_cipher_list(int priority);
WOLFSSL_API char* wolfSSL_get_cipher_list_ex(WOLFSSL* ssl, int priority);
WOLFSSL_API int  wolfSSL_get_ciphers(char* buf, int len);
WOLFSSL_API int wolfSSL_get_ciphers_iana(char* buf, int len);
WOLFSSL_API const char* wolfSSL_get_cipher_name(WOLFSSL* ssl);
WOLFSSL_API const char* wolfSSL_get_cipher_name_from_suite(
    unsigned char cipherSuite0, unsigned char cipherSuite);
WOLFSSL_API const char* wolfSSL_get_cipher_name_iana_from_suite(
    unsigned char cipherSuite0, unsigned char cipherSuite);
WOLFSSL_API int wolfSSL_get_cipher_suite_from_name(const char* name,
    unsigned char* cipherSuite0, unsigned char* cipherSuite, int *flags);
WOLFSSL_API const char* wolfSSL_get_shared_ciphers(WOLFSSL* ssl, char* buf,
    int len);
WOLFSSL_API const char* wolfSSL_get_curve_name(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_get_fd(const WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_get_wfd(const WOLFSSL* ssl);
/* please see note at top of README if you get an error from connect */
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_connect(WOLFSSL* ssl);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_write(
    WOLFSSL* ssl, const void* data, int sz);
WOLFSSL_API int wolfSSL_write_ex(WOLFSSL* ssl, const void* data, size_t sz,
    size_t* wr);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_read(WOLFSSL* ssl, void* data, int sz);
WOLFSSL_API int wolfSSL_read_ex(WOLFSSL* ssl, void* data, size_t sz, size_t* rd);
WOLFSSL_API int  wolfSSL_peek(WOLFSSL* ssl, void* data, int sz);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_accept(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_inject(WOLFSSL* ssl, const void* data, int sz);
WOLFSSL_API int  wolfSSL_CTX_mutual_auth(WOLFSSL_CTX* ctx, int req);
WOLFSSL_API int  wolfSSL_mutual_auth(WOLFSSL* ssl, int req);

WOLFSSL_API int  wolfSSL_CTX_set_groups(WOLFSSL_CTX* ctx, int* groups,
                                        int count);
WOLFSSL_API int  wolfSSL_set_groups(WOLFSSL* ssl, int* groups, int count);
#if defined(OPENSSL_EXTRA) && defined(HAVE_SUPPORTED_CURVES)
WOLFSSL_API int  wolfSSL_CTX_set1_groups(WOLFSSL_CTX* ctx, int* groups,
                                        int count);
WOLFSSL_API int  wolfSSL_set1_groups(WOLFSSL* ssl, int* groups, int count);

#ifdef HAVE_ECC
WOLFSSL_API int  wolfSSL_CTX_set1_groups_list(WOLFSSL_CTX *ctx, const char *list);
WOLFSSL_API int  wolfSSL_set1_groups_list(WOLFSSL *ssl, const char *list);
#endif
#endif

#ifdef WOLFSSL_TLS13
WOLFSSL_API int  wolfSSL_send_hrr_cookie(WOLFSSL* ssl,
    const unsigned char* secret, unsigned int secretSz);
WOLFSSL_API int  wolfSSL_disable_hrr_cookie(WOLFSSL * ssl);
WOLFSSL_API int  wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_no_dhe_psk(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_CTX_only_dhe_psk(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_only_dhe_psk(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_update_keys(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_key_update_response(WOLFSSL* ssl, int* required);
WOLFSSL_API int  wolfSSL_CTX_allow_post_handshake_auth(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_allow_post_handshake_auth(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_request_certificate(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_preferred_group(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_connect_TLSv13(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_accept_TLSv13(WOLFSSL* ssl);

#ifdef WOLFSSL_EARLY_DATA

#define WOLFSSL_EARLY_DATA_NOT_SENT    0
#define WOLFSSL_EARLY_DATA_REJECTED    1
#define WOLFSSL_EARLY_DATA_ACCEPTED    2

WOLFSSL_API int  wolfSSL_CTX_set_max_early_data(WOLFSSL_CTX* ctx,
                                                unsigned int sz);
WOLFSSL_API int  wolfSSL_set_max_early_data(WOLFSSL* ssl, unsigned int sz);
WOLFSSL_API int  wolfSSL_CTX_get_max_early_data(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_get_max_early_data(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_write_early_data(WOLFSSL* ssl, const void* data,
                                          int sz, int* outSz);
WOLFSSL_API int  wolfSSL_read_early_data(WOLFSSL* ssl, void* data, int sz,
                                         int* outSz);
WOLFSSL_API int  wolfSSL_get_early_data_status(const WOLFSSL* ssl);
#ifdef OPENSSL_EXTRA
WOLFSSL_API unsigned int wolfSSL_SESSION_get_max_early_data(const WOLFSSL_SESSION *s);
#endif /* OPENSSL_EXTRA */
#endif /* WOLFSSL_EARLY_DATA */
#endif /* WOLFSSL_TLS13 */
WOLFSSL_ABI WOLFSSL_API void wolfSSL_CTX_free(WOLFSSL_CTX* ctx);
WOLFSSL_ABI WOLFSSL_API void wolfSSL_free(WOLFSSL* ssl);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_shutdown(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SendUserCanceled(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags);
WOLFSSL_API int  wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags);

WOLFSSL_API void wolfSSL_CTX_set_quiet_shutdown(WOLFSSL_CTX* ctx, int mode);
WOLFSSL_API void wolfSSL_set_quiet_shutdown(WOLFSSL* ssl, int mode);

WOLFSSL_ABI WOLFSSL_API int  wolfSSL_get_error(WOLFSSL* ssl, int ret);

WOLFSSL_ABI WOLFSSL_API int  wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session);
WOLFSSL_API long wolfSSL_SSL_SESSION_set_timeout(WOLFSSL_SESSION* ses, long t);
WOLFSSL_API long wolfSSL_SESSION_set_time(WOLFSSL_SESSION *ses, long t);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl);
WOLFSSL_ABI WOLFSSL_API void wolfSSL_flush_sessions(WOLFSSL_CTX* ctx, long tm);
WOLFSSL_API void wolfSSL_CTX_flush_sessions(WOLFSSL_CTX* ctx, long tm);
WOLFSSL_API int  wolfSSL_SetServerID(WOLFSSL* ssl, const unsigned char* id, int len, int newSession);

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX)
WOLFSSL_API int  wolfSSL_BIO_new_bio_pair(WOLFSSL_BIO** bio1_p, size_t writebuf1,
                     WOLFSSL_BIO** bio2_p, size_t writebuf2);

WOLFSSL_API int wolfSSL_RSA_padding_add_PKCS1_PSS_mgf1(WOLFSSL_RSA *rsa,
        unsigned char *em, const unsigned char *mHash,
        const WOLFSSL_EVP_MD *hashAlg, const WOLFSSL_EVP_MD *mgf1Hash,
        int saltLen);
WOLFSSL_API int wolfSSL_RSA_padding_add_PKCS1_PSS(WOLFSSL_RSA *rsa,
                                                  unsigned char *EM,
                                                  const unsigned char *mHash,
                                                  const WOLFSSL_EVP_MD *hashAlg,
                                                  int saltLen);
WOLFSSL_API int wolfSSL_RSA_verify_PKCS1_PSS_mgf1(WOLFSSL_RSA *rsa,
        const unsigned char *mHash, const WOLFSSL_EVP_MD *hashAlg,
        const WOLFSSL_EVP_MD *mgf1Hash, const unsigned char *em, int saltLen);
WOLFSSL_API int wolfSSL_RSA_verify_PKCS1_PSS(WOLFSSL_RSA *rsa, const unsigned char *mHash,
                                          const WOLFSSL_EVP_MD *hashAlg,
                                          const unsigned char *EM, int saltLen);
WOLFSSL_API WOLFSSL_RSA* wolfSSL_d2i_RSAPrivateKey_bio(WOLFSSL_BIO* bio, WOLFSSL_RSA** out);
WOLFSSL_API int wolfSSL_CTX_use_certificate_ASN1(WOLFSSL_CTX* ctx,
                                           int derSz, const unsigned char* der);
WOLFSSL_API int wolfSSL_CTX_use_RSAPrivateKey(WOLFSSL_CTX* ctx, WOLFSSL_RSA* rsa);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_bio(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY** pkey);
#endif /* OPENSSL_ALL || WOLFSSL_ASIO */

#ifdef SESSION_INDEX
WOLFSSL_API int wolfSSL_GetSessionIndex(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_GetSessionAtIndex(int index, WOLFSSL_SESSION* session);
#endif /* SESSION_INDEX */


#ifdef OPENSSL_EXTRA
/* compatibility callback for TLS state */
typedef void (CallbackInfoState)(const WOLFSSL* ssl, int state, int err);
#endif


/* ----- EX DATA BEGIN ----- */
WOLFSSL_API void* wolfSSL_get_ex_data(const WOLFSSL* ssl, int idx);
WOLFSSL_API int  wolfSSL_set_ex_data(WOLFSSL* ssl, int idx, void* data);

#ifdef HAVE_EX_DATA
WOLFSSL_API void wolfSSL_CRYPTO_cleanup_all_ex_data(void);
WOLFSSL_API void* wolfSSL_CRYPTO_get_ex_data(
    const WOLFSSL_CRYPTO_EX_DATA* ex_data, int idx);
WOLFSSL_API int wolfSSL_CRYPTO_set_ex_data(
    WOLFSSL_CRYPTO_EX_DATA* ex_data, int idx, void *data);

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
WOLFSSL_API int wolfSSL_CRYPTO_set_ex_data_with_cleanup(
    WOLFSSL_CRYPTO_EX_DATA* ex_data,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
WOLFSSL_API int wolfSSL_set_ex_data_with_cleanup(
    WOLFSSL* ssl,
    int idx,
    void* data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
#endif

#ifdef HAVE_EX_DATA_CRYPTO
/* class index for wolfSSL_CRYPTO_get_ex_new_index */
#define WOLF_CRYPTO_EX_INDEX_SSL             0
#define WOLF_CRYPTO_EX_INDEX_SSL_CTX         1
#define WOLF_CRYPTO_EX_INDEX_SSL_SESSION     2
#define WOLF_CRYPTO_EX_INDEX_X509            3
#define WOLF_CRYPTO_EX_INDEX_X509_STORE      4
#define WOLF_CRYPTO_EX_INDEX_X509_STORE_CTX  5
#define WOLF_CRYPTO_EX_INDEX_DH              6
#define WOLF_CRYPTO_EX_INDEX_DSA             7
#define WOLF_CRYPTO_EX_INDEX_EC_KEY          8
#define WOLF_CRYPTO_EX_INDEX_RSA             9
#define WOLF_CRYPTO_EX_INDEX_ENGINE          10
#define WOLF_CRYPTO_EX_INDEX_UI              11
#define WOLF_CRYPTO_EX_INDEX_BIO             12
#define WOLF_CRYPTO_EX_INDEX_APP             13
#define WOLF_CRYPTO_EX_INDEX_UI_METHOD       14
#define WOLF_CRYPTO_EX_INDEX_DRBG            15
#define WOLF_CRYPTO_EX_INDEX__COUNT          16

/* Helper macro to log that input arguments should not be used */
#define WOLFSSL_CRYPTO_EX_DATA_IGNORE_PARAMS(a1, a2, a3, a4, a5) \
    (void)(a1);                                                  \
    (void)(a2);                                                  \
    (void)(a3);                                                  \
    (void)(a4);                                                  \
    (void)(a5);                                                  \
    do {                                                         \
        if ((a3) != NULL || (a4) != NULL || (a5) != NULL) {      \
            WOLFSSL_MSG("get_ex_new_index API does not support " \
                        "new, dup, or free callbacks");          \
        }                                                        \
    } while(0)

WOLFSSL_API int wolfSSL_get_ex_new_index(
    long argValue, void* arg,
    WOLFSSL_CRYPTO_EX_new* a, WOLFSSL_CRYPTO_EX_dup* b,
    WOLFSSL_CRYPTO_EX_free* c);
WOLFSSL_API int wolfSSL_CTX_get_ex_new_index(
    long idx, void* arg,
    WOLFSSL_CRYPTO_EX_new* new_func,
    WOLFSSL_CRYPTO_EX_dup* dup_func,
    WOLFSSL_CRYPTO_EX_free* free_func);
WOLFSSL_API int wolfSSL_CRYPTO_get_ex_new_index(
    int class_index, long argl, void *argp,
    WOLFSSL_CRYPTO_EX_new* new_func,
    WOLFSSL_CRYPTO_EX_dup* dup_func,
    WOLFSSL_CRYPTO_EX_free* free_func);
WOLFSSL_API int wolfSSL_SESSION_get_ex_new_index(long ctx_l,void* ctx_ptr,
        WOLFSSL_CRYPTO_EX_new* new_func, WOLFSSL_CRYPTO_EX_dup* dup_func,
        WOLFSSL_CRYPTO_EX_free* free_func);
#endif /* HAVE_EX_DATA_CRYPTO */
#endif /* HAVE_EX_DATA */

/* Exposed EX data API's, guarded internally by HAVE_EX_DATA */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
WOLFSSL_API void *wolfSSL_X509_get_ex_data(WOLFSSL_X509 *x509, int idx);
WOLFSSL_API int wolfSSL_X509_set_ex_data(WOLFSSL_X509 *x509, int idx,
    void *data);
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
WOLFSSL_API int wolfSSL_X509_set_ex_data_with_cleanup(
    WOLFSSL_X509 *x509,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
#endif

#ifdef HAVE_EX_DATA_CRYPTO
WOLFSSL_API int wolfSSL_X509_get_ex_new_index(int idx, void *arg,
    WOLFSSL_CRYPTO_EX_new* new_func,
    WOLFSSL_CRYPTO_EX_dup* dup_func,
    WOLFSSL_CRYPTO_EX_free* free_func);
#endif
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
WOLFSSL_API void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX* ctx, int idx);
WOLFSSL_API int   wolfSSL_CTX_set_ex_data(WOLFSSL_CTX* ctx, int idx, void* data);
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
WOLFSSL_API int wolfSSL_CTX_set_ex_data_with_cleanup(
    WOLFSSL_CTX* ctx,
    int idx,
    void* data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
#endif
#endif /* OPENSSL_EXTRA */
/* ----- EX DATA END ----- */

WOLFSSL_ABI WOLFSSL_API void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode,
                                      VerifyCallback verify_callback);

#ifdef OPENSSL_ALL
typedef int (*CertVerifyCallback)(WOLFSSL_X509_STORE_CTX* store, void* arg);
WOLFSSL_API void wolfSSL_CTX_set_cert_verify_callback(WOLFSSL_CTX* ctx,
    CertVerifyCallback cb, void* arg);
#endif

WOLFSSL_API void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback verify_callback);
WOLFSSL_API void wolfSSL_set_verify_result(WOLFSSL* ssl, long v);

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
WOLFSSL_API int wolfSSL_verify_client_post_handshake(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_set_post_handshake_auth(WOLFSSL_CTX* ctx, int val);
WOLFSSL_API int wolfSSL_set_post_handshake_auth(WOLFSSL* ssl, int val);
#endif

WOLFSSL_API void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx);
WOLFSSL_API void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx);

WOLFSSL_ABI WOLFSSL_API int  wolfSSL_pending(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_has_pending(const WOLFSSL* ssl);

WOLFSSL_API void wolfSSL_load_error_strings(void);
WOLFSSL_API int  wolfSSL_library_init(void);
WOLFSSL_ABI WOLFSSL_API long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX* ctx,
                                                                          long mode);

#ifdef HAVE_SECRET_CALLBACK
typedef int (*SessionSecretCb)(WOLFSSL* ssl, void* secret, int* secretSz,
                               void* ctx);
/* This callback is used to set the master secret during resumption */
WOLFSSL_API int  wolfSSL_set_session_secret_cb(WOLFSSL* ssl, SessionSecretCb cb,
                                               void* ctx);
typedef int (*TicketParseCb)(WOLFSSL *ssl, const unsigned char *data,
                                            int len, void *ctx);
WOLFSSL_API int wolfSSL_set_session_ticket_ext_cb(WOLFSSL* ssl,
        TicketParseCb cb, void *ctx);
typedef int (*TlsSecretCb)(WOLFSSL* ssl, void* secret, int secretSz,
                               void* ctx);
/* This callback is used to log the secret for TLS <= 1.2 */
WOLFSSL_API int wolfSSL_set_secret_cb(WOLFSSL* ssl, TlsSecretCb cb, void* ctx);
#ifdef WOLFSSL_TLS13
typedef int (*Tls13SecretCb)(WOLFSSL* ssl, int id, const unsigned char* secret,
                             int secretSz, void* ctx);
WOLFSSL_API int  wolfSSL_set_tls13_secret_cb(WOLFSSL* ssl, Tls13SecretCb, void*);
#endif
#endif /* HAVE_SECRET_CALLBACK */

/* session cache persistence */
WOLFSSL_API int  wolfSSL_save_session_cache(const char* fname);
WOLFSSL_API int  wolfSSL_restore_session_cache(const char* fname);
WOLFSSL_API int  wolfSSL_memsave_session_cache(void* mem, int sz);
WOLFSSL_API int  wolfSSL_memrestore_session_cache(const void* mem, int sz);
WOLFSSL_API int  wolfSSL_get_session_cache_memsize(void);

/* certificate cache persistence, uses ctx since certs are per ctx */
WOLFSSL_API int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname);
WOLFSSL_API int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname);
WOLFSSL_API int  wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem, int sz, int* used);
WOLFSSL_API int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz);
WOLFSSL_API int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx);

/* only supports full name from cipher_name[] delimited by : */
WOLFSSL_API int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);
WOLFSSL_API int  wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list);

/* supports 2 byte code from cipher_name[] */
WOLFSSL_API int  wolfSSL_CTX_set_cipher_list_bytes(WOLFSSL_CTX* ctx, const byte* list, const int listSz);
WOLFSSL_API int  wolfSSL_set_cipher_list_bytes(WOLFSSL* ssl, const byte* list, const int listSz);

#ifdef HAVE_KEYING_MATERIAL
/* Keying Material Exporter for TLS */
WOLFSSL_API int wolfSSL_export_keying_material(WOLFSSL *ssl,
        unsigned char *out, size_t outLen,
        const char *label, size_t labelLen,
        const unsigned char *context, size_t contextLen,
        int use_context);
#endif /* HAVE_KEYING_MATERIAL */

#ifdef WOLFSSL_WOLFSENTRY_HOOKS

typedef enum {
    WOLFSSL_NETFILTER_PASS = 0,
    WOLFSSL_NETFILTER_ACCEPT = 1,
    WOLFSSL_NETFILTER_REJECT = 2
} wolfSSL_netfilter_decision_t;

typedef int (*NetworkFilterCallback_t)(
    WOLFSSL *ssl,
    void *AcceptFilter_arg,
    wolfSSL_netfilter_decision_t *decision);
WOLFSSL_API int wolfSSL_CTX_set_AcceptFilter(
    WOLFSSL_CTX *ctx,
    NetworkFilterCallback_t AcceptFilter,
    void *AcceptFilter_arg);
WOLFSSL_API int wolfSSL_set_AcceptFilter(
    WOLFSSL *ssl,
    NetworkFilterCallback_t AcceptFilter,
    void *AcceptFilter_arg);
WOLFSSL_API int wolfSSL_CTX_set_ConnectFilter(
    WOLFSSL_CTX *ctx,
    NetworkFilterCallback_t ConnectFilter,
    void *ConnectFilter_arg);
WOLFSSL_API int wolfSSL_set_ConnectFilter(
    WOLFSSL *ssl,
    NetworkFilterCallback_t ConnectFilter,
    void *ConnectFilter_arg);

#endif /* WOLFSSL_WOLFSENTRY_HOOKS */

/* Nonblocking DTLS helper functions */
WOLFSSL_API void wolfSSL_dtls_set_using_nonblock(WOLFSSL* ssl, int nonblock);
WOLFSSL_API int  wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl);
#define wolfSSL_set_using_nonblock wolfSSL_dtls_set_using_nonblock
#define wolfSSL_get_using_nonblock wolfSSL_dtls_get_using_nonblock
    /* The old names are deprecated. */
WOLFSSL_API int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_dtls13_use_quick_timeout(WOLFSSL* ssl);
WOLFSSL_API void wolfSSL_dtls13_set_send_more_acks(WOLFSSL* ssl, int value);
WOLFSSL_API int  wolfSSL_DTLSv1_get_timeout(WOLFSSL* ssl,
        WOLFSSL_TIMEVAL* timeleft);
WOLFSSL_API void wolfSSL_DTLSv1_set_initial_timeout_duration(WOLFSSL* ssl,
    word32 duration_ms);
WOLFSSL_API int  wolfSSL_DTLSv1_handle_timeout(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int timeout);
WOLFSSL_API int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int timeout);
WOLFSSL_API int  wolfSSL_dtls_got_timeout(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_dtls_retransmit(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_dtls(WOLFSSL* ssl);

WOLFSSL_API void* wolfSSL_dtls_create_peer(int port, char* ip);
WOLFSSL_API int   wolfSSL_dtls_free_peer(void* addr);

WOLFSSL_API int  wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer,
                                       unsigned int peerSz);
WOLFSSL_API int wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer,
                                              unsigned int peerSz);
WOLFSSL_API int  wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer,
                                       unsigned int* peerSz);
WOLFSSL_API int  wolfSSL_dtls_get0_peer(WOLFSSL* ssl, const void** peer,
                                        unsigned int* peerSz);

WOLFSSL_API byte wolfSSL_is_stateful(WOLFSSL* ssl);

#if defined(WOLFSSL_SCTP) && defined(WOLFSSL_DTLS)
WOLFSSL_API int  wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_dtls_set_sctp(WOLFSSL* ssl);
#endif
#if (defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)) && \
                                                           defined(WOLFSSL_DTLS)
WOLFSSL_API int  wolfSSL_CTX_dtls_set_mtu(WOLFSSL_CTX* ctx, unsigned short mtu);
WOLFSSL_API int  wolfSSL_dtls_set_mtu(WOLFSSL* ssl, unsigned short mtu);
#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
WOLFSSL_API int  wolfSSL_set_mtu_compat(WOLFSSL* ssl, unsigned short mtu);
#endif
#endif

#ifdef WOLFSSL_SRTP

/* SRTP Profile ID's from RFC 5764 and RFC 7714 */
/* For WebRTC support for profile SRTP_AES128_CM_SHA1_80 is required per
 * draft-ietf-rtcweb-security-arch) */
#define SRTP_AES128_CM_SHA1_80 0x0001
#define SRTP_AES128_CM_SHA1_32 0x0002
#define SRTP_AES128_F8_SHA1_80 0x0003 /* not supported */
#define SRTP_AES128_F8_SHA1_32 0x0004 /* not supported */
#define SRTP_NULL_SHA1_80      0x0005
#define SRTP_NULL_SHA1_32      0x0006
#define SRTP_AEAD_AES_128_GCM  0x0007
#define SRTP_AEAD_AES_256_GCM  0x0008

typedef struct WOLFSSL_SRTP_PROTECTION_PROFILE {
    const char*   name;
    unsigned long id;
    int           kdfBits;
} WOLFSSL_SRTP_PROTECTION_PROFILE;

/* Compatibility API's for SRTP */
WOLFSSL_API int wolfSSL_CTX_set_tlsext_use_srtp(WOLFSSL_CTX* ctx,
                                                const char* profile_str);
WOLFSSL_API int wolfSSL_set_tlsext_use_srtp(WOLFSSL* ssl,
                                const char* wolfSSL_set_tlsext_use_srtp);
WOLFSSL_API const WOLFSSL_SRTP_PROTECTION_PROFILE*
                wolfSSL_get_selected_srtp_profile(WOLFSSL* ssl);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_SRTP_PROTECTION_PROFILE)*
    wolfSSL_get_srtp_profiles(WOLFSSL* ssl);

/* Non standard API for getting the SRTP session keys using KDF */
WOLFSSL_API int wolfSSL_export_dtls_srtp_keying_material(WOLFSSL* ssl,
    unsigned char* out, size_t* olen);
#endif /* WOLFSSL_SRTP */

WOLFSSL_API int  wolfSSL_dtls_get_drop_stats(WOLFSSL* ssl,
                                             unsigned int*, unsigned int*);
WOLFSSL_API int  wolfSSL_CTX_mcast_set_member_id(WOLFSSL_CTX* ctx, unsigned short id);
WOLFSSL_API int  wolfSSL_set_secret(WOLFSSL* ssl, unsigned short epoch,
                     const unsigned char* preMasterSecret, unsigned int preMasterSz,
                     const unsigned char* clientRandom, const unsigned char* serverRandom,
                     const unsigned char* suite);
WOLFSSL_API int  wolfSSL_mcast_read(WOLFSSL* ssl, unsigned short* id, void* data, int sz);
WOLFSSL_API int  wolfSSL_mcast_peer_add(WOLFSSL* ssl, unsigned short peerId, int sub);
WOLFSSL_API int  wolfSSL_mcast_peer_known(WOLFSSL* ssl, unsigned short peerId);
WOLFSSL_API int  wolfSSL_mcast_get_max_peers(void);
typedef int (*CallbackMcastHighwater)(unsigned short peerId,
                                      unsigned int maxSeq,
                                      unsigned int curSeq, void* ctx);
WOLFSSL_API int  wolfSSL_CTX_mcast_set_highwater_cb(WOLFSSL_CTX* ctx,
                                                    unsigned int maxSeq,
                                                    unsigned int first,
                                                    unsigned int second,
                                                    CallbackMcastHighwater cb);
WOLFSSL_API int  wolfSSL_mcast_set_highwater_ctx(WOLFSSL* ssl, void* ctx);

WOLFSSL_API int   wolfSSL_ERR_GET_LIB(unsigned long err);
WOLFSSL_API int   wolfSSL_ERR_GET_REASON(unsigned long err);
WOLFSSL_API char* wolfSSL_ERR_error_string(unsigned long errNumber,char* data);
WOLFSSL_API void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long sz);
WOLFSSL_API const char* wolfSSL_ERR_reason_error_string(unsigned long e);
WOLFSSL_API const char* wolfSSL_ERR_func_error_string(unsigned long e);
WOLFSSL_API const char* wolfSSL_ERR_lib_error_string(unsigned long e);

/* -------- EXTRAS BEGIN -------- */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
WOLFSSL_API void wolfSSL_ERR_print_errors(WOLFSSL_BIO *bio);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap);
WOLFSSL_API void wolfSSL_sk_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_free_node(WOLFSSL_STACK* in);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_dup(WOLFSSL_STACK* sk);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_shallow_sk_dup(WOLFSSL_STACK* sk);
WOLFSSL_API int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* in);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* sk, int idx);
WOLFSSL_API int wolfSSL_sk_push(WOLFSSL_STACK *st, const void *data);
WOLFSSL_API int wolfSSL_sk_insert(WOLFSSL_STACK *sk, const void *data, int idx);

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(WOLFSSL_QT)
WOLFSSL_API int wolfSSL_sk_ACCESS_DESCRIPTION_push(
                                       WOLF_STACK_OF(ACCESS_DESCRIPTION)* sk,
                                       WOLFSSL_ACCESS_DESCRIPTION* a);
#endif /* OPENSSL_ALL || OPENSSL_EXTRA || WOLFSSL_QT */

typedef WOLF_STACK_OF(WOLFSSL_GENERAL_NAME) WOLFSSL_GENERAL_NAMES;
typedef WOLF_STACK_OF(WOLFSSL_DIST_POINT) WOLFSSL_DIST_POINTS;

WOLFSSL_API int wolfSSL_sk_X509_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
                                                            WOLFSSL_X509* x509);
WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_pop(WOLF_STACK_OF(WOLFSSL_X509)* sk);
WOLFSSL_API void wolfSSL_sk_X509_free(WOLF_STACK_OF(WOLFSSL_X509)* sk);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_CRL_new(void);
WOLFSSL_API void wolfSSL_sk_X509_CRL_pop_free(WOLF_STACK_OF(WOLFSSL_X509_CRL)* sk,
    void (*f) (WOLFSSL_X509_CRL*));
WOLFSSL_API void wolfSSL_sk_X509_CRL_free(WOLF_STACK_OF(WOLFSSL_X509_CRL)* sk);
WOLFSSL_API int wolfSSL_sk_X509_CRL_push(WOLF_STACK_OF(WOLFSSL_X509_CRL)* sk,
        WOLFSSL_X509_CRL* crl);
WOLFSSL_API WOLFSSL_X509_CRL* wolfSSL_sk_X509_CRL_value(
        WOLF_STACK_OF(WOLFSSL_X509)* sk, int i);
WOLFSSL_API int wolfSSL_sk_X509_CRL_num(WOLF_STACK_OF(WOLFSSL_X509)* sk);

WOLFSSL_API WOLFSSL_GENERAL_NAME* wolfSSL_GENERAL_NAME_new(void);
WOLFSSL_API void wolfSSL_GENERAL_NAME_free(WOLFSSL_GENERAL_NAME* gn);
WOLFSSL_API WOLFSSL_GENERAL_NAME* wolfSSL_GENERAL_NAME_dup(
    WOLFSSL_GENERAL_NAME* gn);
WOLFSSL_API int wolfSSL_GENERAL_NAME_set_type(WOLFSSL_GENERAL_NAME* name,
        int typ);
WOLFSSL_API WOLFSSL_GENERAL_NAMES* wolfSSL_GENERAL_NAMES_dup(
                                             WOLFSSL_GENERAL_NAMES* gns);
WOLFSSL_API int wolfSSL_GENERAL_NAME_set0_othername(WOLFSSL_GENERAL_NAME* gen,
                                                    WOLFSSL_ASN1_OBJECT* oid,
                                                    WOLFSSL_ASN1_TYPE* value);
WOLFSSL_API void wolfSSL_GENERAL_NAME_set0_value(WOLFSSL_GENERAL_NAME *a,
                                                 int type, void *value);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_GENERAL_NAME_new(void *cmpFunc);
WOLFSSL_API int wolfSSL_sk_GENERAL_NAME_push(WOLFSSL_GENERAL_NAMES* sk,
                                             WOLFSSL_GENERAL_NAME* gn);
WOLFSSL_API WOLFSSL_GENERAL_NAME* wolfSSL_sk_GENERAL_NAME_value(
        WOLFSSL_STACK* sk, int i);
WOLFSSL_API int wolfSSL_sk_GENERAL_NAME_num(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_GENERAL_NAME_pop_free(WOLFSSL_STACK* sk,
                                       void (*f) (WOLFSSL_GENERAL_NAME*));
WOLFSSL_API void wolfSSL_sk_GENERAL_NAME_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_GENERAL_NAMES_free(WOLFSSL_GENERAL_NAMES* name);
WOLFSSL_API int wolfSSL_GENERAL_NAME_print(WOLFSSL_BIO* out,
                                           WOLFSSL_GENERAL_NAME* name);
WOLFSSL_API void wolfSSL_EXTENDED_KEY_USAGE_free(WOLFSSL_STACK * sk);

WOLFSSL_API WOLFSSL_DIST_POINT* wolfSSL_DIST_POINT_new(void);
WOLFSSL_API void wolfSSL_DIST_POINT_free(WOLFSSL_DIST_POINT* dp);
WOLFSSL_API int wolfSSL_sk_DIST_POINT_push(WOLFSSL_DIST_POINTS* sk,
                                             WOLFSSL_DIST_POINT* dp);
WOLFSSL_API WOLFSSL_DIST_POINT* wolfSSL_sk_DIST_POINT_value(
        WOLFSSL_STACK* sk, int i);
WOLFSSL_API int wolfSSL_sk_DIST_POINT_num(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_DIST_POINT_pop_free(WOLFSSL_STACK* sk,
                                       void (*f) (WOLFSSL_DIST_POINT*));
WOLFSSL_API void wolfSSL_sk_DIST_POINT_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_DIST_POINTS_free(WOLFSSL_DIST_POINTS* dp);

WOLFSSL_API int wolfSSL_sk_ACCESS_DESCRIPTION_num(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_AUTHORITY_INFO_ACCESS_free(
        WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)* sk);
WOLFSSL_API void wolfSSL_AUTHORITY_INFO_ACCESS_pop_free(
        WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)* sk,
        void (*f) (WOLFSSL_ACCESS_DESCRIPTION*));
WOLFSSL_API WOLFSSL_ACCESS_DESCRIPTION* wolfSSL_sk_ACCESS_DESCRIPTION_value(
        WOLFSSL_STACK* sk, int idx);
WOLFSSL_API void wolfSSL_sk_ACCESS_DESCRIPTION_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_ACCESS_DESCRIPTION_pop_free(WOLFSSL_STACK* sk,
        void (*f) (WOLFSSL_ACCESS_DESCRIPTION*));
WOLFSSL_API void wolfSSL_ACCESS_DESCRIPTION_free(WOLFSSL_ACCESS_DESCRIPTION* a);
WOLFSSL_API void wolfSSL_sk_X509_EXTENSION_pop_free(
        WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk,
        void (*f) (WOLFSSL_X509_EXTENSION*));
WOLFSSL_API void wolfSSL_sk_X509_EXTENSION_free(
        WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* wolfSSL_sk_X509_EXTENSION_new_null(void);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_new(void);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_dup(WOLFSSL_ASN1_OBJECT* obj);
WOLFSSL_API void wolfSSL_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT* obj);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_new_asn1_obj(void);
WOLFSSL_API int wolfSSL_sk_ASN1_OBJECT_push(WOLF_STACK_OF(WOLFSSL_ASN1_OBJEXT)* sk,
                                                      WOLFSSL_ASN1_OBJECT* obj);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_sk_ASN1_OBJECT_pop(
                                            WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk);
WOLFSSL_API void wolfSSL_sk_ASN1_OBJECT_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk);
WOLFSSL_API void wolfSSL_sk_ASN1_OBJECT_pop_free(
                WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk,
                void (*f)(WOLFSSL_ASN1_OBJECT*));
WOLFSSL_API int wolfSSL_ASN1_STRING_to_UTF8(unsigned char **out, WOLFSSL_ASN1_STRING *in);
WOLFSSL_API int wolfSSL_ASN1_UNIVERSALSTRING_to_string(WOLFSSL_ASN1_STRING *s);
WOLFSSL_API int wolfSSL_sk_X509_EXTENSION_num(WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_sk_X509_EXTENSION_value(
                      const WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk, int idx);

#if defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA)
WOLFSSL_API int wolfSSL_RSA_up_ref(WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_X509_up_ref(WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_EVP_PKEY_up_ref(WOLFSSL_EVP_PKEY* pkey);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509)*
        wolfSSL_X509_chain_up_ref(WOLF_STACK_OF(WOLFSSL_X509)* chain);
#endif

WOLFSSL_API int wolfSSL_OCSP_parse_url(const char* url, char** host,
        char** port, char** path, int* ssl);

#ifndef NO_BIO
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new(const WOLFSSL_BIO_METHOD* method);
#else
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new(WOLFSSL_BIO_METHOD* method);
#endif
WOLFSSL_API int  wolfSSL_BIO_free(WOLFSSL_BIO* bio);
WOLFSSL_API void wolfSSL_BIO_vfree(WOLFSSL_BIO* bio);
WOLFSSL_API void wolfSSL_BIO_free_all(WOLFSSL_BIO* bio);
WOLFSSL_API int wolfSSL_BIO_gets(WOLFSSL_BIO* bio, char* buf, int sz);
WOLFSSL_API int wolfSSL_BIO_puts(WOLFSSL_BIO* bio, const char* buf);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_next(WOLFSSL_BIO* bio);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_find_type(WOLFSSL_BIO* bio, int type);
WOLFSSL_API int  wolfSSL_BIO_read(WOLFSSL_BIO* bio, void* buf, int len);
WOLFSSL_API int  wolfSSL_BIO_write(WOLFSSL_BIO* bio, const void* data, int len);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO* top, WOLFSSL_BIO* append);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO* bio);
WOLFSSL_API int  wolfSSL_BIO_flush(WOLFSSL_BIO* bio);
WOLFSSL_API int  wolfSSL_BIO_pending(WOLFSSL_BIO* bio);
WOLFSSL_API void wolfSSL_BIO_set_callback(WOLFSSL_BIO *bio,
                                          wolf_bio_info_cb callback_func);
WOLFSSL_API wolf_bio_info_cb wolfSSL_BIO_get_callback(WOLFSSL_BIO *bio);
WOLFSSL_API void  wolfSSL_BIO_set_callback_arg(WOLFSSL_BIO *bio, char *arg);
WOLFSSL_API char* wolfSSL_BIO_get_callback_arg(const WOLFSSL_BIO *bio);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_md(void);
WOLFSSL_API int wolfSSL_BIO_get_md_ctx(WOLFSSL_BIO *bio,
                                                WOLFSSL_EVP_MD_CTX **mdcp);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void);
WOLFSSL_API long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO* bio, long size);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void);
WOLFSSL_API WOLFSSL_BIO*        wolfSSL_BIO_new_socket(int sfd, int flag);
WOLFSSL_API WOLFSSL_BIO*        wolfSSL_BIO_new_dgram(int fd, int closeF);
WOLFSSL_API int         wolfSSL_BIO_eof(WOLFSSL_BIO* b);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void);
WOLFSSL_API void wolfSSL_BIO_set_flags(WOLFSSL_BIO* bio, int flags);
WOLFSSL_API void wolfSSL_BIO_clear_flags(WOLFSSL_BIO *bio, int flags);
WOLFSSL_API int wolfSSL_BIO_get_fd(WOLFSSL_BIO *bio, int* fd);
WOLFSSL_API int wolfSSL_BIO_set_ex_data(WOLFSSL_BIO *bio, int idx, void *data);
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
WOLFSSL_API int wolfSSL_BIO_set_ex_data_with_cleanup(
    WOLFSSL_BIO *bio,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
#endif
WOLFSSL_API void *wolfSSL_BIO_get_ex_data(WOLFSSL_BIO *bio, int idx);
WOLFSSL_API long wolfSSL_BIO_set_nbio(WOLFSSL_BIO* bio, long on);

WOLFSSL_API int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,void* p);

WOLFSSL_API void wolfSSL_BIO_set_init(WOLFSSL_BIO* bio, int init);
WOLFSSL_API void wolfSSL_BIO_set_data(WOLFSSL_BIO* bio, void* ptr);
WOLFSSL_API void* wolfSSL_BIO_get_data(WOLFSSL_BIO* bio);
WOLFSSL_API void wolfSSL_BIO_set_shutdown(WOLFSSL_BIO* bio, int shut);
WOLFSSL_API int wolfSSL_BIO_get_shutdown(WOLFSSL_BIO* bio);
WOLFSSL_API void wolfSSL_BIO_clear_retry_flags(WOLFSSL_BIO* bio);
WOLFSSL_API int wolfSSL_BIO_should_retry(WOLFSSL_BIO *bio);
WOLFSSL_API int wolfSSL_BIO_should_read(WOLFSSL_BIO *bio);
WOLFSSL_API int wolfSSL_BIO_should_write(WOLFSSL_BIO *bio);

WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_meth_new(int type, const char* name);
WOLFSSL_API void wolfSSL_BIO_meth_free(WOLFSSL_BIO_METHOD* biom);
WOLFSSL_API int wolfSSL_BIO_meth_set_write(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_write_cb biom_write);
WOLFSSL_API int wolfSSL_BIO_meth_set_read(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_read_cb biom_read);
WOLFSSL_API int wolfSSL_BIO_meth_set_puts(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_puts_cb biom_puts);
WOLFSSL_API int wolfSSL_BIO_meth_set_gets(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_gets_cb biom_gets);
WOLFSSL_API int wolfSSL_BIO_meth_set_ctrl(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_ctrl_get_cb biom_ctrl);
WOLFSSL_API int wolfSSL_BIO_meth_set_create(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_create_cb biom_create);
WOLFSSL_API int wolfSSL_BIO_meth_set_destroy(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_destroy_cb biom_destroy);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(const void* buf, int len);

WOLFSSL_API long wolfSSL_BIO_set_ssl(WOLFSSL_BIO* b, WOLFSSL* ssl, int flag);
WOLFSSL_API long wolfSSL_BIO_get_ssl(WOLFSSL_BIO* bio, WOLFSSL** ssl);
#ifndef NO_FILESYSTEM
WOLFSSL_API long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int flag);
#endif
WOLFSSL_API int wolfSSL_BIO_set_close(WOLFSSL_BIO *b, long flag);
WOLFSSL_API void wolfSSL_set_bio(WOLFSSL* ssl, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr);
WOLFSSL_API void wolfSSL_set_rbio(WOLFSSL* ssl, WOLFSSL_BIO* rd);
WOLFSSL_API void wolfSSL_set_wbio(WOLFSSL* ssl, WOLFSSL_BIO* wr);
WOLFSSL_API int wolfSSL_BIO_method_type(const WOLFSSL_BIO *b);

#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_file(void);
WOLFSSL_API WOLFSSL_BIO *wolfSSL_BIO_new_fd(int fd, int close_flag);
#endif

WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_bio(void);
WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void);
WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_datagram(void);

WOLFSSL_API WOLFSSL_BIO *wolfSSL_BIO_new_connect(const char *str);
WOLFSSL_API WOLFSSL_BIO *wolfSSL_BIO_new_accept(const char *port);
WOLFSSL_API long wolfSSL_BIO_set_conn_hostname(WOLFSSL_BIO* b, char* name);
WOLFSSL_API long wolfSSL_BIO_set_conn_port(WOLFSSL_BIO *b, char* port);
WOLFSSL_API long wolfSSL_BIO_do_connect(WOLFSSL_BIO *b);
WOLFSSL_API int wolfSSL_BIO_do_accept(WOLFSSL_BIO *b);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_ssl(WOLFSSL_CTX* ctx, int client);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_ssl_connect(WOLFSSL_CTX* ctx);

WOLFSSL_API long wolfSSL_BIO_do_handshake(WOLFSSL_BIO *b);
WOLFSSL_API void wolfSSL_BIO_ssl_shutdown(WOLFSSL_BIO* b);

WOLFSSL_API long wolfSSL_BIO_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, void *parg);
WOLFSSL_API long wolfSSL_BIO_int_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, int iarg);

WOLFSSL_API int  wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size);
WOLFSSL_API int  wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2);
WOLFSSL_API int  wolfSSL_BIO_up_ref(WOLFSSL_BIO *b);
WOLFSSL_API int  wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *b);
WOLFSSL_API int  wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf);
WOLFSSL_API int  wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num);
WOLFSSL_API int  wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num);
#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_BIO_NO_FLOW_STATS)
WOLFSSL_API word64 wolfSSL_BIO_number_read(WOLFSSL_BIO *bio);
WOLFSSL_API word64 wolfSSL_BIO_number_written(WOLFSSL_BIO *bio);
#endif
WOLFSSL_API int  wolfSSL_BIO_reset(WOLFSSL_BIO *bio);

WOLFSSL_API int  wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs);
WOLFSSL_API int  wolfSSL_BIO_tell(WOLFSSL_BIO* bio);
WOLFSSL_API int  wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name);
WOLFSSL_API long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v);
WOLFSSL_API long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **m);
#ifdef OPENSSL_ALL
WOLFSSL_API int wolfSSL_BIO_set_mem_buf(WOLFSSL_BIO* bio, WOLFSSL_BUF_MEM* bufMem,
                                        int closeFlag);
#endif
WOLFSSL_API int wolfSSL_BIO_get_len(WOLFSSL_BIO *bio);

#ifdef WOLFSSL_HAVE_BIO_ADDR
WOLFSSL_API WOLFSSL_BIO_ADDR *wolfSSL_BIO_ADDR_new(void);
WOLFSSL_API void wolfSSL_BIO_ADDR_free(WOLFSSL_BIO_ADDR *addr);
WOLFSSL_API void wolfSSL_BIO_ADDR_clear(WOLFSSL_BIO_ADDR *addr);
#endif /* WOLFSSL_HAVE_BIO_ADDR */

#endif /* !NO_BIO */

WOLFSSL_API void        wolfSSL_RAND_screen(void);
WOLFSSL_API const char* wolfSSL_RAND_file_name(char* fname, unsigned long len);
WOLFSSL_API int         wolfSSL_RAND_write_file(const char* fname);
WOLFSSL_API int         wolfSSL_RAND_load_file(const char* fname, long len);
WOLFSSL_API int         wolfSSL_RAND_egd(const char* nm);
WOLFSSL_API int         wolfSSL_RAND_seed(const void* seed, int len);
WOLFSSL_API void        wolfSSL_RAND_Cleanup(void);
WOLFSSL_API void        wolfSSL_RAND_add(const void* add, int len, double entropy);
WOLFSSL_API int         wolfSSL_RAND_poll(void);

#ifndef NO_WOLFSSL_STUB
WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void);
WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void);
WOLFSSL_API int wolfSSL_COMP_add_compression_method(int method, void* data);
WOLFSSL_API const char *wolfSSL_COMP_get_name(const WOLFSSL_COMP_METHOD *comp);
WOLFSSL_API const WOLFSSL_COMP_METHOD* wolfSSL_get_current_compression(const WOLFSSL *ssl);
WOLFSSL_API const WOLFSSL_COMP_METHOD* wolfSSL_get_current_expansion(const WOLFSSL *ssl);
#endif /* !NO_WOLFSSL_STUB */

WOLFSSL_API unsigned long wolfSSL_thread_id(void);
WOLFSSL_API void wolfSSL_set_id_callback(unsigned long (*f)(void));
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
WOLFSSL_API void wolfSSL_set_locking_callback(mutex_cb* f);
WOLFSSL_API mutex_cb* wolfSSL_get_locking_callback(void);
#endif
WOLFSSL_API void wolfSSL_set_dynlock_create_callback(WOLFSSL_dynlock_value* (*f)
                                                   (const char*, int));
WOLFSSL_API void wolfSSL_set_dynlock_lock_callback(void (*f)(int,
                                      WOLFSSL_dynlock_value*, const char*, int));
WOLFSSL_API void wolfSSL_set_dynlock_destroy_callback(void (*f)
                                     (WOLFSSL_dynlock_value*, const char*, int));
WOLFSSL_API int  wolfSSL_num_locks(void);

WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get_current_cert(
                                                        WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API int   wolfSSL_X509_STORE_CTX_get_error(WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API int   wolfSSL_X509_STORE_CTX_get_error_depth(WOLFSSL_X509_STORE_CTX* ctx);

WOLFSSL_API void  wolfSSL_X509_STORE_CTX_set_verify_cb(WOLFSSL_X509_STORE_CTX *ctx,
                                  WOLFSSL_X509_STORE_CTX_verify_cb verify_cb);
WOLFSSL_API void wolfSSL_X509_STORE_set_verify_cb(WOLFSSL_X509_STORE *st,
                                 WOLFSSL_X509_STORE_CTX_verify_cb verify_cb);
WOLFSSL_API void wolfSSL_X509_STORE_set_get_crl(WOLFSSL_X509_STORE *st,
                            WOLFSSL_X509_STORE_CTX_get_crl_cb get_cb);
WOLFSSL_API void wolfSSL_X509_STORE_set_check_crl(WOLFSSL_X509_STORE *st,
        WOLFSSL_X509_STORE_CTX_check_crl_cb check_crl);
WOLFSSL_API int wolfSSL_i2d_X509_NAME(WOLFSSL_X509_NAME* n,
                                                           unsigned char** out);
WOLFSSL_API int wolfSSL_i2d_X509_NAME_canon(WOLFSSL_X509_NAME* name,
                                                    unsigned char** out);
WOLFSSL_API WOLFSSL_X509_NAME *wolfSSL_d2i_X509_NAME(WOLFSSL_X509_NAME **name,
                                              unsigned char **in, long length);
#ifndef NO_RSA
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API int wolfSSL_RSA_print_fp(XFILE fp, WOLFSSL_RSA* rsa, int indent);
#endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */
#ifndef NO_BIO
WOLFSSL_API int wolfSSL_RSA_print(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa, int offset);
#endif /* !NO_BIO */
#endif /* !NO_RSA */

WOLFSSL_API int wolfSSL_X509_print_ex(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
    unsigned long nmflags, unsigned long cflag);
#ifndef NO_FILESYSTEM
WOLFSSL_API int wolfSSL_X509_print_fp(XFILE fp, WOLFSSL_X509 *x509);
#endif
WOLFSSL_API int wolfSSL_X509_signature_print(WOLFSSL_BIO *bp,
        const WOLFSSL_X509_ALGOR *sigalg, const WOLFSSL_ASN1_STRING *sig);
WOLFSSL_API void wolfSSL_X509_get0_signature(const WOLFSSL_ASN1_BIT_STRING **psig,
        const WOLFSSL_X509_ALGOR **palg, const WOLFSSL_X509 *x509);
WOLFSSL_API int wolfSSL_X509_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_REQ_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);
WOLFSSL_API unsigned long wolfSSL_X509_NAME_hash(WOLFSSL_X509_NAME* name);
#if defined(OPENSSL_EXTRA) && defined(XSNPRINTF)
WOLFSSL_API char* wolfSSL_X509_get_name_oneline(WOLFSSL_X509_NAME* name, char* in, int sz);
#endif
WOLFSSL_API unsigned long  wolfSSL_X509_issuer_name_hash(const WOLFSSL_X509* x509);
WOLFSSL_API unsigned long  wolfSSL_X509_subject_name_hash(const WOLFSSL_X509* x509);
WOLFSSL_API int  wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509* x509, int nid);
WOLFSSL_API int  wolfSSL_X509_ext_get_critical_by_NID(WOLFSSL_X509* x509, int nid);
WOLFSSL_API int wolfSSL_X509_EXTENSION_set_critical(WOLFSSL_X509_EXTENSION* ex, int crit);
WOLFSSL_API int  wolfSSL_X509_get_isSet_pathLength(WOLFSSL_X509* x509);
WOLFSSL_API unsigned int wolfSSL_X509_get_pathLength(WOLFSSL_X509* x509);
WOLFSSL_API unsigned int wolfSSL_X509_get_keyUsage(WOLFSSL_X509* x509);
WOLFSSL_API unsigned char* wolfSSL_X509_get_authorityKeyID(
                                            WOLFSSL_X509* x509, unsigned char* dst, int* dstLen);
WOLFSSL_API unsigned char* wolfSSL_X509_get_subjectKeyID(
                                            WOLFSSL_X509* x509, unsigned char* dst, int* dstLen);
WOLFSSL_API const WOLFSSL_ASN1_STRING *wolfSSL_X509_get0_subject_key_id(
        WOLFSSL_X509 *x509);

WOLFSSL_API int wolfSSL_X509_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API int wolfSSL_X509_REQ_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);
#endif
WOLFSSL_API int wolfSSL_X509_set_subject_name(WOLFSSL_X509* cert,
                                              WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_X509_set_issuer_name(WOLFSSL_X509* cert,
                                              WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_X509_set_pubkey(WOLFSSL_X509* cert, WOLFSSL_EVP_PKEY* pkey);
WOLFSSL_API int wolfSSL_X509_set_notAfter(WOLFSSL_X509* x509,
        const WOLFSSL_ASN1_TIME* t);
WOLFSSL_API int wolfSSL_X509_set1_notAfter(WOLFSSL_X509* x509,
        const WOLFSSL_ASN1_TIME *t);
WOLFSSL_API int wolfSSL_X509_set_notBefore(WOLFSSL_X509* x509,
        const WOLFSSL_ASN1_TIME* t);
WOLFSSL_API int wolfSSL_X509_set1_notBefore(WOLFSSL_X509* x509,
        const WOLFSSL_ASN1_TIME *t);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(const WOLFSSL_X509* x509);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(const WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_set_serialNumber(WOLFSSL_X509* x509,
        WOLFSSL_ASN1_INTEGER* s);
WOLFSSL_API int wolfSSL_X509_set_version(WOLFSSL_X509* x509, long v);
WOLFSSL_API int wolfSSL_X509_sign(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey,
        const WOLFSSL_EVP_MD* md);
WOLFSSL_API int wolfSSL_X509_sign_ctx(WOLFSSL_X509 *x509, WOLFSSL_EVP_MD_CTX *ctx);


WOLFSSL_API int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_X509_NAME_get_sz(WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_X509_NAME_get_text_by_NID(
                                            WOLFSSL_X509_NAME* name, int nid, char* buf, int len);
WOLFSSL_API int wolfSSL_X509_NAME_get_index_by_NID(
                                           WOLFSSL_X509_NAME* name, int nid, int pos);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_X509_NAME_ENTRY_get_data(WOLFSSL_X509_NAME_ENTRY* in);

WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_new(void);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_dup(WOLFSSL_ASN1_STRING* asn1);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_type_new(int type);
WOLFSSL_API int wolfSSL_ASN1_STRING_type(const WOLFSSL_ASN1_STRING* asn1);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_d2i_DISPLAYTEXT(WOLFSSL_ASN1_STRING **asn, const unsigned char **in, long len);
WOLFSSL_API int wolfSSL_ASN1_STRING_cmp(const WOLFSSL_ASN1_STRING *a, const WOLFSSL_ASN1_STRING *b);
WOLFSSL_API void wolfSSL_ASN1_STRING_free(WOLFSSL_ASN1_STRING* asn1);
WOLFSSL_API int wolfSSL_ASN1_STRING_set(WOLFSSL_ASN1_STRING* asn1,
                                                  const void* data, int dataSz);
WOLFSSL_API unsigned char* wolfSSL_ASN1_STRING_data(WOLFSSL_ASN1_STRING* asn);
WOLFSSL_API const unsigned char* wolfSSL_ASN1_STRING_get0_data(
                                            const WOLFSSL_ASN1_STRING* asn);
WOLFSSL_API int wolfSSL_ASN1_STRING_length(const WOLFSSL_ASN1_STRING* asn);
WOLFSSL_API int wolfSSL_ASN1_STRING_copy(WOLFSSL_ASN1_STRING* dst,
                                                const WOLFSSL_ASN1_STRING* src);
WOLFSSL_API int         wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API const char* wolfSSL_X509_verify_cert_error_string(long err);

WOLFSSL_API int wolfSSL_X509_LOOKUP_add_dir(WOLFSSL_X509_LOOKUP* lookup,const char* dir,long type);
WOLFSSL_API int wolfSSL_X509_LOOKUP_load_file(WOLFSSL_X509_LOOKUP* lookup, const char* file,
                                            long type);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_hash_dir(void);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_file(void);
WOLFSSL_API int wolfSSL_X509_LOOKUP_ctrl(WOLFSSL_X509_LOOKUP *ctx, int cmd,
        const char *argc, long argl, char **ret);

WOLFSSL_API WOLFSSL_X509_LOOKUP* wolfSSL_X509_STORE_add_lookup(WOLFSSL_X509_STORE* store,
                                                    WOLFSSL_X509_LOOKUP_METHOD* m);
WOLFSSL_API WOLFSSL_X509_STORE*  wolfSSL_X509_STORE_new(void);
WOLFSSL_API void         wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE* store);
WOLFSSL_API int          wolfSSL_X509_STORE_up_ref(WOLFSSL_X509_STORE* store);
WOLFSSL_API int          wolfSSL_X509_STORE_add_cert(
                                              WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509);
WOLFSSL_API WOLFSSL_X509_VERIFY_PARAM *wolfSSL_X509_STORE_get0_param(
        const WOLFSSL_X509_STORE *ctx);
WOLFSSL_API int wolfSSL_X509_STORE_set1_param(WOLFSSL_X509_STORE *ctx,
        WOLFSSL_X509_VERIFY_PARAM *param);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get1_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_X509_STORE_CTX *wolfSSL_X509_STORE_CTX_get0_parent_ctx(
                                                   WOLFSSL_X509_STORE_CTX *ctx);
WOLFSSL_API int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store,
                                                            unsigned long flag);
WOLFSSL_API int wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX* ctx,
                    int idx, WOLFSSL_X509_NAME* name, WOLFSSL_X509_OBJECT* obj);
WOLFSSL_API WOLFSSL_X509_VERIFY_PARAM *wolfSSL_X509_STORE_CTX_get0_param(
        WOLFSSL_X509_STORE_CTX *ctx);
WOLFSSL_API int  wolfSSL_X509_STORE_CTX_init(WOLFSSL_X509_STORE_CTX* ctx,
                      WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509, WOLF_STACK_OF(WOLFSSL_X509)*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_trusted_stack(WOLFSSL_X509_STORE_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509) *sk);

WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_lastUpdate(WOLFSSL_X509_CRL* crl);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_nextUpdate(WOLFSSL_X509_CRL* crl);

WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_X509_get_pubkey(WOLFSSL_X509* x509);
WOLFSSL_API int       wolfSSL_X509_CRL_verify(WOLFSSL_X509_CRL* crl, WOLFSSL_EVP_PKEY* pkey);
WOLFSSL_API void      wolfSSL_X509_OBJECT_free_contents(WOLFSSL_X509_OBJECT* obj);
WOLFSSL_API WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY_bio(
        WOLFSSL_BIO* bio, WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey);
WOLFSSL_API WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY(
        WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey, const unsigned char** keyBuf, long keyLen);
WOLFSSL_API int wolfSSL_i2d_PKCS8_PKEY(WOLFSSL_PKCS8_PRIV_KEY_INFO* key,
        unsigned char** pp);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY_bio(WOLFSSL_BIO* bio,
                                         WOLFSSL_EVP_PKEY** out);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY(WOLFSSL_EVP_PKEY** key,
        const unsigned char** in, long inSz);
WOLFSSL_API int wolfSSL_i2d_PUBKEY(const WOLFSSL_EVP_PKEY *key, unsigned char **der);
WOLFSSL_API int wolfSSL_i2d_X509_PUBKEY(WOLFSSL_X509_PUBKEY* x509_PubKey,
                                        unsigned char** der);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PublicKey(int type, WOLFSSL_EVP_PKEY** pkey,
        const unsigned char ** in, long inSz);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey(int type,
        WOLFSSL_EVP_PKEY** out, const unsigned char **in, long inSz);
#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_id(int type,
    WOLFSSL_EVP_PKEY** out, void* heap, int devId);
#endif
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_EVP(WOLFSSL_EVP_PKEY** key,
        unsigned char** in, long inSz);
WOLFSSL_API int wolfSSL_i2d_PrivateKey(const WOLFSSL_EVP_PKEY* key,
        unsigned char** der);
WOLFSSL_API int wolfSSL_i2d_PublicKey(const WOLFSSL_EVP_PKEY* key,
        unsigned char** der);
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
WOLFSSL_API int wolfSSL_EVP_PKEY_print_public(WOLFSSL_BIO* out,
                                    const WOLFSSL_EVP_PKEY* pkey,
                                    int indent, WOLFSSL_ASN1_PCTX* pctx);
#endif /* OPENSSL_EXTRA && !WOLFCRYPT_ONLY */
WOLFSSL_API int       wolfSSL_X509_cmp_current_time(const WOLFSSL_ASN1_TIME* asnTime);
#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_X509_cmp_time(const WOLFSSL_ASN1_TIME* asnTime,
        time_t *cmpTime);
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_X509_time_adj_ex(WOLFSSL_ASN1_TIME *asnTime,
    int offset_day, long offset_sec, time_t *in_tm);
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_X509_time_adj(WOLFSSL_ASN1_TIME *asnTime,
    long offset_sec, time_t *in_tm);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_gmtime_adj(WOLFSSL_ASN1_TIME* s,
    long adj);
WOLFSSL_API int       wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED* revoked);
WOLFSSL_API void      wolfSSL_X509_STORE_CTX_set_time(WOLFSSL_X509_STORE_CTX* ctx,
                                                      unsigned long flags,
                                                      time_t t);
WOLFSSL_API WOLFSSL_X509_VERIFY_PARAM* wolfSSL_X509_VERIFY_PARAM_new(void);
WOLFSSL_API void wolfSSL_X509_VERIFY_PARAM_free(WOLFSSL_X509_VERIFY_PARAM *param);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set_flags(WOLFSSL_X509_VERIFY_PARAM *param,
        unsigned long flags);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_get_flags(WOLFSSL_X509_VERIFY_PARAM *param);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_clear_flags(WOLFSSL_X509_VERIFY_PARAM *param,
        unsigned long flags);
WOLFSSL_API void wolfSSL_X509_VERIFY_PARAM_set_hostflags(
                WOLFSSL_X509_VERIFY_PARAM* param, unsigned int flags);
WOLFSSL_API int wolfSSL_set1_host(WOLFSSL* ssl, const char * name);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set1_host(WOLFSSL_X509_VERIFY_PARAM* pParam,
                                                    const char* name,
                                                    unsigned int nameSz);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(
        WOLFSSL_X509_VERIFY_PARAM *param, const char *ipasc);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set1_ip(
       WOLFSSL_X509_VERIFY_PARAM* param, const unsigned char* ip, size_t iplen);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set1(WOLFSSL_X509_VERIFY_PARAM* to,
                                    const WOLFSSL_X509_VERIFY_PARAM* from);
WOLFSSL_API const WOLFSSL_X509_VERIFY_PARAM *wolfSSL_X509_VERIFY_PARAM_lookup(
                                                             const char *name);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_inherit(WOLFSSL_X509_VERIFY_PARAM *to,
                                         const WOLFSSL_X509_VERIFY_PARAM *from);
WOLFSSL_API int wolfSSL_X509_load_crl_file(WOLFSSL_X509_LOOKUP *ctx,
                                              const char *file, int type);
WOLFSSL_API int wolfSSL_X509_load_cert_crl_file(WOLFSSL_X509_LOOKUP *ctx,
                                              const char *file, int type);
#endif
WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_X509_CRL_get_REVOKED(WOLFSSL_X509_CRL* crl);
WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
                                                      WOLFSSL_X509_REVOKED* revoked,int value);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_X509_get_serialNumber(WOLFSSL_X509* x509);
WOLFSSL_API void wolfSSL_ASN1_INTEGER_free(WOLFSSL_ASN1_INTEGER* in);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_new(void);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_dup(
                                              const WOLFSSL_ASN1_INTEGER* src);
WOLFSSL_API int wolfSSL_ASN1_INTEGER_set(WOLFSSL_ASN1_INTEGER *a, long v);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_d2i_ASN1_INTEGER(
                                               WOLFSSL_ASN1_INTEGER** a,
                                               const unsigned char** in,
                                               long inSz);
WOLFSSL_API int wolfSSL_i2d_ASN1_INTEGER(const WOLFSSL_ASN1_INTEGER* a,
                                         unsigned char** pp);

WOLFSSL_API int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO* bio, const WOLFSSL_ASN1_TIME* asnTime);

WOLFSSL_API char* wolfSSL_ASN1_TIME_to_string(WOLFSSL_ASN1_TIME* t,
                                                            char* buf, int len);
#ifndef NO_ASN_TIME
WOLFSSL_API int wolfSSL_ASN1_TIME_to_tm(const WOLFSSL_ASN1_TIME* asnTime, struct tm* tm);
#endif
WOLFSSL_API int  wolfSSL_ASN1_INTEGER_cmp(const WOLFSSL_ASN1_INTEGER* a,
                                       const WOLFSSL_ASN1_INTEGER* b);
WOLFSSL_API long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER* a);

#ifdef OPENSSL_EXTRA
WOLFSSL_API WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
                                       WOLFSSL_BIGNUM *bn);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_adj(WOLFSSL_ASN1_TIME* s, time_t t,
                                                     int offset_day, long offset_sec);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_new(void);
WOLFSSL_API void wolfSSL_ASN1_TIME_free(WOLFSSL_ASN1_TIME* t);
#endif

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_load_client_CA_file(const char* fname);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_CTX_get_client_CA_list(
        const WOLFSSL_CTX *ctx);
/* deprecated function name */
#define wolfSSL_SSL_CTX_get_client_CA_list wolfSSL_CTX_get_client_CA_list

WOLFSSL_API void wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX* ctx,
                                               WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API void wolfSSL_set_client_CA_list(WOLFSSL* ssl,
                                               WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_get_client_CA_list(
            const WOLFSSL* ssl);

typedef int (*client_cert_cb)(WOLFSSL *ssl, WOLFSSL_X509 **x509,
                              WOLFSSL_EVP_PKEY **pkey);
WOLFSSL_API void wolfSSL_CTX_set_client_cert_cb(WOLFSSL_CTX *ctx, client_cert_cb cb);

typedef int (*CertSetupCallback)(WOLFSSL* ssl, void*);
WOLFSSL_API void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx,
    CertSetupCallback cb, void *arg);
WOLFSSL_API int wolfSSL_get_client_suites_sigalgs(const WOLFSSL* ssl,
        const byte** suites, word16* suiteSz,
        const byte** hashSigAlgo, word16* hashSigAlgoSz);
typedef struct WOLFSSL_CIPHERSUITE_INFO {
    WC_BITFIELD rsaAuth:1;
    WC_BITFIELD eccAuth:1;
    WC_BITFIELD eccStatic:1;
    WC_BITFIELD psk:1;
} WOLFSSL_CIPHERSUITE_INFO;
WOLFSSL_API WOLFSSL_CIPHERSUITE_INFO wolfSSL_get_ciphersuite_info(byte first,
        byte second);
WOLFSSL_API int wolfSSL_get_sigalg_info(byte first,
        byte second, int* hashAlgo, int* sigAlgo);
WOLFSSL_LOCAL int CertSetupCbWrapper(WOLFSSL* ssl);

WOLFSSL_API void* wolfSSL_X509_STORE_CTX_get_ex_data(
        WOLFSSL_X509_STORE_CTX* ctx, int idx);
WOLFSSL_API int  wolfSSL_X509_STORE_CTX_set_ex_data(WOLFSSL_X509_STORE_CTX* ctx,
        int idx, void *data);
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
WOLFSSL_API int wolfSSL_X509_STORE_CTX_set_ex_data_with_cleanup(
    WOLFSSL_X509_STORE_CTX* ctx,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
#endif
WOLFSSL_API void* wolfSSL_X509_STORE_get_ex_data(
                                           WOLFSSL_X509_STORE* store, int idx);
WOLFSSL_API int  wolfSSL_X509_STORE_set_ex_data(WOLFSSL_X509_STORE* store,
        int idx, void *data);
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
WOLFSSL_API int  wolfSSL_X509_STORE_set_ex_data_with_cleanup(
    WOLFSSL_X509_STORE* store,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
#endif
WOLFSSL_API void wolfSSL_X509_STORE_CTX_set_depth(WOLFSSL_X509_STORE_CTX* ctx,
        int depth);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_current_issuer(
        WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_X509_STORE* wolfSSL_X509_STORE_CTX_get0_store(
        WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_cert(
        WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API int  wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_set_error(
                                           WOLFSSL_X509_STORE_CTX* ctx, int er);
void wolfSSL_X509_STORE_CTX_set_error_depth(WOLFSSL_X509_STORE_CTX* ctx,
                                                                     int depth);

WOLFSSL_API void wolfSSL_CTX_set_info_callback(WOLFSSL_CTX* ctx,
                          void (*f)(const WOLFSSL* ssl, int type, int val));
WOLFSSL_API void wolfSSL_set_info_callback(WOLFSSL* ssl,
                          void (*f)(const WOLFSSL* ssl, int type, int val));

WOLFSSL_API unsigned long wolfSSL_ERR_peek_error(void);
WOLFSSL_API int           wolfSSL_GET_REASON(int);

WOLFSSL_API const char* wolfSSL_alert_type_string_long(int alertID);
WOLFSSL_API const char* wolfSSL_alert_desc_string_long(int alertID);
WOLFSSL_API const char* wolfSSL_state_string_long(const WOLFSSL* ssl);

WOLFSSL_API WOLFSSL_RSA* wolfSSL_RSA_generate_key(int len, unsigned long e,
                                               void(*f)(int, int, void*), void* data);
WOLFSSL_API WOLFSSL_RSA *wolfSSL_d2i_RSAPublicKey(WOLFSSL_RSA **r,
                                            const unsigned char **pp, long len);
WOLFSSL_API WOLFSSL_RSA *wolfSSL_d2i_RSAPrivateKey(WOLFSSL_RSA** r,
                                            const unsigned char** derBuf, long derSz);
WOLFSSL_API int wolfSSL_i2d_RSAPublicKey(WOLFSSL_RSA *r, unsigned char **pp);
WOLFSSL_API int wolfSSL_i2d_RSAPrivateKey(WOLFSSL_RSA *r, unsigned char **pp);
WOLFSSL_API void wolfSSL_CTX_set_tmp_rsa_callback(WOLFSSL_CTX* ctx,
                                           WOLFSSL_RSA *(*f)(WOLFSSL *, int, int));

WOLFSSL_API int wolfSSL_PEM_def_callback(char* name, int num, int w, void* key);

WOLFSSL_API long wolfSSL_CTX_sess_accept(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_connect(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_accept_good(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_connect_good(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_accept_renegotiate(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_connect_renegotiate(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_hits(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_cb_hits(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_cache_full(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_misses(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_timeouts(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_sess_number(WOLFSSL_CTX* ctx);

WOLFSSL_API long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);
WOLFSSL_API long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX* ctx, long sz);
WOLFSSL_API long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX* ctx);

WOLFSSL_API long wolfSSL_CTX_get_session_cache_mode(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_get_read_ahead(const WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_set_read_ahead(WOLFSSL* ssl, int v);
WOLFSSL_API int  wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX* ctx, int v);
WOLFSSL_API long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);
WOLFSSL_API long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(
        WOLFSSL_CTX* ctx, void* arg);
WOLFSSL_API int  wolfSSL_CTX_add_client_CA(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);
WOLFSSL_API int  wolfSSL_CTX_set_srp_password(WOLFSSL_CTX* ctx, char* password);
WOLFSSL_API int  wolfSSL_CTX_set_srp_username(WOLFSSL_CTX* ctx, char* username);
WOLFSSL_API int  wolfSSL_CTX_set_srp_strength(WOLFSSL_CTX *ctx, int strength);

WOLFSSL_API char* wolfSSL_get_srp_username(WOLFSSL *ssl);

WOLFSSL_API long wolfSSL_clear_options(WOLFSSL *s,  long op);
WOLFSSL_API long wolfSSL_set_tmp_dh(WOLFSSL *s, WOLFSSL_DH *dh);
WOLFSSL_API long wolfSSL_set_tlsext_debug_arg(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type);
WOLFSSL_API long wolfSSL_get_tlsext_status_type(WOLFSSL *s);
WOLFSSL_API long wolfSSL_set_tlsext_status_exts(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_tlsext_status_ids(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_set_tlsext_status_ids(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char **resp);
WOLFSSL_API long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char *resp, int len);
WOLFSSL_API int wolfSSL_set_tlsext_max_fragment_length
                                                (WOLFSSL *s, unsigned char mode);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_max_fragment_length
                                        (WOLFSSL_CTX *c, unsigned char mode);
WOLFSSL_API void wolfSSL_CONF_modules_unload(int all);
WOLFSSL_API char* wolfSSL_CONF_get1_default_config_file(void);
WOLFSSL_API long wolfSSL_get_tlsext_status_exts(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_verify_result(const WOLFSSL *ssl);

WOLFSSL_API void* wolfSSL_get_app_data( const WOLFSSL *ssl);
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED)

    /* Errors used in wolfSSL. utilize the values from the defines in
     * wolfssl/openssl/x509.h, but without the WOLFSSL_ prefix.
     */
enum {
    WOLFSSL_X509_V_OK                                    = 0,
    WOLFSSL_X509_V_ERR_CERT_SIGNATURE_FAILURE            = 7,
    WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID                = 9,
    WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED                  = 10,
    WOLFSSL_X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD    = 13,
    WOLFSSL_X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD     = 14,
    WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT       = 18,
    WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20,
    WOLFSSL_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE   = 21,
    WOLFSSL_X509_V_ERR_CERT_CHAIN_TOO_LONG               = 22,
    WOLFSSL_X509_V_ERR_CERT_REVOKED                      = 23,
    WOLFSSL_X509_V_ERR_INVALID_CA                        = 24,
    WOLFSSL_X509_V_ERR_PATH_LENGTH_EXCEEDED              = 25,
    WOLFSSL_X509_V_ERR_CERT_REJECTED                     = 28,
    WOLFSSL_X509_V_ERR_SUBJECT_ISSUER_MISMATCH           = 29,

#ifdef HAVE_OCSP
    /* OCSP Flags */
    WOLFSSL_OCSP_NOCERTS     = 1,
    WOLFSSL_OCSP_NOINTERN    = 2,
    WOLFSSL_OCSP_NOSIGS      = 4,
    WOLFSSL_OCSP_NOCHAIN     = 8,
    WOLFSSL_OCSP_NOVERIFY    = 16,
    WOLFSSL_OCSP_NOEXPLICIT  = 32,
    WOLFSSL_OCSP_NOCASIGN    = 64,
    WOLFSSL_OCSP_NODELEGATED = 128,
    WOLFSSL_OCSP_NOCHECKS    = 256,
    WOLFSSL_OCSP_TRUSTOTHER  = 512,
    WOLFSSL_OCSP_RESPID_KEY  = 1024,
    WOLFSSL_OCSP_NOTIME      = 2048,
#endif

    WOLFSSL_ST_CONNECT = 0x1000,
    WOLFSSL_ST_ACCEPT  = 0x2000,
    WOLFSSL_ST_MASK    = 0x0FFF,

    WOLFSSL_CB_LOOP = 0x01,
    WOLFSSL_CB_EXIT = 0x02,
    WOLFSSL_CB_READ = 0x04,
    WOLFSSL_CB_WRITE = 0x08,
    WOLFSSL_CB_HANDSHAKE_START = 0x10,
    WOLFSSL_CB_HANDSHAKE_DONE = 0x20,
    WOLFSSL_CB_ALERT = 0x4000,
    WOLFSSL_CB_READ_ALERT = (WOLFSSL_CB_ALERT | WOLFSSL_CB_READ),
    WOLFSSL_CB_WRITE_ALERT = (WOLFSSL_CB_ALERT | WOLFSSL_CB_WRITE),
    WOLFSSL_CB_ACCEPT_LOOP = (WOLFSSL_ST_ACCEPT | WOLFSSL_CB_LOOP),
    WOLFSSL_CB_ACCEPT_EXIT = (WOLFSSL_ST_ACCEPT | WOLFSSL_CB_EXIT),
    WOLFSSL_CB_CONNECT_LOOP = (WOLFSSL_ST_CONNECT | WOLFSSL_CB_LOOP),
    WOLFSSL_CB_CONNECT_EXIT = (WOLFSSL_ST_CONNECT | WOLFSSL_CB_EXIT),
    WOLFSSL_CB_MODE_READ = 1,
    WOLFSSL_CB_MODE_WRITE = 2,

    WOLFSSL_MODE_ENABLE_PARTIAL_WRITE = 2,
    WOLFSSL_MODE_AUTO_RETRY = 3, /* wolfSSL default is to return WANT_{READ|WRITE}
                              * to the user. This is set by default with
                              * OPENWOLFSSL_COMPATIBLE_DEFAULTS. The macro
                              * WOLFWOLFSSL_MODE_AUTO_RETRY_ATTEMPTS is used to
                              * limit the possibility of an infinite retry loop
                              */
    WOLFSSL_MODE_RELEASE_BUFFERS = -1, /* For libwebsockets build. No current use. */

    WOLFSSL_CRYPTO_LOCK = 1,
    WOLFSSL_CRYPTO_NUM_LOCKS = 10
};

#define WOLFSSL_NOTHING 1
#define WOLFSSL_WRITING 2
#define WOLFSSL_READING 3
#define WOLFSSL_MAX_SSL_SESSION_ID_LENGTH 32  /* = ID_LEN */

#ifndef OPENSSL_COEXIST

/* for compatibility these must be macros */

#define SSL_OP_MICROSOFT_SESS_ID_BUG            WOLFSSL_OP_MICROSOFT_SESS_ID_BUG
#define SSL_OP_NETSCAPE_CHALLENGE_BUG           WOLFSSL_OP_NETSCAPE_CHALLENGE_BUG
#define SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG WOLFSSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
#define SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG      WOLFSSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
#define SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER       WOLFSSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
#define SSL_OP_MSIE_SSLV2_RSA_PADDING           WOLFSSL_OP_MSIE_SSLV2_RSA_PADDING
#define SSL_OP_SSLEAY_080_CLIENT_DH_BUG         WOLFSSL_OP_SSLEAY_080_CLIENT_DH_BUG
#define SSL_OP_TLS_D5_BUG                       WOLFSSL_OP_TLS_D5_BUG
#define SSL_OP_TLS_BLOCK_PADDING_BUG            WOLFSSL_OP_TLS_BLOCK_PADDING_BUG
#define SSL_OP_TLS_ROLLBACK_BUG                 WOLFSSL_OP_TLS_ROLLBACK_BUG
#define SSL_OP_EPHEMERAL_RSA                    WOLFSSL_OP_EPHEMERAL_RSA
#define SSL_OP_PKCS1_CHECK_1                    WOLFSSL_OP_PKCS1_CHECK_1
#define SSL_OP_PKCS1_CHECK_2                    WOLFSSL_OP_PKCS1_CHECK_2
#define SSL_OP_NETSCAPE_CA_DN_BUG               WOLFSSL_OP_NETSCAPE_CA_DN_BUG
#define SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG  WOLFSSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
#define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS      WOLFSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
#define SSL_OP_NO_QUERY_MTU                     WOLFSSL_OP_NO_QUERY_MTU
#define SSL_OP_COOKIE_EXCHANGE                  WOLFSSL_OP_COOKIE_EXCHANGE
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION \
                                                WOLFSSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
#define SSL_OP_ALL                              WOLFSSL_OP_ALL

#define SSL_OP_NO_SSLv2       WOLFSSL_OP_NO_SSLv2
#define SSL_OP_NO_SSLv3       WOLFSSL_OP_NO_SSLv3
#define SSL_OP_NO_TLSv1       WOLFSSL_OP_NO_TLSv1
#define SSL_OP_NO_TLSv1_1     WOLFSSL_OP_NO_TLSv1_1
#define SSL_OP_NO_TLSv1_2     WOLFSSL_OP_NO_TLSv1_2
#define SSL_OP_NO_COMPRESSION WOLFSSL_OP_NO_COMPRESSION

/* apache uses SSL_OP_NO_TLSv1_3 to determine if TLS 1.3 is enabled */
#if !(!defined(WOLFSSL_TLS13) && defined(WOLFSSL_APACHE_HTTPD))
#define SSL_OP_NO_TLSv1_3 WOLFSSL_OP_NO_TLSv1_3
#endif

#ifdef HAVE_SESSION_TICKET
#define SSL_OP_NO_TICKET WOLFSSL_OP_NO_TICKET
#endif

#define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | \
    SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3)


#define SSL_NOTHING  WOLFSSL_NOTHING
#define SSL_WRITING  WOLFSSL_WRITING
#define SSL_READING  WOLFSSL_READING
#define SSL_MAX_SSL_SESSION_ID_LENGTH  WOLFSSL_MAX_SSL_SESSION_ID_LENGTH
#define SSL_MAX_SID_CTX_LENGTH  WOLFSSL_MAX_SSL_SESSION_ID_LENGTH

#ifdef HAVE_OCSP
    /* OCSP Flags */
#define OCSP_NOCERTS WOLFSSL_OCSP_NOCERTS
#define OCSP_NOINTERN WOLFSSL_OCSP_NOINTERN
#define OCSP_NOSIGS WOLFSSL_OCSP_NOSIGS
#define OCSP_NOCHAIN WOLFSSL_OCSP_NOCHAIN
#define OCSP_NOVERIFY WOLFSSL_OCSP_NOVERIFY
#define OCSP_NOEXPLICIT WOLFSSL_OCSP_NOEXPLICIT
#define OCSP_NOCASIGN WOLFSSL_OCSP_NOCASIGN
#define OCSP_NODELEGATED WOLFSSL_OCSP_NODELEGATED
#define OCSP_NOCHECKS WOLFSSL_OCSP_NOCHECKS
#define OCSP_TRUSTOTHER WOLFSSL_OCSP_TRUSTOTHER
#define OCSP_RESPID_KEY WOLFSSL_OCSP_RESPID_KEY
#define OCSP_NOTIME WOLFSSL_OCSP_NOTIME
#endif

#define SSL_ST_CONNECT WOLFSSL_ST_CONNECT
#define SSL_ST_ACCEPT WOLFSSL_ST_ACCEPT
#define SSL_ST_MASK WOLFSSL_ST_MASK

#define SSL_CB_LOOP WOLFSSL_CB_LOOP
#define SSL_CB_EXIT WOLFSSL_CB_EXIT
#define SSL_CB_READ WOLFSSL_CB_READ
#define SSL_CB_WRITE WOLFSSL_CB_WRITE
#define SSL_CB_HANDSHAKE_START WOLFSSL_CB_HANDSHAKE_START
#define SSL_CB_HANDSHAKE_DONE WOLFSSL_CB_HANDSHAKE_DONE
#define SSL_CB_ALERT WOLFSSL_CB_ALERT
#define SSL_CB_READ_ALERT WOLFSSL_CB_READ_ALERT
#define SSL_CB_WRITE_ALERT WOLFSSL_CB_WRITE_ALERT
#define SSL_CB_ACCEPT_LOOP WOLFSSL_CB_ACCEPT_LOOP
#define SSL_CB_ACCEPT_EXIT WOLFSSL_CB_ACCEPT_EXIT
#define SSL_CB_CONNECT_LOOP WOLFSSL_CB_CONNECT_LOOP
#define SSL_CB_CONNECT_EXIT WOLFSSL_CB_CONNECT_EXIT
#define SSL_CB_MODE_READ WOLFSSL_CB_MODE_READ
#define SSL_CB_MODE_WRITE WOLFSSL_CB_MODE_WRITE

#define SSL_MODE_ENABLE_PARTIAL_WRITE WOLFSSL_MODE_ENABLE_PARTIAL_WRITE
#define SSL_MODE_AUTO_RETRY WOLFSSL_MODE_AUTO_RETRY
#define SSL_MODE_RELEASE_BUFFERS WOLFSSL_MODE_RELEASE_BUFFERS

#define CRYPTO_LOCK WOLFSSL_CRYPTO_LOCK
#define CRYPTO_NUM_LOCKS WOLFSSL_CRYPTO_NUM_LOCKS

#endif /* !OPENSSL_COEXIST */

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL || HAVE_WEBSERVER || HAVE_MEMCACHED */
/* -------- EXTRAS END -------- */


#define WOLFSSL_DEFAULT_CIPHER_LIST ""   /* default all */

/* These are bit-masks */
enum {
    WOLFSSL_OCSP_URL_OVERRIDE = 1,
    WOLFSSL_OCSP_NO_NONCE     = 2,
    WOLFSSL_OCSP_CHECKALL     = 4,

    WOLFSSL_CRL_CHECKALL = 1,
    WOLFSSL_CRL_CHECK    = 2
};

/* Separated out from other enums because of size */
enum {
    WOLFSSL_OP_MICROSOFT_SESS_ID_BUG                  = 0x00000001,
    WOLFSSL_OP_NETSCAPE_CHALLENGE_BUG                 = 0x00000002,
    WOLFSSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG       = 0x00000004,
    WOLFSSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG            = 0x00000008,
    WOLFSSL_OP_MICROSOFT_BIG_SSLV3_BUFFER             = 0x00000010,
    WOLFSSL_OP_MSIE_SSLV2_RSA_PADDING                 = 0x00000020,
    WOLFSSL_OP_SSLEAY_080_CLIENT_DH_BUG               = 0x00000040,
    WOLFSSL_OP_TLS_D5_BUG                             = 0x00000080,
    WOLFSSL_OP_TLS_BLOCK_PADDING_BUG                  = 0x00000100,
    WOLFSSL_OP_TLS_ROLLBACK_BUG                       = 0x00000200,
    WOLFSSL_OP_NO_RENEGOTIATION                       = 0x00000400,
    WOLFSSL_OP_EPHEMERAL_RSA                          = 0x00000800,
    WOLFSSL_OP_NO_SSLv3                               = 0x00001000,
    WOLFSSL_OP_NO_TLSv1                               = 0x00002000,
    WOLFSSL_OP_PKCS1_CHECK_1                          = 0x00004000,
    WOLFSSL_OP_PKCS1_CHECK_2                          = 0x00008000,
    WOLFSSL_OP_NETSCAPE_CA_DN_BUG                     = 0x00010000,
    WOLFSSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG        = 0x00020000,
    WOLFSSL_OP_SINGLE_DH_USE                          = 0x00040000,
    WOLFSSL_OP_NO_TICKET                              = 0x00080000,
    WOLFSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS            = 0x00100000,
    WOLFSSL_OP_NO_QUERY_MTU                           = 0x00200000,
    WOLFSSL_OP_COOKIE_EXCHANGE                        = 0x00400000,
    WOLFSSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00800000,
    WOLFSSL_OP_SINGLE_ECDH_USE                        = 0x01000000,
    WOLFSSL_OP_CIPHER_SERVER_PREFERENCE               = 0x02000000,
    WOLFSSL_OP_NO_TLSv1_1                             = 0x04000000,
    WOLFSSL_OP_NO_TLSv1_2                             = 0x08000000,
    WOLFSSL_OP_NO_COMPRESSION                         = 0x10000000,
    WOLFSSL_OP_NO_TLSv1_3                             = 0x20000000,
    WOLFSSL_OP_NO_SSLv2                               = 0x40000000,
    WOLFSSL_OP_ALL   =
                   (WOLFSSL_OP_MICROSOFT_SESS_ID_BUG
                  | WOLFSSL_OP_NETSCAPE_CHALLENGE_BUG
                  | WOLFSSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
                  | WOLFSSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
                  | WOLFSSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
                  | WOLFSSL_OP_MSIE_SSLV2_RSA_PADDING
                  | WOLFSSL_OP_SSLEAY_080_CLIENT_DH_BUG
                  | WOLFSSL_OP_TLS_D5_BUG
                  | WOLFSSL_OP_TLS_BLOCK_PADDING_BUG
                  | WOLFSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
                  | WOLFSSL_OP_TLS_ROLLBACK_BUG)
};

WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX* ctx,
                                                          void* userdata);
WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX* ctx,
                                                   wc_pem_password_cb* cb);
WOLFSSL_API wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX* ctx);
WOLFSSL_API void *wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx);

WOLFSSL_API int  wolfSSL_SSL_renegotiate_pending(WOLFSSL *s);
WOLFSSL_API long wolfSSL_total_renegotiations(WOLFSSL *s);
WOLFSSL_API long wolfSSL_num_renegotiations(WOLFSSL* s);
WOLFSSL_API long wolfSSL_clear_num_renegotiations(WOLFSSL *s);
WOLFSSL_API int  wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h);
WOLFSSL_API int  wolfSSL_get_shutdown(const WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_set_rfd(WOLFSSL* ssl, int rfd);
WOLFSSL_API int  wolfSSL_set_wfd(WOLFSSL* ssl, int wfd);
WOLFSSL_API void wolfSSL_set_shutdown(WOLFSSL* ssl, int opt);
WOLFSSL_API int  wolfSSL_set_session_id_context(WOLFSSL* ssl, const unsigned char* id,
                                           unsigned int len);
WOLFSSL_API void wolfSSL_set_connect_state(WOLFSSL* ssl);
WOLFSSL_API void wolfSSL_set_accept_state(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_session_reused(WOLFSSL* ssl);
#ifdef OPENSSL_EXTRA
/* using unsigned char instead of uint8_t here to avoid stdint include */
WOLFSSL_API unsigned char wolfSSL_SESSION_get_max_fragment_length(
                                                      WOLFSSL_SESSION* session);
#endif
WOLFSSL_API int wolfSSL_SESSION_up_ref(WOLFSSL_SESSION* session);

WOLFSSL_API WOLFSSL_SESSION* wolfSSL_SESSION_dup(WOLFSSL_SESSION* session);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_SESSION_new(void);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_SESSION_new_ex(void* heap);
WOLFSSL_API void wolfSSL_SESSION_free(WOLFSSL_SESSION* session);
WOLFSSL_API int wolfSSL_CTX_add_session(WOLFSSL_CTX* ctx,
                                        WOLFSSL_SESSION* session);
WOLFSSL_API int wolfSSL_SESSION_set_cipher(WOLFSSL_SESSION* session,
                                        const WOLFSSL_CIPHER* cipher);
WOLFSSL_API int  wolfSSL_is_init_finished(const WOLFSSL* ssl);

WOLFSSL_API const char*  wolfSSL_get_version(const WOLFSSL* ssl);
#ifdef OPENSSL_EXTRA
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_CIPHER)*  wolfSSL_get_client_ciphers(
    WOLFSSL* ssl);
#endif
WOLFSSL_API int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);
WOLFSSL_API WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL* ssl);
WOLFSSL_API char* wolfSSL_CIPHER_description(const WOLFSSL_CIPHER* cipher, char* in, int len);
WOLFSSL_API const char*  wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API const char*  wolfSSL_CIPHER_get_version(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API word32       wolfSSL_CIPHER_get_id(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API int wolfSSL_CIPHER_get_auth_nid(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API int wolfSSL_CIPHER_get_cipher_nid(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API int wolfSSL_CIPHER_get_digest_nid(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API int wolfSSL_CIPHER_get_kx_nid(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API int wolfSSL_CIPHER_is_aead(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API const WOLFSSL_CIPHER* wolfSSL_get_cipher_by_value(word16 value);
WOLFSSL_API const char*  wolfSSL_SESSION_CIPHER_get_name(const WOLFSSL_SESSION* session);
WOLFSSL_API const char*  wolfSSL_get_cipher(WOLFSSL* ssl);
WOLFSSL_API void wolfSSL_sk_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SessionIsSetup(WOLFSSL_SESSION* session);

WOLFSSL_API WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void);
WOLFSSL_API WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new_ex(void* heap);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX* ctx);

WOLFSSL_API long wolfSSL_set_options(WOLFSSL *s, long op);
WOLFSSL_API long wolfSSL_get_options(const WOLFSSL *s);

WOLFSSL_ABI WOLFSSL_API char* wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME* name,
                                                                    char* in, int sz);

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
/* wolfSSL extension, provide last error from SSL_get_error
   since not using thread storage error queue */
#ifdef FUSION_RTOS
    #include <fclstdio.h>
#else
    #include <stdio.h>
#endif
WOLFSSL_API void  wolfSSL_ERR_print_errors_fp(XFILE fp, int err);
#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
WOLFSSL_API void wolfSSL_ERR_dump_errors_fp(XFILE fp);
WOLFSSL_API void wolfSSL_ERR_print_errors_cb(int (*cb)(const char *str,
                                                size_t len, void *u), void *u);
#endif
#endif

#ifndef NO_OLD_SSL_NAMES
    #define SSL_ERROR_NONE WOLFSSL_ERROR_NONE
    #define SSL_FAILURE WOLFSSL_FAILURE
    #define SSL_SUCCESS WOLFSSL_SUCCESS
    #define SSL_SHUTDOWN_NOT_DONE WOLFSSL_SHUTDOWN_NOT_DONE

    #define SSL_ALPN_NOT_FOUND WOLFSSL_ALPN_NOT_FOUND
    #define SSL_BAD_CERTTYPE WOLFSSL_BAD_CERTTYPE
    #define SSL_BAD_STAT WOLFSSL_BAD_STAT
    #define SSL_BAD_PATH WOLFSSL_BAD_PATH
    #define SSL_BAD_FILETYPE WOLFSSL_BAD_FILETYPE
    #define SSL_BAD_FILE WOLFSSL_BAD_FILE
    #define SSL_NOT_IMPLEMENTED WOLFSSL_NOT_IMPLEMENTED
    #define SSL_UNKNOWN WOLFSSL_UNKNOWN
    #define SSL_FATAL_ERROR WOLFSSL_FATAL_ERROR

    #define SSL_FILETYPE_ASN1 WOLFSSL_FILETYPE_ASN1
    #define SSL_FILETYPE_PEM WOLFSSL_FILETYPE_PEM
    #define SSL_FILETYPE_DEFAULT WOLFSSL_FILETYPE_DEFAULT

    #define SSL_VERIFY_NONE WOLFSSL_VERIFY_NONE
    #define SSL_VERIFY_PEER WOLFSSL_VERIFY_PEER
    #define SSL_VERIFY_FAIL_IF_NO_PEER_CERT WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
    #define SSL_VERIFY_CLIENT_ONCE WOLFSSL_VERIFY_CLIENT_ONCE
    #define SSL_VERIFY_POST_HANDSHAKE WOLFSSL_VERIFY_POST_HANDSHAKE
    #define SSL_VERIFY_FAIL_EXCEPT_PSK WOLFSSL_VERIFY_FAIL_EXCEPT_PSK

    #define SSL_SESS_CACHE_OFF WOLFSSL_SESS_CACHE_OFF
    #define SSL_SESS_CACHE_CLIENT WOLFSSL_SESS_CACHE_CLIENT
    #define SSL_SESS_CACHE_SERVER WOLFSSL_SESS_CACHE_SERVER
    #define SSL_SESS_CACHE_BOTH WOLFSSL_SESS_CACHE_BOTH
    #define SSL_SESS_CACHE_NO_AUTO_CLEAR WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR
    #define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP
    #define SSL_SESS_CACHE_NO_INTERNAL_STORE WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE
    #define SSL_SESS_CACHE_NO_INTERNAL WOLFSSL_SESS_CACHE_NO_INTERNAL

    #define SSL_ERROR_WANT_READ WOLFSSL_ERROR_WANT_READ
    #define SSL_ERROR_WANT_WRITE WOLFSSL_ERROR_WANT_WRITE
    #define SSL_ERROR_WANT_CONNECT WOLFSSL_ERROR_WANT_CONNECT
    #define SSL_ERROR_WANT_ACCEPT WOLFSSL_ERROR_WANT_ACCEPT
    #define SSL_ERROR_SYSCALL WOLFSSL_ERROR_SYSCALL
    #define SSL_ERROR_WANT_X509_LOOKUP WOLFSSL_ERROR_WANT_X509_LOOKUP
    #define SSL_ERROR_ZERO_RETURN WOLFSSL_ERROR_ZERO_RETURN
    #define SSL_ERROR_SSL WOLFSSL_ERROR_SSL

    #define SSL_SENT_SHUTDOWN WOLFSSL_SENT_SHUTDOWN
    #define SSL_RECEIVED_SHUTDOWN WOLFSSL_RECEIVED_SHUTDOWN
    #define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER

    #define SSL_R_SSL_HANDSHAKE_FAILURE WOLFSSL_R_SSL_HANDSHAKE_FAILURE
    #define SSL_R_TLSV1_ALERT_UNKNOWN_CA WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA
    #define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN
    #define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE
#endif

enum { /* ssl Constants */
    WOLFSSL_ERROR_NONE      =  0,   /* for most functions */
    WOLFSSL_FAILURE         =  0,   /* for some functions */
    WOLFSSL_SUCCESS         =  1,

    #if defined(WOLFSSL_DEBUG_TRACE_ERROR_CODES) && \
            (defined(BUILDING_WOLFSSL) || \
             defined(WOLFSSL_DEBUG_TRACE_ERROR_CODES_ALWAYS))
        #define WOLFSSL_FAILURE WC_ERR_TRACE(WOLFSSL_FAILURE)
        #define CONST_NUM_ERR_WOLFSSL_FAILURE 0
        /* include CONST_NUM_ERR_ variants of the success codes, so that they
         * can be harmlessly wrapped in WC_NO_ERR_TRACE().
         */
        #define CONST_NUM_ERR_WOLFSSL_ERROR_NONE 0
        #define CONST_NUM_ERR_WOLFSSL_SUCCESS 1
    #endif

/* WOLFSSL_SHUTDOWN_NOT_DONE is returned by wolfSSL_shutdown and
 * wolfSSL_SendUserCanceled when the other end
 * of the connection has yet to send its close notify alert as part of the
 * bidirectional shutdown. To complete the shutdown, either keep calling
 * wolfSSL_shutdown until it returns WOLFSSL_SUCCESS or call wolfSSL_read until
 * it returns <= 0 AND SSL_get_error returns SSL_ERROR_ZERO_RETURN. See OpenSSL
 * docs for more: https://www.openssl.org/docs/man1.1.1/man3/SSL_shutdown.html
 */
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
/* SSL_shutdown returns 0 when not done, per OpenSSL documentation. */
    WOLFSSL_SHUTDOWN_NOT_DONE = 0,
#else
    WOLFSSL_SHUTDOWN_NOT_DONE =  2,
#endif

    WOLFSSL_FILETYPE_ASN1    = CTC_FILETYPE_ASN1,
    WOLFSSL_FILETYPE_PEM     = CTC_FILETYPE_PEM,
    WOLFSSL_FILETYPE_DEFAULT = CTC_FILETYPE_ASN1, /* ASN1 */

    WOLFSSL_VERIFY_NONE                 = 0,
    WOLFSSL_VERIFY_PEER                 = 1 << 0,
    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT = 1 << 1,
    WOLFSSL_VERIFY_CLIENT_ONCE          = 1 << 2,
    WOLFSSL_VERIFY_POST_HANDSHAKE       = 1 << 3,
    WOLFSSL_VERIFY_FAIL_EXCEPT_PSK      = 1 << 4,
    WOLFSSL_VERIFY_DEFAULT              = 1 << 9,

    WOLFSSL_SESS_CACHE_OFF                = 0x0000,
    WOLFSSL_SESS_CACHE_CLIENT             = 0x0001,
    WOLFSSL_SESS_CACHE_SERVER             = 0x0002,
    WOLFSSL_SESS_CACHE_BOTH               = 0x0003,
    WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR      = 0x0008,
    WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100,
    WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE  = 0x0200,
    WOLFSSL_SESS_CACHE_NO_INTERNAL        =
            (WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE |
                    WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP),

    /* These values match OpenSSL values for corresponding names.*/
    WOLFSSL_ERROR_SSL              =  1,

    /* Operation did not complete; call this API again.*/
    WOLFSSL_ERROR_WANT_READ        =  2,

    /* Operation did not complete; call this API again.*/
    WOLFSSL_ERROR_WANT_WRITE       =  3,

    /* Operation did not complete; callback needs this API to be called again.*/
    WOLFSSL_ERROR_WANT_X509_LOOKUP =  4,

    /* Some sort of system I/O error happened.*/
    WOLFSSL_ERROR_SYSCALL          =  5,

    /* The connection has been closed with a closure alert.*/
    WOLFSSL_ERROR_ZERO_RETURN      =  6,

    /* Underlying protocol connection not started yet, call this API again.*/
    WOLFSSL_ERROR_WANT_CONNECT     =  7,

    /* Underlying protocol connection not started yet, call this API again.*/
    WOLFSSL_ERROR_WANT_ACCEPT      =  8,

    /* Close notify alert was sent to the peer.*/
    WOLFSSL_SENT_SHUTDOWN     = 1,

    /* Close notify or fatal error was received from the peer.*/
    WOLFSSL_RECEIVED_SHUTDOWN = 2,

    /* Let library know that write buffer might move to different addresses.*/
    WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4,

    /* The handshake failed. */
    WOLFSSL_R_SSL_HANDSHAKE_FAILURE           = 101,

    /* The issuer CA certificate is unknown. */
    WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102,

    /* Unable to validate the certificate. */
    WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103,

    /* There was a problem parsing the certificate. */
    WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104,

    WOLF_PEM_BUFSIZE = 1024
};

#ifndef NO_PSK
    typedef unsigned int (*wc_psk_client_callback)(WOLFSSL* ssl, const char*, char*,
                                    unsigned int, unsigned char*, unsigned int);
    WOLFSSL_API void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx,
                                                        wc_psk_client_callback cb);
    WOLFSSL_API void wolfSSL_set_psk_client_callback(WOLFSSL* ssl,
                                                        wc_psk_client_callback cb);
    #ifdef OPENSSL_EXTRA
    typedef int (*wc_psk_use_session_cb_func)(WOLFSSL* ssl,
                            const WOLFSSL_EVP_MD* md, const unsigned char **id,
                                        size_t* idlen,  WOLFSSL_SESSION **sess);
    WOLFSSL_API void wolfSSL_set_psk_use_session_callback(WOLFSSL* ssl,
                                               wc_psk_use_session_cb_func cb);
    #endif
#ifdef WOLFSSL_TLS13
    typedef unsigned int (*wc_psk_client_cs_callback)(WOLFSSL* ssl, const char*,
        char*, unsigned int, unsigned char*, unsigned int, const char*);
    WOLFSSL_API void wolfSSL_CTX_set_psk_client_cs_callback(WOLFSSL_CTX* ctx,
        wc_psk_client_cs_callback cb);
    WOLFSSL_API void wolfSSL_set_psk_client_cs_callback(WOLFSSL* ssl,
        wc_psk_client_cs_callback cb);

    typedef unsigned int (*wc_psk_client_tls13_callback)(WOLFSSL* ssl, const char*,
        char*, unsigned int, unsigned char*, unsigned int, const char**);
    WOLFSSL_API void wolfSSL_CTX_set_psk_client_tls13_callback(WOLFSSL_CTX* ctx,
        wc_psk_client_tls13_callback cb);
    WOLFSSL_API void wolfSSL_set_psk_client_tls13_callback(WOLFSSL* ssl,
        wc_psk_client_tls13_callback cb);
#endif

    WOLFSSL_API const char* wolfSSL_get_psk_identity_hint(const WOLFSSL* ssl);
    WOLFSSL_API const char* wolfSSL_get_psk_identity(const WOLFSSL* ssl);

    WOLFSSL_API int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint);
    WOLFSSL_API int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint);

    typedef unsigned int (*wc_psk_server_callback)(WOLFSSL* ssl, const char*,
                          unsigned char*, unsigned int);
    WOLFSSL_API void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx,
                                                        wc_psk_server_callback cb);
    WOLFSSL_API void wolfSSL_set_psk_server_callback(WOLFSSL* ssl,
                                                        wc_psk_server_callback cb);
#ifdef WOLFSSL_TLS13
    typedef unsigned int (*wc_psk_server_tls13_callback)(WOLFSSL* ssl, const char*,
        unsigned char*, unsigned int, const char**);
    WOLFSSL_API void wolfSSL_CTX_set_psk_server_tls13_callback(WOLFSSL_CTX* ctx,
        wc_psk_server_tls13_callback cb);
    WOLFSSL_API void wolfSSL_set_psk_server_tls13_callback(WOLFSSL* ssl,
        wc_psk_server_tls13_callback cb);
#endif
    WOLFSSL_API void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl);
    WOLFSSL_API int   wolfSSL_set_psk_callback_ctx(WOLFSSL* ssl, void* psk_ctx);

    WOLFSSL_API void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX* ctx);
    WOLFSSL_API int   wolfSSL_CTX_set_psk_callback_ctx(WOLFSSL_CTX* ctx, void* psk_ctx);

    #define PSK_TYPES_DEFINED

#ifdef WOLFSSL_TLS13
    WOLFSSL_API const char* wolfSSL_get_cipher_name_by_hash(WOLFSSL* ssl,
        const char* hash);
#endif
#endif /* NO_PSK */


#ifdef HAVE_ANON
    WOLFSSL_API int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX* ctx);
#endif /* HAVE_ANON */


/* extra begins */
#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
enum {  /* ERR Constants */
    WOLFSSL_ERR_TXT_STRING = 1
};
#ifndef OPENSSL_COEXIST
#define ERR_TXT_STRING WOLFSSL_ERR_TXT_STRING
#endif
#endif
#ifdef OPENSSL_EXTRA
/* bio misc */
enum {
    WOLFSSL_BIO_ERROR = -1,
    WOLFSSL_BIO_UNSET = -2,
    WOLFSSL_BIO_SIZE  = 17000 /* default BIO write size if not set */
};
#endif

WOLFSSL_API void wolfSSL_ERR_put_error(int lib, int fun, int err,
                                       const char* file, int line);
WOLFSSL_API unsigned long wolfSSL_ERR_get_error_line(const char** file, int* line);
WOLFSSL_API unsigned long wolfSSL_ERR_get_error_line_data(const char** file, int* line,
                                                 const char** data, int* flags);

WOLFSSL_API unsigned long wolfSSL_ERR_get_error(void);
WOLFSSL_API void          wolfSSL_ERR_clear_error(void);


WOLFSSL_API int  wolfSSL_RAND_status(void);
WOLFSSL_API int  wolfSSL_RAND_pseudo_bytes(unsigned char* buf, int num);
WOLFSSL_API int  wolfSSL_RAND_bytes(unsigned char* buf, int num);
WOLFSSL_API long wolfSSL_CTX_set_options(WOLFSSL_CTX* ctx, long opt);
WOLFSSL_API long wolfSSL_CTX_get_options(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_clear_options(WOLFSSL_CTX* ctx, long opt);

#if !defined(NO_CHECK_PRIVATE_KEY)
  WOLFSSL_API int  wolfSSL_CTX_check_private_key(const WOLFSSL_CTX* ctx);
#endif

WOLFSSL_API void wolfSSL_ERR_free_strings(void);
WOLFSSL_API void wolfSSL_ERR_remove_state(unsigned long id);
WOLFSSL_API int  wolfSSL_clear(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_state(WOLFSSL* ssl);

WOLFSSL_API void wolfSSL_cleanup_all_ex_data(void);
WOLFSSL_API long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode);
WOLFSSL_API long wolfSSL_CTX_clear_mode(WOLFSSL_CTX* ctx, long mode);
WOLFSSL_API long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx);
WOLFSSL_API void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m);
WOLFSSL_API long wolfSSL_SSL_get_mode(WOLFSSL* ssl);


WOLFSSL_API int  wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX* ctx);
WOLFSSL_API const char* wolfSSL_X509_get_default_cert_file_env(void);
WOLFSSL_API const char* wolfSSL_X509_get_default_cert_file(void);
WOLFSSL_API const char* wolfSSL_X509_get_default_cert_dir_env(void);
WOLFSSL_API const char* wolfSSL_X509_get_default_cert_dir(void);
WOLFSSL_API int  wolfSSL_CTX_set_session_id_context(WOLFSSL_CTX* ctx,
                                            const unsigned char* sid_ctx, unsigned int sid_ctx_len);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);
#ifdef OPENSSL_EXTRA
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL* ssl);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_set_peer_cert_chain(WOLFSSL* ssl);
#endif

WOLFSSL_API int wolfSSL_want_read(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_want_write(WOLFSSL* ssl);


#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_want(WOLFSSL* ssl);

WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_CTX_get0_privatekey(const WOLFSSL_CTX* ctx);

#include <stdarg.h> /* var_arg */
WOLFSSL_API int wolfSSL_BIO_vprintf(WOLFSSL_BIO* bio, const char* format,
                                                            va_list args);
WOLFSSL_API int wolfSSL_BIO_printf(WOLFSSL_BIO* bio, const char* format, ...);


WOLFSSL_API int wolfSSL_BIO_dump(WOLFSSL_BIO *bio, const char* buf, int length);
WOLFSSL_API int wolfSSL_ASN1_UTCTIME_print(WOLFSSL_BIO* bio,
                                         const WOLFSSL_ASN1_UTCTIME* a);
WOLFSSL_API int wolfSSL_ASN1_GENERALIZEDTIME_print(WOLFSSL_BIO* bio,
                                         const WOLFSSL_ASN1_GENERALIZEDTIME* asnTime);
WOLFSSL_API void wolfSSL_ASN1_GENERALIZEDTIME_free(WOLFSSL_ASN1_GENERALIZEDTIME*);
WOLFSSL_API int wolfSSL_ASN1_TIME_check(const WOLFSSL_ASN1_TIME* a);
WOLFSSL_API int wolfSSL_ASN1_TIME_diff(int* days, int* secs, const WOLFSSL_ASN1_TIME* from,
    const WOLFSSL_ASN1_TIME* to);
WOLFSSL_API int wolfSSL_ASN1_TIME_compare(const WOLFSSL_ASN1_TIME *a,
    const WOLFSSL_ASN1_TIME *b);
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_ASN1_TIME_set(WOLFSSL_ASN1_TIME *s, time_t t);
WOLFSSL_API int wolfSSL_ASN1_TIME_set_string(WOLFSSL_ASN1_TIME *s, const char *str);
WOLFSSL_API int wolfSSL_ASN1_TIME_set_string_X509(WOLFSSL_ASN1_TIME *t,
        const char *str);
#endif /* OPENSSL_EXTRA */


#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API int wolfSSL_sk_num(const WOLFSSL_STACK* sk);
WOLFSSL_API void* wolfSSL_sk_value(const WOLFSSL_STACK* sk, int i);
#endif


/* stunnel 4.28 needs */
WOLFSSL_API void  wolfSSL_CTX_sess_set_get_cb(WOLFSSL_CTX* ctx,
                   WOLFSSL_SESSION*(*f)(WOLFSSL* ssl, const unsigned char*, int, int*));
WOLFSSL_API void  wolfSSL_CTX_sess_set_new_cb(WOLFSSL_CTX* ctx,
                                            int (*f)(WOLFSSL* ssl, WOLFSSL_SESSION*));
WOLFSSL_API void  wolfSSL_CTX_sess_set_remove_cb(WOLFSSL_CTX* ctx,
                                       void (*f)(WOLFSSL_CTX* ctx, WOLFSSL_SESSION*));

WOLFSSL_API int          wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION* sess,unsigned char** p);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_d2i_SSL_SESSION(WOLFSSL_SESSION** sess,
                                                   const unsigned char** p, long i);

WOLFSSL_API int wolfSSL_SESSION_has_ticket(const WOLFSSL_SESSION* session);
WOLFSSL_API unsigned long wolfSSL_SESSION_get_ticket_lifetime_hint(
                              const WOLFSSL_SESSION* sess);
WOLFSSL_API long wolfSSL_SESSION_get_timeout(const WOLFSSL_SESSION* session);
WOLFSSL_API long wolfSSL_SESSION_get_time(const WOLFSSL_SESSION* session);


#ifdef SESSION_CERTS
#ifdef OPENSSL_EXTRA
WOLFSSL_API const char *wolfSSL_get0_peername(WOLFSSL *ssl);
#endif

WOLFSSL_API
    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);
WOLFSSL_API WOLFSSL_X509* wolfSSL_SESSION_get0_peer(WOLFSSL_SESSION* session);

WOLFSSL_API int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx,
                                unsigned char* buf, int inLen, int* outLen);
#endif /* SESSION_CERTS */


/* extra ends */


/* wolfSSL extensions */

/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
WOLFSSL_ABI WOLFSSL_API int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn);


/* need to call once to load library (session cache) */
WOLFSSL_ABI WOLFSSL_API int wolfSSL_Init(void);
/* call when done to cleanup/free session cache mutex / resources  */
WOLFSSL_ABI WOLFSSL_API int wolfSSL_Cleanup(void);

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
#ifndef NO_FILESYSTEM
WOLFSSL_API int    wolfSSL_crypto_policy_enable(const char * policy);
#endif /* ! NO_FILESYSTEM */
WOLFSSL_API int    wolfSSL_crypto_policy_enable_buffer(const char * buf);
WOLFSSL_API void   wolfSSL_crypto_policy_disable(void);
WOLFSSL_API int    wolfSSL_crypto_policy_is_enabled(void);
WOLFSSL_API const char * wolfSSL_crypto_policy_get_ciphers(void);
WOLFSSL_API int    wolfSSL_crypto_policy_get_level(void);
WOLFSSL_LOCAL int  wolfSSL_crypto_policy_init_ctx(WOLFSSL_CTX * ctx,
                                                  WOLFSSL_METHOD * method);
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */
/* compat functions. */
WOLFSSL_API int    wolfSSL_get_security_level(const WOLFSSL * ssl);
#ifndef NO_WOLFSSL_STUB
WOLFSSL_API void   wolfSSL_set_security_level(WOLFSSL * ssl, int level);
#endif /* !NO_WOLFSSL_STUB */

/* which library version do we have */
WOLFSSL_API const char* wolfSSL_lib_version(void);
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
WOLFSSL_API const char* wolfSSL_OpenSSL_version(int a);
#else
WOLFSSL_API const char* wolfSSL_OpenSSL_version(void);
#endif
/* which library version do we have in hex */
WOLFSSL_API word32 wolfSSL_lib_version_hex(void);

/* do accept or connect depedning on side */
WOLFSSL_API int wolfSSL_negotiate(WOLFSSL* ssl);
/* turn on wolfSSL data compression */
WOLFSSL_API int wolfSSL_set_compression(WOLFSSL* ssl);

WOLFSSL_ABI WOLFSSL_API int wolfSSL_set_timeout(WOLFSSL* ssl, unsigned int to);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_set_timeout(WOLFSSL_CTX* ctx, unsigned int to);
WOLFSSL_API void wolfSSL_CTX_set_current_time_cb(WOLFSSL_CTX* ctx,
    void (*cb)(const WOLFSSL* ssl, WOLFSSL_TIMEVAL* out_clock));

/* get wolfSSL peer X509_CHAIN */
WOLFSSL_API WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl);
#ifdef WOLFSSL_ALT_CERT_CHAINS
WOLFSSL_API int wolfSSL_is_peer_alt_cert_chain(const WOLFSSL* ssl);
/* get wolfSSL alternate peer X509_CHAIN */
WOLFSSL_API WOLFSSL_X509_CHAIN* wolfSSL_get_peer_alt_chain(WOLFSSL* ssl);
#endif
/* peer chain count */
WOLFSSL_API int  wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain);
/* index cert length */
WOLFSSL_API int  wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx);
/* index cert */
WOLFSSL_API unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx);
/* index cert in X509 */
WOLFSSL_API WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx);


#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(KEEP_PEER_CERT) || defined(KEEP_OUR_CERT) || defined(SESSION_CERTS)

WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_new(void);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_new_ex(void* heap);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_dup(WOLFSSL_X509* x);

WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_get_issuer_name(
                                                            WOLFSSL_X509* cert);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_get_subject_name(
                                                            WOLFSSL_X509* cert);

WOLFSSL_API int wolfSSL_X509_get_signature_type(WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_get_isCA(WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_get_signature(WOLFSSL_X509* x509,
    unsigned char* buf, int* bufSz);
WOLFSSL_API int wolfSSL_X509_get_pubkey_buffer(WOLFSSL_X509* x509,
    unsigned char* buf, int* bufSz);
WOLFSSL_API int wolfSSL_X509_get_pubkey_type(WOLFSSL_X509* x509);

#ifndef NO_FILESYSTEM
WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_load_certificate_file(const char* fname, int format);
#endif
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_load_certificate_buffer(
    const unsigned char* buf, int sz, int format);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_REQ_load_certificate_buffer(
    const unsigned char* buf, int sz, int format);
#endif

/* free X509 */
#define wolfSSL_FreeX509(x509) wolfSSL_X509_free((x509))
WOLFSSL_ABI WOLFSSL_API void wolfSSL_X509_free(WOLFSSL_X509* x509);

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL || KEEP_PEER_CERT || \
          KEEP_OUR_CERT || SESSION_CERTS */


/* get index cert in PEM */

WOLFSSL_ABI WOLFSSL_API const unsigned char* wolfSSL_get_sessionID(
                                                      const WOLFSSL_SESSION* s);
WOLFSSL_API int  wolfSSL_X509_get_serial_number(WOLFSSL_X509* x509,unsigned char* in,int* inOutSz);
WOLFSSL_API char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509* x509);
WOLFSSL_API const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz);
WOLFSSL_API const unsigned char* wolfSSL_X509_get_tbs(WOLFSSL_X509* x509, int* outSz);
WOLFSSL_ABI WOLFSSL_API const byte* wolfSSL_X509_notBefore(WOLFSSL_X509* x509);
WOLFSSL_ABI WOLFSSL_API const byte* wolfSSL_X509_notAfter(WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_version(WOLFSSL_X509* x509);

WOLFSSL_API int wolfSSL_cmp_peer_cert_to_file(WOLFSSL* ssl, const char* fname);

WOLFSSL_ABI WOLFSSL_API char* wolfSSL_X509_get_next_altname(WOLFSSL_X509* cert);
WOLFSSL_API int wolfSSL_X509_add_altname_ex(WOLFSSL_X509* x509, const char* name, word32 nameSz, int type);
WOLFSSL_API int wolfSSL_X509_add_altname(WOLFSSL_X509* x509, const char* name, int type);

WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509(WOLFSSL_X509** x509,
        const unsigned char** in, int len);
WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_d2i(WOLFSSL_X509** x509, const unsigned char* in, int len);
WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_d2i_ex(WOLFSSL_X509** x509, const unsigned char* in, int len,
    void* heap);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_REQ_d2i(WOLFSSL_X509** x509, const unsigned char* in, int len);
WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509_REQ_INFO(WOLFSSL_X509** req,
        const unsigned char** in, int len);
#endif
WOLFSSL_API int wolfSSL_i2d_X509(WOLFSSL_X509* x509, unsigned char** out);
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_d2i_X509_CRL(WOLFSSL_X509_CRL **crl,
                                                   const unsigned char *in, int len);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_d2i_X509_CRL_fp(XFILE file, WOLFSSL_X509_CRL **crl);
#endif
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA)
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_d2i_X509_CRL_bio(WOLFSSL_BIO *bp,
                                                    WOLFSSL_X509_CRL **crl);
WOLFSSL_API int wolfSSL_X509_CRL_version(WOLFSSL_X509_CRL *crl);
WOLFSSL_API int wolfSSL_X509_CRL_get_signature_type(WOLFSSL_X509_CRL* crl);
WOLFSSL_API int wolfSSL_X509_CRL_get_signature_nid(
                                                  const WOLFSSL_X509_CRL* crl);
WOLFSSL_API int wolfSSL_X509_CRL_get_signature(WOLFSSL_X509_CRL* crl,
                                               unsigned char* buf, int* bufSz);
WOLFSSL_API int wolfSSL_X509_CRL_print(WOLFSSL_BIO* bio,
                                       WOLFSSL_X509_CRL* crl);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_CRL_get_issuer_name(
                                                        WOLFSSL_X509_CRL *crl);
WOLFSSL_API int wolfSSL_X509_REVOKED_get_serial_number(RevokedCert* rev,
                                                       byte* in, int* inOutSz);
#endif
#if defined(HAVE_CRL) && (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL))
WOLFSSL_API WOLFSSL_X509_CRL* wolfSSL_X509_CRL_dup(const WOLFSSL_X509_CRL* crl);
WOLFSSL_API void wolfSSL_X509_CRL_free(WOLFSSL_X509_CRL *crl);
#endif

#if defined(WOLFSSL_ACERT) && \
   (defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA))
WOLFSSL_API WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_new_ex(void * heap);
WOLFSSL_API WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_new(void);
WOLFSSL_API void wolfSSL_X509_ACERT_init(WOLFSSL_X509_ACERT * x509,
                                         int dynamic, void * heap);
WOLFSSL_API void wolfSSL_X509_ACERT_free(WOLFSSL_X509_ACERT* x509);
#ifndef NO_WOLFSSL_STUB
WOLFSSL_API int  wolfSSL_X509_ACERT_sign(WOLFSSL_X509_ACERT * x509,
                                        WOLFSSL_EVP_PKEY * pkey,
                                        const WOLFSSL_EVP_MD * md);
#endif /* !NO_WOLFSSL_STUB */
WOLFSSL_API int  wolfSSL_X509_ACERT_verify(WOLFSSL_X509_ACERT* x509,
                                           WOLFSSL_EVP_PKEY* pkey);
#if defined(OPENSSL_EXTRA)
WOLFSSL_API int  wolfSSL_X509_ACERT_get_signature_nid(
                                                  const WOLFSSL_X509_ACERT* x);
WOLFSSL_API int  wolfSSL_X509_ACERT_print(WOLFSSL_BIO* bio,
                                          WOLFSSL_X509_ACERT* x509_acert);
WOLFSSL_API WOLFSSL_X509_ACERT * wolfSSL_PEM_read_bio_X509_ACERT(
    WOLFSSL_BIO *bp, WOLFSSL_X509_ACERT **x, wc_pem_password_cb *cb, void *u);
WOLFSSL_API long wolfSSL_X509_ACERT_get_version(const WOLFSSL_X509_ACERT *x);
#endif /* OPENSSL_EXTRA */
WOLFSSL_API int  wolfSSL_X509_ACERT_get_attr_buf(const WOLFSSL_X509_ACERT* x509,
                                                 const byte ** rawAttr,
                                                 word32 * rawAttrLen);
WOLFSSL_API int  wolfSSL_X509_ACERT_get_serial_number(WOLFSSL_X509_ACERT* x509,
                                                      unsigned char* in,
                                                      int * inOutSz);
WOLFSSL_API int  wolfSSL_X509_ACERT_version(WOLFSSL_X509_ACERT* x509);
WOLFSSL_API int  wolfSSL_X509_ACERT_get_signature(WOLFSSL_X509_ACERT* x509,
                                                  unsigned char* buf,
                                                  int* bufSz);
WOLFSSL_API WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_load_certificate_buffer_ex(
    const unsigned char* buf, int sz, int format, void * heap);
WOLFSSL_API WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_load_certificate_buffer(
    const unsigned char* buf, int sz, int format);
#endif /* WOLFSSL_ACERT && (OPENSSL_EXTRA_X509_SMALL || OPENSSL_EXTRA) */

#ifdef OPENSSL_EXTRA
WOLFSSL_API
const WOLFSSL_ASN1_INTEGER* wolfSSL_X509_REVOKED_get0_serial_number(const
                                                     WOLFSSL_X509_REVOKED *rev);
WOLFSSL_API
const WOLFSSL_ASN1_TIME* wolfSSL_X509_REVOKED_get0_revocation_date(const
                                                     WOLFSSL_X509_REVOKED *rev);

#ifndef NO_FILESYSTEM
    #ifndef NO_STDIO_FILESYSTEM
    WOLFSSL_API WOLFSSL_X509*
        wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, XFILE file);
    #endif
#endif

#ifdef WOLFSSL_SEP
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_device_type(WOLFSSL_X509* x509, unsigned char* in, int* inOutSz);
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_type(WOLFSSL_X509* x509, unsigned char* in, int* inOutSz);
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509* x509, unsigned char* in, int* inOutSz);
#endif

#endif /* OPENSSL_EXTRA */

/* connect enough to get peer cert */
WOLFSSL_API int  wolfSSL_connect_cert(WOLFSSL* ssl);


#ifdef OPENSSL_EXTRA
/* PKCS12 compatibility */
WOLFSSL_API void wolfSSL_PKCS12_PBE_add(void);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API WOLFSSL_X509_PKCS12* wolfSSL_d2i_PKCS12_fp(XFILE fp,
                                       WOLFSSL_X509_PKCS12** pkcs12);
#endif

#ifdef HAVE_PKCS12
WOLFSSL_API WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12** pkcs12);
WOLFSSL_API int wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO *bio, WC_PKCS12 *pkcs12);

WOLFSSL_API int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
     WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert,
     WOLF_STACK_OF(WOLFSSL_X509)** ca);
WOLFSSL_API int wolfSSL_PKCS12_verify_mac(WC_PKCS12 *pkcs12, const char *psw,
        int pswLen);
WOLFSSL_API WC_PKCS12* wolfSSL_PKCS12_create(char* pass, char* name,
        WOLFSSL_EVP_PKEY* pkey, WOLFSSL_X509* cert,
        WOLF_STACK_OF(WOLFSSL_X509)* ca,
        int keyNID, int certNID, int itt, int macItt, int keytype);
#endif /* HAVE_PKCS12 */
#endif /* OPENSSL_EXTRA */


#ifndef NO_DH
/* server Diffie-Hellman parameters */
WOLFSSL_API int  wolfSSL_SetTmpDH(WOLFSSL* ssl, const unsigned char* p, int pSz,
                                const unsigned char* g, int gSz);
WOLFSSL_API int  wolfSSL_SetTmpDH_buffer(WOLFSSL* ssl, const unsigned char* b, long sz,
                                       int format);
WOLFSSL_API int wolfSSL_SetEnableDhKeyTest(WOLFSSL* ssl, int enable);
#ifndef NO_FILESYSTEM
    WOLFSSL_API int  wolfSSL_SetTmpDH_file(WOLFSSL* ssl, const char* f, int format);
#endif

/* server ctx Diffie-Hellman parameters */
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX* ctx, const unsigned char* b,
                                           long sz, int format);

#ifndef NO_FILESYSTEM
    WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* f,
                                             int format);
#endif

WOLFSSL_API int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits);
WOLFSSL_API int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);
WOLFSSL_API int wolfSSL_CTX_SetMaxDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits);
WOLFSSL_API int wolfSSL_SetMaxDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);
WOLFSSL_API int wolfSSL_GetDhKey_Sz(WOLFSSL* ssl);
#endif /* NO_DH */

#ifndef NO_RSA
WOLFSSL_API int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX* ctx, short keySz);
WOLFSSL_API int wolfSSL_SetMinRsaKey_Sz(WOLFSSL* ssl, short keySz);
#endif /* NO_RSA */

#ifdef HAVE_ECC
WOLFSSL_API int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX* ctx, short keySz);
WOLFSSL_API int wolfSSL_SetMinEccKey_Sz(WOLFSSL* ssl, short keySz);
#endif /* NO_RSA */

WOLFSSL_API int  wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL* ssl, word16 sz);
WOLFSSL_API int  wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX* ctx, word16 sz);

/* keyblock size in bytes or -1 */
/* need to call wolfSSL_KeepArrays before handshake to save keys */
WOLFSSL_API int wolfSSL_get_keyblock_size(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_get_keys(WOLFSSL* ssl,unsigned char** ms, unsigned int* msLen,
                                       unsigned char** sr, unsigned int* srLen,
                                       unsigned char** cr, unsigned int* crLen);

/* Computes EAP-TLS and EAP-TTLS keying material from the master_secret. */
WOLFSSL_API int wolfSSL_make_eap_keys(WOLFSSL* ssl, void* key, unsigned int len,
                                                             const char* label);


#ifndef _WIN32
    #ifndef NO_WRITEV
        #ifdef __PPU
            #include <sys/types.h>
            #include <sys/socket.h>
        #elif defined(ARDUINO)
            /* TODO board specific */
        #elif defined(NUCLEUS_PLUS_2_3)
            #include "services/sys/uio.h"
        #elif !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_IAR_ARM)    && \
              !defined(WOLFSSL_PICOTCP) && !defined(WOLFSSL_ROWLEY_ARM) && \
              !defined(WOLFSSL_EMBOS)   && !defined(WOLFSSL_FROSTED)    && \
              !defined(WOLFSSL_CHIBIOS) && !defined(WOLFSSL_CONTIKI)    && \
              !defined(WOLFSSL_ZEPHYR)  && !defined(NETOS) && \
              !defined(WOLFSSL_NDS)
            #include <sys/uio.h>
        #endif
        /* allow writev style writing */
        WOLFSSL_API int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);
    #endif /* !NO_WRITEV */
#endif /* !_WIN32 */


#ifndef NO_CERTS
    /* SSL_CTX versions */
    WOLFSSL_API int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_UnloadIntermediateCerts(WOLFSSL_CTX* ctx);
#ifdef WOLFSSL_TRUST_PEER_CERT
    WOLFSSL_API int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX* ctx);
#ifdef WOLFSSL_LOCAL_X509_STORE
    WOLFSSL_API int wolfSSL_Unload_trust_peers(WOLFSSL* ssl);
#endif
    WOLFSSL_API int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX* ctx,
                                       const unsigned char* in,
                                       long sz, int format);
#endif
    WOLFSSL_API int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX* ctx,
                                               const unsigned char* in, long sz, int format,
                                               int userChain, word32 flags);
    WOLFSSL_API int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx,
                                               const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_CTX_load_verify_chain_buffer_format(WOLFSSL_CTX* ctx,
                                               const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
                                               const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx,
                                               const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_id(WOLFSSL_CTX* ctx,
                                                  const unsigned char* id, long sz,
                                                  int devId, long keySz);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_Id(WOLFSSL_CTX* ctx,
                                                  const unsigned char* id, long sz,
                                                  int devId);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_Label(WOLFSSL_CTX* ctx, const char* label,
                                                     int devId);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx,
                                               const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX* ctx,
                                                    const unsigned char* in, long sz);
#if defined(WOLF_CRYPTO_CB)
    WOLFSSL_API int wolfSSL_CTX_use_certificate_label(WOLFSSL_CTX* ctx,
                                                const char *label, int devId);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_id(WOLFSSL_CTX* ctx,
                                const unsigned char *id, int idLen, int devId);
#endif
#ifdef WOLFSSL_DUAL_ALG_CERTS
    WOLFSSL_API int wolfSSL_CTX_use_AltPrivateKey_buffer(WOLFSSL_CTX* ctx,
                                const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_CTX_use_AltPrivateKey_id(WOLFSSL_CTX* ctx,
                                const unsigned char* id, long sz,
                                int devId, long keySz);
    WOLFSSL_API int wolfSSL_CTX_use_AltPrivateKey_Id(WOLFSSL_CTX* ctx,
                                const unsigned char* id, long sz, int devId);
    WOLFSSL_API int wolfSSL_CTX_use_AltPrivateKey_Label(WOLFSSL_CTX* ctx,
                                const char* label, int devId);
#endif

    /* SSL versions */
    WOLFSSL_API int wolfSSL_use_certificate_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);
    WOLFSSL_API int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl,
                                           const unsigned char* der, int derSz);
    WOLFSSL_API int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);
    WOLFSSL_API int wolfSSL_use_PrivateKey_id(WOLFSSL* ssl, const unsigned char* id,
                                              long sz, int devId, long keySz);
    WOLFSSL_API int wolfSSL_use_PrivateKey_Id(WOLFSSL* ssl, const unsigned char* id,
                                              long sz, int devId);
    WOLFSSL_API int wolfSSL_use_PrivateKey_Label(WOLFSSL* ssl, const char* label, int devId);
    WOLFSSL_API int wolfSSL_use_certificate_chain_buffer_format(WOLFSSL* ssl,
                                               const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl,
                                               const unsigned char* in, long sz);
    WOLFSSL_API int wolfSSL_UnloadCertsKeys(WOLFSSL* ssl);
#ifdef WOLFSSL_DUAL_ALG_CERTS
    WOLFSSL_API int wolfSSL_use_AltPrivateKey_buffer(WOLFSSL* ssl,
                                const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_use_AltPrivateKey_id(WOLFSSL* ssl,
                                const unsigned char* id, long sz,
                                int devId, long keySz);
    WOLFSSL_API int wolfSSL_use_AltPrivateKey_Id(WOLFSSL* ssl,
                                const unsigned char* id, long sz, int devId);
    WOLFSSL_API int wolfSSL_use_AltPrivateKey_Label(WOLFSSL* ssl,
                                const char* label, int devId);
#endif

    #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
        defined(KEEP_OUR_CERT)
        WOLFSSL_API WOLFSSL_X509* wolfSSL_get_certificate(WOLFSSL* ssl);
        WOLFSSL_API WOLFSSL_X509* wolfSSL_CTX_get0_certificate(WOLFSSL_CTX* ctx);
    #endif
#endif

WOLFSSL_API int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_set_group_messages(WOLFSSL* ssl);


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

WOLFSSL_API void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx);
#endif


WOLFSSL_API int   wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl, const byte* secret, word32 secretSz);


/* CA cache callbacks */
enum {
    WOLFSSL_SSLV3    = 0,
    WOLFSSL_TLSV1    = 1,
    WOLFSSL_TLSV1_1  = 2,
    WOLFSSL_TLSV1_2  = 3,
    WOLFSSL_TLSV1_3  = 4,
    WOLFSSL_DTLSV1   = 5,
    WOLFSSL_DTLSV1_2 = 6,
    WOLFSSL_DTLSV1_3 = 7,

    WOLFSSL_USER_CA  = 1,          /* user added as trusted */
    WOLFSSL_CHAIN_CA = 2,          /* added to cache from trusted chain */
    WOLFSSL_TEMP_CA = 3            /* Temp intermediate CA, only for use by
                                    * X509_STORE */
};

WOLFSSL_ABI WOLFSSL_API WC_RNG* wolfSSL_GetRNG(WOLFSSL* ssl);

WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);
WOLFSSL_API int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version);
WOLFSSL_API int wolfSSL_GetObjectSize(void);  /* object size based on build */
WOLFSSL_API int wolfSSL_CTX_GetObjectSize(void);
WOLFSSL_API int wolfSSL_METHOD_GetObjectSize(void);
WOLFSSL_API int wolfSSL_GetOutputSize(WOLFSSL* ssl, int inSz);
WOLFSSL_API int wolfSSL_GetMaxOutputSize(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_GetVersion(const WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SetVersion(WOLFSSL* ssl, int version);

/* moved to asn.c, old names kept for backwards compatibility */
#define wolfSSL_KeyPemToDer    wc_KeyPemToDer
#define wolfSSL_CertPemToDer   wc_CertPemToDer
#define wolfSSL_PemPubKeyToDer wc_PemPubKeyToDer
#define wolfSSL_PubKeyPemToDer wc_PubKeyPemToDer
#define wolfSSL_PemCertToDer   wc_PemCertToDer


typedef void (*CallbackCACache)(unsigned char* der, int sz, int type);
typedef void (*CbMissingCRL)(const char* url);
typedef int  (*crlErrorCb)(int ret, WOLFSSL_CRL* crl, WOLFSSL_CERT_MANAGER* cm,
                           void* ctx);
typedef int  (*CbOCSPIO)(void*, const char*, int,
                                         unsigned char*, int, unsigned char**);
typedef void (*CbOCSPRespFree)(void*,unsigned char*);

#ifdef HAVE_CRL_IO
typedef int  (*CbCrlIO)(WOLFSSL_CRL* crl, const char* url, int urlSz);
#endif

#ifdef HAVE_CRL_UPDATE_CB
typedef struct CrlInfo {
    byte *issuerHash;
    word32 issuerHashLen;
    byte *lastDate;
    word32 lastDateMaxLen;
    byte lastDateFormat;
    byte *nextDate;
    word32 nextDateMaxLen;
    byte nextDateFormat;
    sword32 crlNumber;
} CrlInfo;

typedef void (*CbUpdateCRL)(CrlInfo* old, CrlInfo* cnew);
#endif

/* User Atomic Record Layer CallBacks */
typedef int (*CallbackMacEncrypt)(WOLFSSL* ssl, unsigned char* macOut,
       const unsigned char* macIn, unsigned int macInSz, int macContent,
       int macVerify, unsigned char* encOut, const unsigned char* encIn,
       unsigned int encSz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX* ctx, CallbackMacEncrypt cb);
WOLFSSL_API void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

typedef int (*CallbackDecryptVerify)(WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int verify, unsigned int* padSz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX* ctx,
                                                 CallbackDecryptVerify cb);
WOLFSSL_API void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

typedef int (*CallbackEncryptMac)(WOLFSSL* ssl, unsigned char* macOut,
       int content, int macVerify, unsigned char* encOut,
       const unsigned char* encIn, unsigned int encSz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEncryptMacCb(WOLFSSL_CTX* ctx, CallbackEncryptMac cb);
WOLFSSL_API void  wolfSSL_SetEncryptMacCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEncryptMacCtx(WOLFSSL* ssl);

#ifdef WOLFSSL_THREADED_CRYPT
    #ifndef WOLFSSL_THREADED_CRYPT_CNT
        #define WOLFSSL_THREADED_CRYPT_CNT  16
    #endif

typedef void (*WOLFSSL_THREAD_SIGNAL)(void* ctx, WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_AsyncEncryptReady(WOLFSSL* ssl, int idx);
WOLFSSL_API int wolfSSL_AsyncEncryptStop(WOLFSSL* ssl, int idx);
WOLFSSL_API int wolfSSL_AsyncEncrypt(WOLFSSL* ssl, int idx);
WOLFSSL_API int wolfSSL_AsyncEncryptSetSignal(WOLFSSL* ssl, int idx,
   WOLFSSL_THREAD_SIGNAL signal, void* ctx);
#endif


typedef int (*CallbackVerifyDecrypt)(WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int verify, unsigned int* padSz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetVerifyDecryptCb(WOLFSSL_CTX* ctx,
                                                 CallbackVerifyDecrypt cb);
WOLFSSL_API void  wolfSSL_SetVerifyDecryptCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetVerifyDecryptCtx(WOLFSSL* ssl);

WOLFSSL_API const unsigned char* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify);
WOLFSSL_API const unsigned char* wolfSSL_GetDtlsMacSecret(WOLFSSL* ssl, int verify, int epochOrder);
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL* ssl);
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL* ssl);
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL* ssl);
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetKeySize(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetIVSize(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetSide(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_IsTLSv1_1(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetBulkCipher(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetCipherBlockSize(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetAeadMacSize(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetHmacSize(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_GetHmacType(WOLFSSL* ssl);
#ifdef WORD64_AVAILABLE
WOLFSSL_API int                  wolfSSL_GetPeerSequenceNumber(WOLFSSL* ssl, word64* seq);
WOLFSSL_API int                  wolfSSL_GetSequenceNumber(WOLFSSL* ssl, word64* seq);
#endif
WOLFSSL_API int                  wolfSSL_GetCipherType(WOLFSSL* ssl);
WOLFSSL_API int                  wolfSSL_SetTlsHmacInner(WOLFSSL* ssl,
                               byte* inner, word32 sz, int content, int verify);

/* Atomic User Needs */
enum {
    WOLFSSL_SERVER_END = 0,
    WOLFSSL_CLIENT_END = 1,
    WOLFSSL_NEITHER_END = 3,
    WOLFSSL_BLOCK_TYPE = 2,
    WOLFSSL_STREAM_TYPE = 3,
    WOLFSSL_AEAD_TYPE = 4,
    WOLFSSL_TLS_HMAC_INNER_SZ = 13 /* SEQ_SZ + ENUM + VERSION_SZ + LEN_SZ */
};

/* for GetBulkCipher and internal use
 * using explicit values to assist with serialization of a TLS session */
enum BulkCipherAlgorithm {
    wolfssl_cipher_null = 0,
    wolfssl_rc4         = 1,
    wolfssl_rc2         = 2,
    wolfssl_des         = 3,
    wolfssl_triple_des  = 4,
    wolfssl_des40       = 5,
    wolfssl_aes         = 6,
    wolfssl_aes_gcm     = 7,
    wolfssl_aes_ccm     = 8,
    wolfssl_chacha      = 9,
    wolfssl_camellia    = 10,
    wolfssl_sm4_cbc     = 11,
    wolfssl_sm4_gcm     = 12,
    wolfssl_sm4_ccm     = 13,
    wolfssl_aria_gcm    = 14
};


/* for KDF TLS 1.2 mac types */
enum KDF_MacAlgorithm {
    wolfssl_sha256 = 4,     /* needs to match hash.h wc_MACAlgorithm */
    wolfssl_sha384,
    wolfssl_sha512,
    wolfssl_sm3 = 9
};


/* Public Key Callback support */
#ifdef HAVE_PK_CALLBACKS
#ifdef HAVE_ECC

struct ecc_key;

typedef int (*CallbackEccKeyGen)(WOLFSSL* ssl, struct ecc_key* key,
    unsigned int keySz, int ecc_curve, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEccKeyGenCb(WOLFSSL_CTX* ctx, CallbackEccKeyGen cb);
WOLFSSL_API void  wolfSSL_SetEccKeyGenCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccKeyGenCtx(WOLFSSL* ssl);

typedef int (*CallbackEccSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_ABI WOLFSSL_API void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx,
                                                               CallbackEccSign cb);
WOLFSSL_API void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);
WOLFSSL_API void  wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx);
WOLFSSL_API void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx);

typedef int (*CallbackEccVerify)(WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* hash, unsigned int hashSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb);
WOLFSSL_API void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

typedef int (*CallbackEccSharedSecret)(WOLFSSL* ssl, struct ecc_key* otherKey,
        unsigned char* pubKeyDer, word32* pubKeySz,
        unsigned char* out, word32* outlen,
        int side, void* ctx); /* side is WOLFSSL_CLIENT_END or WOLFSSL_SERVER_END */
WOLFSSL_API void  wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX* ctx, CallbackEccSharedSecret cb);
WOLFSSL_API void  wolfSSL_SetEccSharedSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccSharedSecretCtx(WOLFSSL* ssl);
#endif

#ifdef HAVE_HKDF
#include <wolfssl/wolfcrypt/kdf.h>
typedef int (*CallbackHKDFExtract)(byte* prk, const byte* salt, word32 saltLen,
       byte* ikm, word32 ikmLen, int digest, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetHKDFExtractCb(WOLFSSL_CTX* ctx, CallbackHKDFExtract cb);
WOLFSSL_API void* wolfSSL_GetHKDFExtractCtx(WOLFSSL* ssl);
WOLFSSL_API void  wolfSSL_SetHKDFExtractCtx(WOLFSSL* ssl, void *ctx);
#endif

#ifndef NO_DH
/* Public DH Key Callback support */
struct DhKey;
typedef int (*CallbackDhGenerateKeyPair)(DhKey* key, WC_RNG* rng,
                                         byte* priv, word32* privSz,
                                         byte* pub, word32* pubSz);
typedef int (*CallbackDhAgree)(WOLFSSL* ssl, struct DhKey* key,
        const unsigned char* priv, unsigned int privSz,
        const unsigned char* otherPubKeyDer, unsigned int otherPubKeySz,
        unsigned char* out, word32* outlen,
        void* ctx);
WOLFSSL_API void wolfSSL_CTX_SetDhGenerateKeyPair(WOLFSSL_CTX* ctx,
                                                  CallbackDhGenerateKeyPair cb);
WOLFSSL_API void wolfSSL_CTX_SetDhAgreeCb(WOLFSSL_CTX* ctx,
                                           CallbackDhAgree cb);
WOLFSSL_API void wolfSSL_SetDhAgreeCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetDhAgreeCtx(WOLFSSL* ssl);
#endif /* !NO_DH */

#ifdef HAVE_ED25519
struct ed25519_key;
typedef int (*CallbackEd25519Sign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd25519SignCb(WOLFSSL_CTX* ctx,
                                               CallbackEd25519Sign cb);
WOLFSSL_API void  wolfSSL_SetEd25519SignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd25519SignCtx(WOLFSSL* ssl);

typedef int (*CallbackEd25519Verify)(WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* msg, unsigned int msgSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd25519VerifyCb(WOLFSSL_CTX* ctx,
                                                 CallbackEd25519Verify cb);
WOLFSSL_API void  wolfSSL_SetEd25519VerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd25519VerifyCtx(WOLFSSL* ssl);
#endif

#ifdef HAVE_CURVE25519
struct curve25519_key;

typedef int (*CallbackX25519KeyGen)(WOLFSSL* ssl, struct curve25519_key* key,
    unsigned int keySz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetX25519KeyGenCb(WOLFSSL_CTX* ctx, CallbackX25519KeyGen cb);
WOLFSSL_API void  wolfSSL_SetX25519KeyGenCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX25519KeyGenCtx(WOLFSSL* ssl);

typedef int (*CallbackX25519SharedSecret)(WOLFSSL* ssl,
        struct curve25519_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx);
        /* side is WOLFSSL_CLIENT_END or WOLFSSL_SERVER_END */
WOLFSSL_API void  wolfSSL_CTX_SetX25519SharedSecretCb(WOLFSSL_CTX* ctx,
        CallbackX25519SharedSecret cb);
WOLFSSL_API void  wolfSSL_SetX25519SharedSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX25519SharedSecretCtx(WOLFSSL* ssl);
#endif

#ifdef HAVE_ED448
struct ed448_key;
typedef int (*CallbackEd448Sign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd448SignCb(WOLFSSL_CTX* ctx,
                                               CallbackEd448Sign cb);
WOLFSSL_API void  wolfSSL_SetEd448SignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd448SignCtx(WOLFSSL* ssl);

typedef int (*CallbackEd448Verify)(WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* msg, unsigned int msgSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd448VerifyCb(WOLFSSL_CTX* ctx,
                                                 CallbackEd448Verify cb);
WOLFSSL_API void  wolfSSL_SetEd448VerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd448VerifyCtx(WOLFSSL* ssl);
#endif

#ifdef HAVE_CURVE448
struct curve448_key;

typedef int (*CallbackX448KeyGen)(WOLFSSL* ssl, struct curve448_key* key,
    unsigned int keySz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetX448KeyGenCb(WOLFSSL_CTX* ctx, CallbackX448KeyGen cb);
WOLFSSL_API void  wolfSSL_SetX448KeyGenCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX448KeyGenCtx(WOLFSSL* ssl);

typedef int (*CallbackX448SharedSecret)(WOLFSSL* ssl,
        struct curve448_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx);
        /* side is WOLFSSL_CLIENT_END or WOLFSSL_SERVER_END */
WOLFSSL_API void  wolfSSL_CTX_SetX448SharedSecretCb(WOLFSSL_CTX* ctx,
        CallbackX448SharedSecret cb);
WOLFSSL_API void  wolfSSL_SetX448SharedSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX448SharedSecretCtx(WOLFSSL* ssl);
#endif

#ifndef NO_RSA
typedef int (*CallbackRsaSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb);
WOLFSSL_API void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

typedef int (*CallbackRsaVerify)(WOLFSSL* ssl,
       unsigned char* sig, unsigned int sigSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);
WOLFSSL_API void  wolfSSL_CTX_SetRsaSignCheckCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);
WOLFSSL_API void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

#ifdef WC_RSA_PSS
typedef int (*CallbackRsaPssSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       int hash, int mgf,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaPssSignCb(WOLFSSL_CTX* ctx, CallbackRsaPssSign cb);
WOLFSSL_API void  wolfSSL_SetRsaPssSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaPssSignCtx(WOLFSSL* ssl);

typedef int (*CallbackRsaPssVerify)(WOLFSSL* ssl,
       unsigned char* sig, unsigned int sigSz,
       unsigned char** out,
       int hash, int mgf,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaPssVerifyCb(WOLFSSL_CTX* ctx,
                                                CallbackRsaPssVerify cb);
WOLFSSL_API void  wolfSSL_CTX_SetRsaPssSignCheckCb(WOLFSSL_CTX* ctx,
                                                    CallbackRsaPssVerify cb);
WOLFSSL_API void  wolfSSL_SetRsaPssVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaPssVerifyCtx(WOLFSSL* ssl);
#endif

/* RSA Public Encrypt cb */
typedef int (*CallbackRsaEnc)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb);
WOLFSSL_API void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/* RSA Private Decrypt cb */
typedef int (*CallbackRsaDec)(WOLFSSL* ssl,
       unsigned char* in, unsigned int inSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb);
WOLFSSL_API void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);
#endif

/* Protocol Callback */
typedef int (*CallbackGenMasterSecret)(WOLFSSL* ssl, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetGenMasterSecretCb(WOLFSSL_CTX* ctx,
                                                    CallbackGenMasterSecret cb);
WOLFSSL_API void  wolfSSL_SetGenMasterSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetGenMasterSecretCtx(WOLFSSL* ssl);

typedef int (*CallbackGenExtMasterSecret)(WOLFSSL* ssl, byte* hash,
                                            word32 hashsz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetGenExtMasterSecretCb(WOLFSSL_CTX* ctx,
                                                CallbackGenExtMasterSecret cb);
WOLFSSL_API void  wolfSSL_SetGenExtMasterSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetGenExtMasterSecretCtx(WOLFSSL* ssl);

typedef int (*CallbackGenPreMaster)(WOLFSSL* ssl, byte *premaster,
                                                   word32 preSz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetGenPreMasterCb(WOLFSSL_CTX* ctx,
                                                        CallbackGenPreMaster cb);
WOLFSSL_API void  wolfSSL_SetGenPreMasterCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetGenPreMasterCtx(WOLFSSL* ssl);

typedef int (*CallbackGenSessionKey)(WOLFSSL* ssl, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetGenSessionKeyCb(WOLFSSL_CTX* ctx,
                                                        CallbackGenSessionKey cb);
WOLFSSL_API void  wolfSSL_SetGenSessionKeyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetGenSessionKeyCtx(WOLFSSL* ssl);

typedef int (*CallbackEncryptKeys)(WOLFSSL* ssl, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEncryptKeysCb(WOLFSSL_CTX* ctx,
                                                        CallbackEncryptKeys cb);
WOLFSSL_API void  wolfSSL_SetEncryptKeysCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEncryptKeysCtx(WOLFSSL* ssl);

typedef int (*CallbackTlsFinished)(WOLFSSL* ssl,
                            const byte *side,
                            const byte *handshake_hash, word32 hashSz,
                            byte *hashes, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetTlsFinishedCb(WOLFSSL_CTX* ctx, CallbackTlsFinished cb);
WOLFSSL_API void  wolfSSL_SetTlsFinishedCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetTlsFinishedCtx(WOLFSSL* ssl);

#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
typedef int (*CallbackVerifyMac)(WOLFSSL *ssl, const byte* message,
                    word32 messageSz, word32 macSz, word32 content, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetVerifyMacCb(WOLFSSL_CTX* ctx, CallbackVerifyMac cb);
WOLFSSL_API void  wolfSSL_SetVerifyMacCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetVerifyMacCtx(WOLFSSL* ssl);
#endif

typedef int (*CallbackHKDFExpandLabel)(byte* okm, word32 okmLen,
       const byte* prk, word32 prkLen,
       const byte* protocol, word32 protocolLen,
       const byte* label, word32 labelLen,
       const byte* info, word32 infoLen,
       int digest, int side);
WOLFSSL_API void wolfSSL_CTX_SetHKDFExpandLabelCb(WOLFSSL_CTX* ctx,
       CallbackHKDFExpandLabel cb);

typedef int (*CallbackProcessServerSigKex)(WOLFSSL* ssl, byte p_sig_algo,
       const byte* p_sig, word32 p_sig_len,
       const byte* p_rand, word32 p_rand_len,
       const byte* p_server_params, word32 p_server_params_len);
WOLFSSL_API void wolfSSL_CTX_SetProcessServerSigKexCb(WOLFSSL_CTX* ctx,
       CallbackProcessServerSigKex cb);

typedef int (*CallbackPerformTlsRecordProcessing)(WOLFSSL* ssl, int is_encrypt,
       byte* out, const byte* in, word32 sz,
       const byte* iv, word32 ivSz,
       byte* authTag, word32 authTagSz,
       const byte* authIn, word32 authInSz);
WOLFSSL_API void wolfSSL_CTX_SetPerformTlsRecordProcessingCb(WOLFSSL_CTX* ctx,
       CallbackPerformTlsRecordProcessing cb);

#endif /* HAVE_PK_CALLBACKS */

#ifndef NO_CERTS
    WOLFSSL_API void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb);

    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CTX_GetCertManager(WOLFSSL_CTX* ctx);

    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);
    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);
    WOLFSSL_API void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManager_up_ref(WOLFSSL_CERT_MANAGER* cm);

#ifdef WC_ASN_UNKNOWN_EXT_CB
    WOLFSSL_API void wolfSSL_CertManagerSetUnknownExtCallback(
        WOLFSSL_CERT_MANAGER* cm,
        wc_UnknownExtCallback cb);
#endif

    WOLFSSL_API int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER* cm,
        const char* f, const char* d);
    WOLFSSL_API int wolfSSL_CertManagerLoadCABuffer_ex(WOLFSSL_CERT_MANAGER* cm,
        const unsigned char* buff, long sz, int format, int userChain,
        word32 flags);
    WOLFSSL_API int wolfSSL_CertManagerLoadCABuffer(WOLFSSL_CERT_MANAGER* cm,
        const unsigned char* buff, long sz, int format);

    WOLFSSL_API int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerUnloadIntermediateCerts(
        WOLFSSL_CERT_MANAGER* cm);
#ifdef WOLFSSL_TRUST_PEER_CERT
    WOLFSSL_API int wolfSSL_CertManagerUnload_trust_peers(
        WOLFSSL_CERT_MANAGER* cm);
#endif
    WOLFSSL_API int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER* cm,
        const char* f, int format);
    WOLFSSL_API int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
        const unsigned char* buff, long sz, int format);
    WOLFSSL_API int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER* cm,
        const unsigned char* der, int sz);
    WOLFSSL_API int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER* cm,
        int options);
    WOLFSSL_API int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER* cm);
#ifndef NO_WOLFSSL_CM_VERIFY
    WOLFSSL_API void wolfSSL_CertManagerSetVerify(WOLFSSL_CERT_MANAGER* cm,
        VerifyCallback vc);
#endif
    WOLFSSL_API int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER* cm,
        const char* path, int type, int monitor);
    WOLFSSL_API int wolfSSL_CertManagerLoadCRLFile(WOLFSSL_CERT_MANAGER* cm,
        const char* file, int type);
    WOLFSSL_API int wolfSSL_CertManagerLoadCRLBuffer(WOLFSSL_CERT_MANAGER* cm,
        const unsigned char* buff, long sz, int type);
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER* cm,
        CbMissingCRL cb);
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_ErrorCb(WOLFSSL_CERT_MANAGER* cm,
                                                      crlErrorCb cb, void* ctx);
    WOLFSSL_API int wolfSSL_CertManagerFreeCRL(WOLFSSL_CERT_MANAGER* cm);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_IOCb(WOLFSSL_CERT_MANAGER* cm,
        CbCrlIO cb);
#endif
#ifdef HAVE_CRL_UPDATE_CB
    WOLFSSL_API int wolfSSL_CertManagerGetCRLInfo(WOLFSSL_CERT_MANAGER* cm, CrlInfo* info,
        const byte* buff, long sz, int type);
    WOLFSSL_API int wolfSSL_CertManagerSetCRLUpdate_Cb(WOLFSSL_CERT_MANAGER* cm,
        CbUpdateCRL cb);
#endif
#if defined(HAVE_OCSP)
    WOLFSSL_API int wolfSSL_CertManagerCheckOCSPResponse(
        WOLFSSL_CERT_MANAGER* cm, unsigned char *response, int responseSz,
        WOLFSSL_BUFFER_INFO *responseBuffer, CertStatus *status,
        OcspEntry *entry, OcspRequest *ocspRequest);
#endif
    WOLFSSL_API int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER* cm,
        const unsigned char* der, int sz);
    WOLFSSL_API int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER* cm,
        int options);
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerSetOCSPOverrideURL(
        WOLFSSL_CERT_MANAGER* cm, const char* url);
    WOLFSSL_API int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER* cm,
        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx);

    WOLFSSL_API int wolfSSL_CertManagerEnableOCSPStapling(
        WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSPStapling(
        WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerEnableOCSPMustStaple(
        WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSPMustStaple(
        WOLFSSL_CERT_MANAGER* cm);
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SIGNER_DER_CERT) && \
    !defined(NO_FILESYSTEM)
WOLFSSL_API WOLFSSL_STACK* wolfSSL_CertManagerGetCerts(
    WOLFSSL_CERT_MANAGER* cm);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_X509_STORE_get1_certs(
    WOLFSSL_X509_STORE_CTX* ctx, WOLFSSL_X509_NAME* name);
#endif /* OPENSSL_EXTRA && WOLFSSL_SIGNER_DER_CERT && !NO_FILESYSTEM */
    WOLFSSL_API int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);
    WOLFSSL_API int wolfSSL_DisableCRL(WOLFSSL* ssl);
    WOLFSSL_API int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor);
    WOLFSSL_API int wolfSSL_LoadCRLFile(WOLFSSL* ssl, const char* file, int type);
    WOLFSSL_API int wolfSSL_LoadCRLBuffer(WOLFSSL* ssl,
                                          const unsigned char* buff, long sz, int type);
    WOLFSSL_API int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb);
    WOLFSSL_API int wolfSSL_SetCRL_ErrorCb(WOLFSSL* ssl, crlErrorCb cb,
                                           void* ctx);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb);
#endif
    WOLFSSL_API int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options);
    WOLFSSL_API int wolfSSL_DisableOCSP(WOLFSSL* ssl);
    WOLFSSL_API int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url);
    WOLFSSL_API int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx);
    WOLFSSL_API int wolfSSL_EnableOCSPStapling(WOLFSSL* ssl);
    WOLFSSL_API int wolfSSL_DisableOCSPStapling(WOLFSSL* ssl);

    WOLFSSL_API int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);
    WOLFSSL_API int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path, int type, int monitor);
    WOLFSSL_API int wolfSSL_CTX_LoadCRLFile(WOLFSSL_CTX* ctx, const char* path, int type);
    WOLFSSL_API int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX* ctx,
                                            const unsigned char* buff, long sz, int type);
    WOLFSSL_API int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb);
    WOLFSSL_API int wolfSSL_CTX_SetCRL_ErrorCb(WOLFSSL_CTX* ctx, crlErrorCb cb,
                                               void* cbCtx);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX* ctx, CbCrlIO cb);
#endif

    WOLFSSL_API int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options);
    WOLFSSL_API int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url);
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx,
                                               CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx);
    WOLFSSL_API int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX* ctx);
#endif /* !NO_CERTS */


#ifdef SINGLE_THREADED
    WOLFSSL_API int wolfSSL_CTX_new_rng(WOLFSSL_CTX* ctx);
#endif

/* end of handshake frees temporary arrays, if user needs for get_keys or
   psk hints, call KeepArrays before handshake and then FreeArrays when done
   if don't want to wait for object free */
WOLFSSL_API void wolfSSL_KeepArrays(WOLFSSL* ssl);
WOLFSSL_API void wolfSSL_FreeArrays(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_KeepHandshakeResources(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_FreeHandshakeResources(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_CTX_UseClientSuites(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_UseClientSuites(WOLFSSL* ssl);

/* async additions */
#define wolfSSL_UseAsync wolfSSL_SetDevId
#define wolfSSL_CTX_UseAsync wolfSSL_CTX_SetDevId
WOLFSSL_ABI WOLFSSL_API int wolfSSL_SetDevId(WOLFSSL* ssl, int devId);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_SetDevId(WOLFSSL_CTX* ctx, int devId);

/* helpers to get device id and heap */
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_GetDevId(WOLFSSL_CTX* ctx, WOLFSSL* ssl);
WOLFSSL_API void* wolfSSL_CTX_GetHeap(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/* TLS Extensions */

/* Server Name Indication */
#ifdef HAVE_SNI

/* SNI types */
enum {
    WOLFSSL_SNI_HOST_NAME = 0
};

WOLFSSL_ABI WOLFSSL_API int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type,
                                                   const void* data, unsigned short size);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
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
    WOLFSSL_SNI_ABORT_ON_ABSENCE     = 0x04
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

#endif /* HAVE_SNI */

/* Trusted CA Key Indication - RFC 6066 (Section 6) */
#ifdef HAVE_TRUSTED_CA

/* TCA Identifier Type */
enum {
    WOLFSSL_TRUSTED_CA_PRE_AGREED = 0,
    WOLFSSL_TRUSTED_CA_KEY_SHA1 = 1,
    WOLFSSL_TRUSTED_CA_X509_NAME = 2,
    WOLFSSL_TRUSTED_CA_CERT_SHA1 = 3
};

WOLFSSL_API int wolfSSL_UseTrustedCA(WOLFSSL* ssl, unsigned char type,
            const unsigned char* certId, unsigned int certIdSz);
#endif /* HAVE_TRUSTED_CA */

/* Application-Layer Protocol Negotiation */
#ifdef HAVE_ALPN

/* ALPN status code */
enum {
    WOLFSSL_ALPN_NO_MATCH = 0,
    WOLFSSL_ALPN_MATCH    = 1,
    WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 2,
    WOLFSSL_ALPN_FAILED_ON_MISMATCH = 4
};

enum {
    WOLFSSL_MAX_ALPN_PROTO_NAME_LEN = 255,
    WOLFSSL_MAX_ALPN_NUMBER = 257
};

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_QUIC)
typedef int (*CallbackALPNSelect)(WOLFSSL* ssl, const unsigned char** out,
    unsigned char* outLen, const unsigned char* in, unsigned int inLen,
    void *arg);
#endif

WOLFSSL_ABI WOLFSSL_API int wolfSSL_UseALPN(WOLFSSL* ssl,
                                char *protocol_name_list,
                                unsigned int protocol_name_listSz,
                                unsigned char options);

WOLFSSL_API int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name,
                                         unsigned short *size);

WOLFSSL_API int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list,
                                             unsigned short *listSz);
WOLFSSL_API int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char **list);
#endif /* HAVE_ALPN */

/* Maximum Fragment Length */
#ifdef HAVE_MAX_FRAGMENT

/* Fragment lengths */
enum {
    WOLFSSL_MFL_DISABLED = 0,
    WOLFSSL_MFL_2_9  = 1, /*  512 bytes */
    WOLFSSL_MFL_2_10 = 2, /* 1024 bytes */
    WOLFSSL_MFL_2_11 = 3, /* 2048 bytes */
    WOLFSSL_MFL_2_12 = 4, /* 4096 bytes */
    WOLFSSL_MFL_2_13 = 5, /* 8192 bytes *//* wolfSSL ONLY!!! */
    WOLFSSL_MFL_2_8  = 6, /*  256 bytes *//* wolfSSL ONLY!!! */
    WOLFSSL_MFL_MIN  = WOLFSSL_MFL_2_9,
    WOLFSSL_MFL_MAX  = WOLFSSL_MFL_2_8
};

#ifndef NO_WOLFSSL_CLIENT

WOLFSSL_API int wolfSSL_UseMaxFragment(WOLFSSL* ssl, unsigned char mfl);
WOLFSSL_API int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, unsigned char mfl);

#endif
#endif /* HAVE_MAX_FRAGMENT */

/* Truncated HMAC */
#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_WOLFSSL_CLIENT

WOLFSSL_API int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl);
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

WOLFSSL_API int wolfSSL_UseOCSPStapling(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

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

WOLFSSL_API int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

WOLFSSL_API int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

#endif
#endif

/* Named Groups */
enum {
    WOLFSSL_NAMED_GROUP_INVALID = 0,
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
    WOLFSSL_ECC_X448      = 30,
    WOLFSSL_ECC_SM2P256V1 = 41,
    WOLFSSL_ECC_MAX       = 41,
    WOLFSSL_ECC_MAX_AVAIL = 46,
    /* Update use of disabled curves when adding value greater than 46. */

    WOLFSSL_FFDHE_START   = 256,
    WOLFSSL_FFDHE_2048    = 256,
    WOLFSSL_FFDHE_3072    = 257,
    WOLFSSL_FFDHE_4096    = 258,
    WOLFSSL_FFDHE_6144    = 259,
    WOLFSSL_FFDHE_8192    = 260,

#ifdef HAVE_PQC
    /* These group numbers were taken from OQS's openssl provider, see:
     * https://github.com/open-quantum-safe/oqs-provider/blob/main/oqs-template/
     * oqs-kem-info.md.
     *
     * The levels in the group name refer to the claimed NIST level of each
     * parameter set. The associated parameter set name is listed as a comment
     * beside the group number. Please see the NIST PQC Competition's submitted
     * papers for more details.
     *
     * LEVEL1 means that an attack on that parameter set would require the same
     * or more resources as a key search on AES 128. LEVEL3 would require the
     * same or more resources as a key search on AES 192. LEVEL5 would require
     * the same or more resources as a key search on AES 256. None of the
     * algorithms have LEVEL2 and LEVEL4 because none of these submissions
     * included them. */

#ifdef WOLFSSL_KYBER_ORIGINAL
    WOLFSSL_PQC_MIN               = 570,
    WOLFSSL_PQC_SIMPLE_MIN        = 570,
    WOLFSSL_KYBER_LEVEL1          = 570, /* KYBER_512 */
    WOLFSSL_KYBER_LEVEL3          = 572, /* KYBER_768 */
    WOLFSSL_KYBER_LEVEL5          = 573, /* KYBER_1024 */
#ifdef WOLFSSL_NO_ML_KEM
    WOLFSSL_PQC_SIMPLE_MAX        = 573,
#endif

    WOLFSSL_PQC_HYBRID_MIN        = 12090,
    WOLFSSL_P256_KYBER_LEVEL1     = 12090,
    WOLFSSL_P384_KYBER_LEVEL3     = 12092,
    WOLFSSL_P521_KYBER_LEVEL5     = 12093,
#ifdef WOLFSSL_NO_ML_KEM
    WOLFSSL_PQC_HYBRID_MAX        = 12093,
    WOLFSSL_PQC_MAX               = 12093,
#endif
#endif
#ifndef WOLFSSL_NO_ML_KEM
#ifndef WOLFSSL_KYBER_ORIGINAL
    WOLFSSL_PQC_MIN               = 583,
    WOLFSSL_PQC_SIMPLE_MIN        = 583,
#endif
    WOLFSSL_ML_KEM_512            = 583, /* ML-KEM 512 */
    WOLFSSL_ML_KEM_768            = 584, /* ML-KEM 768 */
    WOLFSSL_ML_KEM_1024           = 585, /* ML-KEM 1024 */
    WOLFSSL_PQC_SIMPLE_MAX        = 585,

#ifndef WOLFSSL_KYBER_ORIGINAL
    WOLFSSL_PQC_HYBRID_MIN        = 12103,
#endif
    WOLFSSL_P256_ML_KEM_512       = 12103,
    WOLFSSL_P384_ML_KEM_768       = 12104,
    WOLFSSL_P521_ML_KEM_1024      = 12105,
    WOLFSSL_PQC_HYBRID_MAX        = 12105,
    WOLFSSL_PQC_MAX               = 12105,
#endif /* !WOLFSSL_NO_ML_KEM */
#endif /* HAVE_PQC */
    WOLF_ENUM_DUMMY_LAST_ELEMENT(SSL_H)
};

enum {
    WOLFSSL_EC_PF_UNCOMPRESSED = 0,
#if 0 /* Not Supported */
    WOLFSSL_EC_PF_X962_COMP_PRIME = 1,
    WOLFSSL_EC_PF_X962_COMP_CHAR2 = 2,
#endif
    WOLF_ENUM_DUMMY_LAST_ELEMENT(SSL_H)
};

#ifdef HAVE_SUPPORTED_CURVES
WOLFSSL_API int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name);
WOLFSSL_API int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           word16 name);
#endif

#ifdef WOLFSSL_TLS13
WOLFSSL_API int wolfSSL_UseKeyShare(WOLFSSL* ssl, word16 group);
WOLFSSL_API int wolfSSL_NoKeyShares(WOLFSSL* ssl);
#endif

#ifdef WOLFSSL_DUAL_ALG_CERTS
#define WOLFSSL_CKS_SIGSPEC_NATIVE      0x0001
#define WOLFSSL_CKS_SIGSPEC_ALTERNATIVE 0x0002
#define WOLFSSL_CKS_SIGSPEC_BOTH        0x0003
#define WOLFSSL_CKS_SIGSPEC_EXTERNAL    0x0004

WOLFSSL_API int wolfSSL_UseCKS(WOLFSSL* ssl, byte *sigSpec, word16 sigSpecSz);
WOLFSSL_API int wolfSSL_CTX_UseCKS(WOLFSSL_CTX* ctx, byte *sigSpec,
                                   word16 sigSpecSz);
#endif /* WOLFSSL_DUAL_ALG_CERTS */

/* Secure Renegotiation */
#if defined(HAVE_SECURE_RENEGOTIATION) || defined(HAVE_SERVER_RENEGOTIATION_INFO)

WOLFSSL_API int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx);
#ifdef HAVE_SECURE_RENEGOTIATION
WOLFSSL_API int wolfSSL_Rehandshake(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SecureResume(WOLFSSL* ssl);
#endif
WOLFSSL_API long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl);

#endif

#if defined(HAVE_SELFTEST) && \
    (!defined(HAVE_SELFTEST_VERSION) || (HAVE_SELFTEST_VERSION < 2))

    /* Needed by session ticket stuff below */
    #ifndef WOLFSSL_AES_KEY_SIZE_ENUM
    #define WOLFSSL_AES_KEY_SIZE_ENUM
    enum SSL_Misc {
        AES_IV_SIZE         = 16,
        AES_128_KEY_SIZE    = 16,
        AES_192_KEY_SIZE    = 24,
        AES_256_KEY_SIZE    = 32
    };
    #endif
#endif

/* Session Ticket */
#ifdef HAVE_SESSION_TICKET

#if !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && !defined(NO_WOLFSSL_SERVER)
    #ifdef WOLFSSL_TICKET_ENC_CBC_HMAC
        #if defined(WOLFSSL_TICKET_ENC_HMAC_SHA512)
            #define WOLFSSL_TICKET_ENC_HMAC     WC_HASH_TYPE_SHA512
            #define WOLFSSL_TICKET_HMAC_KEY_SZ  64
        #elif defined(WOLFSSL_TICKET_ENC_HMAC_SHA384)
            #define WOLFSSL_TICKET_ENC_HMAC     WC_HASH_TYPE_SHA384
            #define WOLFSSL_TICKET_HMAC_KEY_SZ  48
        #else
            #define WOLFSSL_TICKET_ENC_HMAC     WC_HASH_TYPE_SHA256
            #define WOLFSSL_TICKET_HMAC_KEY_SZ  32
        #endif
        #ifdef WOLFSSL_TICKET_ENC_AES256_CBC
            #define WOLFSSL_TICKET_KEY_SZ   \
                (AES_256_KEY_SIZE + WOLFSSL_TICKET_HMAC_KEY_SZ)
        #else
            #define WOLFSSL_TICKET_KEY_SZ   \
                (AES_128_KEY_SIZE + WOLFSSL_TICKET_HMAC_KEY_SZ)
        #endif
    #elif defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
        !defined(WOLFSSL_TICKET_ENC_AES128_GCM) && \
        !defined(WOLFSSL_TICKET_ENC_AES256_GCM)
        #define WOLFSSL_TICKET_KEY_SZ       CHACHA20_POLY1305_AEAD_KEYSIZE
    #elif defined(WOLFSSL_TICKET_ENC_AES256_GCM)
        #define WOLFSSL_TICKET_KEY_SZ       AES_256_KEY_SIZE
    #else
        #define WOLFSSL_TICKET_KEY_SZ       AES_128_KEY_SIZE
    #endif

    #define WOLFSSL_TICKET_KEYS_SZ     (WOLFSSL_TICKET_NAME_SZ +    \
                                        2 * WOLFSSL_TICKET_KEY_SZ + \
                                        sizeof(word32) * 2)
#endif

#ifndef NO_WOLFSSL_CLIENT
WOLFSSL_API int wolfSSL_UseSessionTicket(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_get_SessionTicket(WOLFSSL* ssl, unsigned char* buf, word32* bufSz);
WOLFSSL_API int wolfSSL_set_SessionTicket(WOLFSSL* ssl, const unsigned char* buf, word32 bufSz);
typedef int (*CallbackSessionTicket)(WOLFSSL* ssl, const unsigned char*, int, void*);
WOLFSSL_API int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                                  CallbackSessionTicket cb, void* ctx);
#endif /* NO_WOLFSSL_CLIENT */
#ifndef NO_WOLFSSL_SERVER
WOLFSSL_API int wolfSSL_send_SessionTicket(WOLFSSL* ssl);
#endif /* !NO_WOLFSSL_SERVER */


#define WOLFSSL_TICKET_NAME_SZ 16
#define WOLFSSL_TICKET_IV_SZ   16
#ifndef WOLFSSL_TICKET_ENC_CBC_HMAC
    #define WOLFSSL_TICKET_MAC_SZ  32
#else
    #define WOLFSSL_TICKET_MAC_SZ  WOLFSSL_TICKET_HMAC_KEY_SZ
#endif

enum TicketEncRet {
    WOLFSSL_TICKET_RET_FATAL  = -1,  /* fatal error, don't use ticket */
    WOLFSSL_TICKET_RET_OK     =  0,  /* ok, use ticket */
    WOLFSSL_TICKET_RET_REJECT,       /* don't use ticket, but not fatal */
    WOLFSSL_TICKET_RET_CREATE        /* existing ticket ok and create new one */
};

#ifndef NO_WOLFSSL_SERVER

WOLFSSL_API int wolfSSL_CTX_NoTicketTLSv12(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_NoTicketTLSv12(WOLFSSL* ssl);

typedef int (*SessionTicketEncCb)(WOLFSSL* ssl,
                                 unsigned char key_name[WOLFSSL_TICKET_NAME_SZ],
                                 unsigned char iv[WOLFSSL_TICKET_IV_SZ],
                                 unsigned char mac[WOLFSSL_TICKET_MAC_SZ],
                                 int enc, unsigned char*, int, int*, void*);
WOLFSSL_API int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb cb);
WOLFSSL_API int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int hint);
WOLFSSL_API int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void* userCtx);
WOLFSSL_API void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx);
WOLFSSL_API size_t wolfSSL_CTX_get_num_tickets(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_CTX_set_num_tickets(WOLFSSL_CTX* ctx, size_t mxTickets);

#endif /* NO_WOLFSSL_SERVER */

#endif /* HAVE_SESSION_TICKET */

/* TLS Extended Master Secret Extension */
WOLFSSL_API int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx);


#define WOLFSSL_CRL_MONITOR   0x01   /* monitor this dir flag */
#define WOLFSSL_CRL_START_MON 0x02   /* start monitoring flag */


#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
WOLFSSL_API int wolfDTLS_accept_stateless(WOLFSSL* ssl);
/* notify user we parsed a verified ClientHello is done. This only has an effect
 * on the server end. */
typedef int (*ClientHelloGoodCb)(WOLFSSL* ssl, void*);
WOLFSSL_API int wolfDTLS_SetChGoodCb(WOLFSSL* ssl, ClientHelloGoodCb cb, void* user_ctx);
#endif

/* notify user the handshake is done */
typedef int (*HandShakeDoneCb)(WOLFSSL* ssl, void*);
WOLFSSL_API int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx);


WOLFSSL_API int wolfSSL_PrintSessionStats(void);
WOLFSSL_API int wolfSSL_get_session_stats(unsigned int* active,
                                          unsigned int* total,
                                          unsigned int* peak,
                                          unsigned int* maxSessions);
/* External facing KDF */
WOLFSSL_API
int wolfSSL_MakeTlsMasterSecret(unsigned char* ms, word32 msLen,
                               const unsigned char* pms, word32 pmsLen,
                               const unsigned char* cr, const unsigned char* sr,
                               int tls1_2, int hash_type);

WOLFSSL_API
int wolfSSL_MakeTlsExtendedMasterSecret(unsigned char* ms, word32 msLen,
                              const unsigned char* pms, word32 pmsLen,
                              const unsigned char* sHash, word32 sHashLen,
                              int tls1_2, int hash_type);

WOLFSSL_API
int wolfSSL_DeriveTlsKeys(unsigned char* key_data, word32 keyLen,
                               const unsigned char* ms, word32 msLen,
                               const unsigned char* sr, const unsigned char* cr,
                               int tls1_2, int hash_type);

#ifdef WOLFSSL_CALLBACKS

typedef int (*HandShakeCallBack)(HandShakeInfo*);
typedef int (*TimeoutCallBack)(TimeoutInfo*);

/* wolfSSL connect extension allowing HandShakeCallBack and/or TimeoutCallBack
   for diagnostics */
WOLFSSL_API int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                                 TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);
WOLFSSL_API int wolfSSL_accept_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                                 TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

#endif /* WOLFSSL_CALLBACKS */


#ifdef WOLFSSL_HAVE_WOLFSCEP
    WOLFSSL_API void wolfSSL_wolfSCEP(void);
#endif /* WOLFSSL_HAVE_WOLFSCEP */

#ifdef WOLFSSL_HAVE_CERT_SERVICE
    WOLFSSL_API void wolfSSL_cert_service(void);
#endif

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Smaller subset of X509 compatibility functions. Avoid increasing the size of
 * this subset and its memory usage */

#include <wolfssl/openssl/asn1.h>
struct WOLFSSL_X509_NAME_ENTRY {
    WOLFSSL_ASN1_OBJECT* object;  /* static object just for keeping grp, type */
    WOLFSSL_ASN1_STRING* value;  /* points to data, for lighttpd port */
    int nid; /* i.e. ASN_COMMON_NAME */
    int set;
    int size;
};

WOLFSSL_API int wolfSSL_X509_NAME_get_index_by_OBJ(WOLFSSL_X509_NAME *name,
                                                   const WOLFSSL_ASN1_OBJECT *obj,
                                                   int idx);



enum {
    WOLFSSL_SYS_ACCEPT = 0,
    WOLFSSL_SYS_BIND,
    WOLFSSL_SYS_CONNECT,
    WOLFSSL_SYS_FOPEN,
    WOLFSSL_SYS_FREAD,
    WOLFSSL_SYS_GETADDRINFO,
    WOLFSSL_SYS_GETSOCKOPT,
    WOLFSSL_SYS_GETSOCKNAME,
    WOLFSSL_SYS_GETHOSTBYNAME,
    WOLFSSL_SYS_GETNAMEINFO,
    WOLFSSL_SYS_GETSERVBYNAME,
    WOLFSSL_SYS_IOCTLSOCKET,
    WOLFSSL_SYS_LISTEN,
    WOLFSSL_SYS_OPENDIR,
    WOLFSSL_SYS_SETSOCKOPT,
    WOLFSSL_SYS_SOCKET
};

/* Object functions */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Do not use - use wolfSSL_OBJ_sn2nid instead. */
WOLFSSL_LOCAL int wc_OBJ_sn2nid(const char *sn);
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

WOLFSSL_API const char* wolfSSL_OBJ_nid2sn(int n);
WOLFSSL_API int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o);
WOLFSSL_API int wolfSSL_OBJ_get_type(const WOLFSSL_ASN1_OBJECT *o);
WOLFSSL_API int wolfSSL_OBJ_sn2nid(const char *sn);
WOLFSSL_API size_t wolfSSL_OBJ_length(const WOLFSSL_ASN1_OBJECT* o);
WOLFSSL_API const unsigned char* wolfSSL_OBJ_get0_data(
    const WOLFSSL_ASN1_OBJECT* o);

WOLFSSL_API const char* wolfSSL_OBJ_nid2ln(int n);
WOLFSSL_API int wolfSSL_OBJ_ln2nid(const char *ln);
WOLFSSL_API int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a,
            const WOLFSSL_ASN1_OBJECT* b);
WOLFSSL_API int wolfSSL_OBJ_txt2nid(const char *sn);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name);

WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj(int n);
WOLFSSL_LOCAL WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj_ex(int n, WOLFSSL_ASN1_OBJECT *arg_obj);
WOLFSSL_API int wolfSSL_OBJ_obj2txt(char *buf, int buf_len,
            const WOLFSSL_ASN1_OBJECT *a, int no_name);

WOLFSSL_API void wolfSSL_OBJ_cleanup(void);
WOLFSSL_API int wolfSSL_OBJ_create(const char *oid, const char *sn, const char *ln);
#ifdef HAVE_ECC
WOLFSSL_LOCAL int NIDToEccEnum(int n);
#endif

#define WOLFSSL_OBJ_NAME_TYPE_UNDEF         0x00
#define WOLFSSL_OBJ_NAME_TYPE_MD_METH       0x01
#define WOLFSSL_OBJ_NAME_TYPE_CIPHER_METH   0x02
#define WOLFSSL_OBJ_NAME_TYPE_PKEY_METH     0x03
#define WOLFSSL_OBJ_NAME_TYPE_COMP_METH     0x04
#define WOLFSSL_OBJ_NAME_TYPE_NUM           0x05
#define WOLFSSL_OBJ_NAME_ALIAS              0x8000

WOLFSSL_API void wolfSSL_OBJ_NAME_do_all(int type,
                           void (*fn) (const WOLFSSL_OBJ_NAME* , void *arg),
                           void* arg);
/* end of object functions */

WOLFSSL_API unsigned long wolfSSL_ERR_peek_last_error_line(const char **file, int *line);
WOLFSSL_API long wolfSSL_CTX_ctrl(WOLFSSL_CTX* ctx, int cmd, long opt,void* pt);
WOLFSSL_API long wolfSSL_CTX_callback_ctrl(WOLFSSL_CTX* ctx, int cmd, void (*fp)(void));
WOLFSSL_API long wolfSSL_CTX_clear_extra_chain_certs(WOLFSSL_CTX* ctx);

WOLFSSL_API void wolfSSL_certs_clear(WOLFSSL* ssl);

#ifndef NO_CERTS
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_ENTRY_create_by_NID(
            WOLFSSL_X509_NAME_ENTRY** out, int nid, int type,
            const unsigned char* data, int dataSz);
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_ENTRY_create_by_txt(
            WOLFSSL_X509_NAME_ENTRY **neIn, const char *txt, int format,
            const unsigned char *data, int dataSz);
WOLFSSL_API int wolfSSL_X509_NAME_add_entry(WOLFSSL_X509_NAME* name,
                              WOLFSSL_X509_NAME_ENTRY* entry, int idx, int set);
WOLFSSL_API int wolfSSL_X509_NAME_add_entry_by_txt(WOLFSSL_X509_NAME *name,
    const char *field, int type, const unsigned char *bytes, int len, int loc,
    int set);
#ifndef wolfSSL_X509_NAME_add_entry_by_NID
WOLFSSL_API int wolfSSL_X509_NAME_add_entry_by_NID(WOLFSSL_X509_NAME *name, int nid,
                                           int type, const unsigned char *bytes,
                                           int len, int loc, int set);
#endif
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY *wolfSSL_X509_NAME_delete_entry(
        WOLFSSL_X509_NAME *name, int loc);
WOLFSSL_API int wolfSSL_X509_NAME_cmp(const WOLFSSL_X509_NAME* x,
            const WOLFSSL_X509_NAME* y);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_NAME_new(void);
#ifndef wolfSSL_X509_NAME_new_ex
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_NAME_new_ex(void *heap);
#endif
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_NAME_dup(WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_X509_NAME_copy(WOLFSSL_X509_NAME* from, WOLFSSL_X509_NAME* to);
WOLFSSL_API int wolfSSL_check_private_key(const WOLFSSL* ssl);
#endif /* !NO_CERTS */
#endif /* OPENSSL_ALL || OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)
WOLFSSL_API long wolfSSL_ctrl(WOLFSSL* ssl, int cmd, long opt, void* pt);
#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509,
                                                     int nid, int* c, int* idx);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
#ifndef NO_CERTS
WOLFSSL_API unsigned int wolfSSL_X509_get_extension_flags(WOLFSSL_X509* x509);
WOLFSSL_API unsigned int wolfSSL_X509_get_key_usage(WOLFSSL_X509* x509);
WOLFSSL_API unsigned int wolfSSL_X509_get_extended_key_usage(WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_get_ext_count(const WOLFSSL_X509* passedCert);
WOLFSSL_API int wolfSSL_X509_get_ext_by_NID(const WOLFSSL_X509 *x, int nid, int lastpos);
WOLFSSL_API int wolfSSL_X509_add_ext(WOLFSSL_X509 *x, WOLFSSL_X509_EXTENSION *ex, int loc);
WOLFSSL_API WOLFSSL_X509_EXTENSION *wolfSSL_X509V3_EXT_i2d(int nid, int crit,
                                                           void *data);
WOLFSSL_API WOLFSSL_X509_EXTENSION *wolfSSL_X509_delete_ext(WOLFSSL_X509 *x509, int loc);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509V3_EXT_conf_nid(
        WOLF_LHASH_OF(CONF_VALUE)* conf, WOLFSSL_X509V3_CTX* ctx, int nid,
        char* value);
WOLFSSL_API void wolfSSL_X509V3_set_ctx(WOLFSSL_X509V3_CTX* ctx,
        WOLFSSL_X509* issuer, WOLFSSL_X509* subject, WOLFSSL_X509* req,
        WOLFSSL_X509_CRL* crl, int flag);
WOLFSSL_API void wolfSSL_X509V3_set_ctx_nodb(WOLFSSL_X509V3_CTX* ctx);
WOLFSSL_API int wolfSSL_X509_digest(const WOLFSSL_X509* x509,
        const WOLFSSL_EVP_MD* digest, unsigned char* buf, unsigned int* len);
WOLFSSL_API int wolfSSL_X509_pubkey_digest(const WOLFSSL_X509 *x509,
        const WOLFSSL_EVP_MD *digest, unsigned char* buf, unsigned int* len);
WOLFSSL_API int wolfSSL_use_certificate(WOLFSSL* ssl, WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_use_PrivateKey(WOLFSSL* ssl, WOLFSSL_EVP_PKEY* pkey);
WOLFSSL_API int wolfSSL_use_PrivateKey_ASN1(int pri, WOLFSSL* ssl,
                                            const unsigned char* der, long derSz);
WOLFSSL_API WOLFSSL_EVP_PKEY *wolfSSL_get_privatekey(const WOLFSSL *ssl);
#ifndef NO_RSA
WOLFSSL_API int wolfSSL_use_RSAPrivateKey_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                long derSz);
#endif
WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_ASN1(int pri, WOLFSSL_CTX* ctx,
                                            unsigned char* der, long derSz);

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
WOLFSSL_API int wolfSSL_X509_cmp(const WOLFSSL_X509* a, const WOLFSSL_X509* b);
WOLFSSL_API const WOLFSSL_STACK *wolfSSL_X509_get0_extensions(const WOLFSSL_X509 *x);
WOLFSSL_API const WOLFSSL_STACK *wolfSSL_X509_REQ_get_extensions(const WOLFSSL_X509 *x);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_get_ext(const WOLFSSL_X509* x, int loc);
WOLFSSL_API int wolfSSL_X509_get_ext_by_OBJ(const WOLFSSL_X509 *x,
        const WOLFSSL_ASN1_OBJECT *obj, int lastpos);
WOLFSSL_API int wolfSSL_X509_OBJECT_set1_X509(WOLFSSL_X509_OBJECT *a,
        WOLFSSL_X509 *obj);
WOLFSSL_API int wolfSSL_X509_OBJECT_set1_X509_CRL(WOLFSSL_X509_OBJECT *a,
        WOLFSSL_X509_CRL *obj);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_set_ext(WOLFSSL_X509* x, int loc);
WOLFSSL_API int wolfSSL_X509_EXTENSION_get_critical(const WOLFSSL_X509_EXTENSION* ex);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_new(void);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_create_by_OBJ(
        WOLFSSL_X509_EXTENSION* ex, WOLFSSL_ASN1_OBJECT *obj, int crit,
        WOLFSSL_ASN1_STRING *data);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_dup(
        WOLFSSL_X509_EXTENSION* src);
WOLFSSL_API int wolfSSL_sk_X509_EXTENSION_push(WOLFSSL_STACK* sk,
                                       WOLFSSL_X509_EXTENSION* ext);
WOLFSSL_API void wolfSSL_X509_EXTENSION_free(WOLFSSL_X509_EXTENSION* ext_to_free);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_new_x509_ext(void);
#endif

WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_X509_EXTENSION_get_object(WOLFSSL_X509_EXTENSION* ext);
WOLFSSL_API int wolfSSL_X509_EXTENSION_set_object(WOLFSSL_X509_EXTENSION* ext,
        const WOLFSSL_ASN1_OBJECT* obj);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_X509_EXTENSION_get_data(WOLFSSL_X509_EXTENSION* ext);
WOLFSSL_API int wolfSSL_X509_EXTENSION_set_data(WOLFSSL_X509_EXTENSION* ext,
        WOLFSSL_ASN1_STRING* data);
#endif /* !NO_CERTS */

WOLFSSL_API WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *r);

WOLFSSL_API int wolfSSL_SESSION_get_master_key(const WOLFSSL_SESSION* ses,
        unsigned char* out, int outSz);
WOLFSSL_API int wolfSSL_SESSION_get_master_key_length(const WOLFSSL_SESSION* ses);

WOLFSSL_API int wolfSSL_i2d_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API int wolfSSL_i2d_X509_REQ_bio(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);
#endif
#if !defined(NO_FILESYSTEM)
WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509_fp(XFILE fp,
                                               WOLFSSL_X509** x509);
#endif
WOLFSSL_API WOLFSSL_STACK* wolfSSL_X509_STORE_GetCerts(WOLFSSL_X509_STORE_CTX* s);
WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio,
                                               WOLFSSL_X509** x509);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509_REQ_bio(WOLFSSL_BIO* bio,
                                               WOLFSSL_X509** x509);
#if !defined(NO_FILESYSTEM)
WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509_REQ_fp(XFILE fp, WOLFSSL_X509 **req);
#endif
#endif
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509) *wolfSSL_get0_verified_chain(
        const WOLFSSL *ssl);
WOLFSSL_API void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);
#ifdef OPENSSL_ALL
WOLFSSL_API int wolfSSL_CTX_set1_verify_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);
#endif
WOLFSSL_API int wolfSSL_set0_verify_cert_store(WOLFSSL *ssl,
                                                       WOLFSSL_X509_STORE* str);
WOLFSSL_API int wolfSSL_set1_verify_cert_store(WOLFSSL *ssl,
                                                       WOLFSSL_X509_STORE* str);
WOLFSSL_API WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(const WOLFSSL_CTX* ctx);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(HAVE_SECRET_CALLBACK)
WOLFSSL_API size_t wolfSSL_get_server_random(const WOLFSSL *ssl,
                                             unsigned char *out, size_t outlen);
WOLFSSL_API size_t wolfSSL_get_client_random(const WOLFSSL* ssl,
                                              unsigned char* out, size_t outSz);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || HAVE_SECRET_CALLBACK */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
WOLFSSL_API size_t wolfSSL_BIO_wpending(const WOLFSSL_BIO *bio);
/* non-standard API to determine if BIO supports "pending" */
WOLFSSL_API int wolfSSL_BIO_supports_pending(const WOLFSSL_BIO *bio);
WOLFSSL_API size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *b);

/* Definition for backwards comaptiblity */
#define wolfSSL_get_server_tmp_key          wolfSSL_get_peer_tmp_key
WOLFSSL_API int wolfSSL_get_peer_tmp_key(const WOLFSSL* ssl, WOLFSSL_EVP_PKEY** pkey);

WOLFSSL_API int wolfSSL_CTX_set_min_proto_version(WOLFSSL_CTX* ctx, int version);
WOLFSSL_API int wolfSSL_CTX_set_max_proto_version(WOLFSSL_CTX* ctx, int version);
WOLFSSL_API int wolfSSL_set_min_proto_version(WOLFSSL* ssl, int version);
WOLFSSL_API int wolfSSL_set_max_proto_version(WOLFSSL* ssl, int version);
WOLFSSL_API int wolfSSL_CTX_get_min_proto_version(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_CTX_get_max_proto_version(WOLFSSL_CTX* ctx);

WOLFSSL_API int wolfSSL_CTX_use_PrivateKey(WOLFSSL_CTX *ctx,
    WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509(WOLFSSL_BIO *bp,
    WOLFSSL_X509 **x, wc_pem_password_cb *cb, void *u);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_REQ(WOLFSSL_BIO *bp,
    WOLFSSL_X509 **x, wc_pem_password_cb *cb, void *u);
#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_X509* wolfSSL_PEM_read_X509_REQ(XFILE fp, WOLFSSL_X509** x,
    wc_pem_password_cb* cb, void* u);
#endif
#endif
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_PEM_read_bio_X509_CRL(WOLFSSL_BIO *bp,
        WOLFSSL_X509_CRL **x, wc_pem_password_cb *cb, void *u);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_AUX
        (WOLFSSL_BIO *bp, WOLFSSL_X509 **x, wc_pem_password_cb *cb, void *u);
#ifndef NO_FILESYSTEM
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_INFO)* wolfSSL_PEM_X509_INFO_read(
        XFILE fp, WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk,
        wc_pem_password_cb* cb, void* u);
#endif
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_INFO)* wolfSSL_PEM_X509_INFO_read_bio(
        WOLFSSL_BIO* bio, WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk,
        wc_pem_password_cb* cb, void* u);
#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_PEM_read_X509_CRL(XFILE fp,
        WOLFSSL_X509_CRL **x, wc_pem_password_cb *cb, void *u);
#endif
WOLFSSL_API int wolfSSL_PEM_get_EVP_CIPHER_INFO(const char* header,
                                                EncryptedInfo* cipher);
WOLFSSL_API int wolfSSL_PEM_do_header(EncryptedInfo* cipher,
                                      unsigned char* data, long* len,
                                      wc_pem_password_cb* callback, void* ctx);
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */

/*lighttp compatibility */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(OPENSSL_EXTRA_X509_SMALL)
struct WOLFSSL_ASN1_BIT_STRING {
    int length;
    int type;
    byte* data;
    long flags;
};

struct WOLFSSL_CONF_CTX {
    unsigned int flags;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
};

WOLFSSL_API WOLFSSL_X509_NAME_ENTRY *wolfSSL_X509_NAME_get_entry(WOLFSSL_X509_NAME *name, int loc);
WOLFSSL_API int wolfSSL_X509_NAME_ENTRY_set(const WOLFSSL_X509_NAME_ENTRY *ne);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if    defined(OPENSSL_EXTRA) \
    || defined(OPENSSL_ALL) \
    || defined(HAVE_LIGHTY) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) \
    || defined(HAVE_STUNNEL) \
    || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA_X509_SMALL)
WOLFSSL_API void wolfSSL_X509_NAME_ENTRY_free(WOLFSSL_X509_NAME_ENTRY* ne);
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_ENTRY_new(void);
#ifndef wolfSSL_X509_NAME_free
WOLFSSL_API void wolfSSL_X509_NAME_free(WOLFSSL_X509_NAME* name);
#endif
WOLFSSL_API int wolfSSL_CTX_use_certificate(WOLFSSL_CTX* ctx, WOLFSSL_X509* x);
WOLFSSL_API int wolfSSL_CTX_add0_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_CTX_add1_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_add0_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_add1_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_BIO_read_filename(WOLFSSL_BIO *b, const char *name);
/* These are to be merged shortly */
WOLFSSL_API void wolfSSL_set_verify_depth(WOLFSSL *ssl,int depth);
WOLFSSL_API int wolfSSL_set_app_data(WOLFSSL *ssl, void *arg);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY *ne);
WOLFSSL_API unsigned char *wolfSSL_SHA1(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA224(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA256(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA384(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA512(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API int wolfSSL_X509_check_private_key(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME) *wolfSSL_dup_CA_list( WOLF_STACK_OF(WOLFSSL_X509_NAME) *sk );
WOLFSSL_API int wolfSSL_X509_check_ca(WOLFSSL_X509 *x509);

#ifndef NO_FILESYSTEM
WOLFSSL_API long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c);
WOLFSSL_API long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp);
#endif

#endif /* OPENSSL_EXTRA || OPENSSL_ALL || HAVE_LIGHTY || \
          WOLFSSL_MYSQL_COMPATIBLE || HAVE_STUNNEL || WOLFSSL_NGINX || \
          WOLFSSL_HAPROXY */

#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(OPENSSL_EXTRA)
#ifndef NO_BIO
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_file(const char *filename,
    const char *mode);
#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_fp(XFILE fp, int c);
#endif /* !NO_FILESYSTEM */
#endif /* !NO_BIO */
#endif

#if defined(OPENSSL_ALL) \
    || defined(HAVE_STUNNEL) \
    || defined(HAVE_LIGHTY) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) \
    || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA)
#define X509_BUFFER_SZ 8192

WOLFSSL_API long wolfSSL_CTX_set_tmp_dh(WOLFSSL_CTX* ctx, WOLFSSL_DH* dh);
WOLFSSL_API WOLFSSL_DH *wolfSSL_PEM_read_bio_DHparams(WOLFSSL_BIO *bp,
    WOLFSSL_DH **x, wc_pem_password_cb *cb, void *u);
#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_DH *wolfSSL_PEM_read_DHparams(XFILE fp, WOLFSSL_DH **x,
        wc_pem_password_cb *cb, void *u);
#endif
WOLFSSL_API WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp,
    WOLFSSL_DSA **x, wc_pem_password_cb *cb, void *u);
WOLFSSL_API int wolfSSL_PEM_write_bio_X509_REQ(WOLFSSL_BIO *bp,WOLFSSL_X509 *x);
WOLFSSL_API int wolfSSL_PEM_write_bio_X509_AUX(WOLFSSL_BIO *bp,WOLFSSL_X509 *x);
WOLFSSL_API int wolfSSL_PEM_write_bio_X509(WOLFSSL_BIO *bp, WOLFSSL_X509 *x);
#endif /* HAVE_STUNNEL || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && defined(WOLFSSL_CERT_GEN) && \
                                                       defined(WOLFSSL_CERT_REQ)
WOLFSSL_API int wolfSSL_i2d_X509_REQ(WOLFSSL_X509* req, unsigned char** out);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_REQ_new(void);
WOLFSSL_API void wolfSSL_X509_REQ_free(WOLFSSL_X509* req);
WOLFSSL_API long wolfSSL_X509_REQ_get_version(const WOLFSSL_X509 *req);
WOLFSSL_API int wolfSSL_X509_REQ_set_version(WOLFSSL_X509 *x, long version);
WOLFSSL_API int wolfSSL_X509_REQ_sign(WOLFSSL_X509 *req, WOLFSSL_EVP_PKEY *pkey,
                                      const WOLFSSL_EVP_MD *md);
WOLFSSL_API int wolfSSL_X509_REQ_sign_ctx(WOLFSSL_X509 *req,
                                          WOLFSSL_EVP_MD_CTX* md_ctx);
WOLFSSL_API int wolfSSL_X509_REQ_add_extensions(WOLFSSL_X509* req,
        WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* ext_sk);
WOLFSSL_API int wolfSSL_X509_REQ_set_subject_name(WOLFSSL_X509 *req,
                                                  WOLFSSL_X509_NAME *name);
WOLFSSL_API int wolfSSL_X509_REQ_set_pubkey(WOLFSSL_X509 *req,
                                            WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int wolfSSL_X509_REQ_add1_attr_by_NID(WOLFSSL_X509 *req,
                                                  int nid, int type,
                                                  const unsigned char *bytes,
                                                  int len);
WOLFSSL_API int wolfSSL_X509_REQ_add1_attr_by_txt(WOLFSSL_X509 *req,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_X509_to_X509_REQ(WOLFSSL_X509 *x,
        WOLFSSL_EVP_PKEY *pkey, const WOLFSSL_EVP_MD *md);
#endif

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && defined(WOLFSSL_CERT_GEN) || \
                                                       defined(WOLFSSL_CERT_REQ)
WOLFSSL_API int wolfSSL_X509_REQ_get_attr_count(const WOLFSSL_X509 *req);
WOLFSSL_API WOLFSSL_X509_ATTRIBUTE *wolfSSL_X509_REQ_get_attr(
        const WOLFSSL_X509 *req, int loc);
WOLFSSL_API int wolfSSL_X509_REQ_get_attr_by_NID(const WOLFSSL_X509 *req,
        int nid, int lastpos);
WOLFSSL_API WOLFSSL_X509_ATTRIBUTE* wolfSSL_X509_ATTRIBUTE_new(void);
WOLFSSL_API void wolfSSL_X509_ATTRIBUTE_free(WOLFSSL_X509_ATTRIBUTE* attr);
WOLFSSL_API WOLFSSL_ASN1_TYPE *wolfSSL_X509_ATTRIBUTE_get0_type(
        WOLFSSL_X509_ATTRIBUTE *attr, int idx);
#endif

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

#include <wolfssl/openssl/crypto.h>

WOLFSSL_API int wolfSSL_CRYPTO_set_mem_functions(
        wolfSSL_OSSL_Malloc_cb  m,
        wolfSSL_OSSL_Realloc_cb r,
        wolfSSL_OSSL_Free_cb    f);
WOLFSSL_API int wolfSSL_CRYPTO_set_mem_ex_functions(void *(*m) (size_t, const char *, int),
    void *(*r) (void *, size_t, const char *, int), void (*f) (void *));

WOLFSSL_API int wolfSSL_CRYPTO_memcmp(const void *a, const void *b, size_t size);

WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_768_prime(WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_1024_prime(WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_1536_prime(WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_2048_prime(WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_3072_prime(WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_4096_prime(WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_6144_prime(WOLFSSL_BIGNUM* bn);
WOLFSSL_API WOLFSSL_BIGNUM* wolfSSL_DH_8192_prime(WOLFSSL_BIGNUM* bn);

WOLFSSL_API WOLFSSL_DH *wolfSSL_DH_generate_parameters(int prime_len, int generator,
    void (*callback) (int, int, void *), void *cb_arg);

WOLFSSL_API int wolfSSL_DH_generate_parameters_ex(WOLFSSL_DH* dh, int prime_len, int generator,
                           void (*callback) (int, int, void *));

WOLFSSL_API int wolfSSL_ERR_load_ERR_strings(void);
WOLFSSL_API void wolfSSL_ERR_load_crypto_strings(void);
WOLFSSL_API unsigned long wolfSSL_ERR_peek_last_error(void);

WOLFSSL_API int wolfSSL_FIPS_mode(void);

WOLFSSL_API int wolfSSL_FIPS_mode_set(int r);

WOLFSSL_API int wolfSSL_RAND_set_rand_method(const WOLFSSL_RAND_METHOD *methods);

WOLFSSL_API int wolfSSL_CIPHER_get_bits(const WOLFSSL_CIPHER *c, int *alg_bits);

#define WOLF_SK_COMPARE_CB(type, arg) \
    int (*(arg)) (const type* const* a, const type* const* b)
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_new(
    WOLF_SK_COMPARE_CB(WOLFSSL_X509, cb));
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_new_null(void);
WOLFSSL_API int wolfSSL_sk_X509_num(const WOLF_STACK_OF(WOLFSSL_X509) *s);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_OBJECT_new(void);
WOLFSSL_API void wolfSSL_sk_X509_OBJECT_free(WOLFSSL_STACK* s);
WOLFSSL_API void wolfSSL_sk_X509_OBJECT_pop_free(WOLFSSL_STACK* s,
        void (*f) (WOLFSSL_X509_OBJECT*));
WOLFSSL_API int wolfSSL_sk_X509_OBJECT_push(WOLFSSL_STACK* sk, WOLFSSL_X509_OBJECT* obj);

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_OBJECT)*
        wolfSSL_sk_X509_OBJECT_deep_copy(
            const WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* sk,
            WOLFSSL_X509_OBJECT* (*c)(const WOLFSSL_X509_OBJECT*),
            void (*f)(WOLFSSL_X509_OBJECT*));

WOLFSSL_API WOLFSSL_X509_INFO *wolfSSL_X509_INFO_new(void);
WOLFSSL_API void wolfSSL_X509_INFO_free(WOLFSSL_X509_INFO* info);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_INFO_new_null(void);
WOLFSSL_API int wolfSSL_sk_X509_INFO_num(const WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk);
WOLFSSL_API WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_value(
    const WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk, int i);
WOLFSSL_API int wolfSSL_sk_X509_INFO_push(WOLF_STACK_OF(WOLFSSL_X509_INFO)*,
    WOLFSSL_X509_INFO* in);
WOLFSSL_API WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_pop(WOLF_STACK_OF(WOLFSSL_X509_INFO)*);
WOLFSSL_API void wolfSSL_sk_X509_INFO_pop_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)*,
    void (*f) (WOLFSSL_X509_INFO*));
WOLFSSL_API void wolfSSL_sk_X509_INFO_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)*);

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_sk_X509_NAME_new(
    WOLF_SK_COMPARE_CB(WOLFSSL_X509_NAME, cb));
WOLFSSL_API int wolfSSL_sk_X509_NAME_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_sk_X509_NAME_find(const WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
    WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_sk_X509_NAME_set_cmp_func(
    WOLF_STACK_OF(WOLFSSL_X509_NAME)*, WOLF_SK_COMPARE_CB(WOLFSSL_X509_NAME, cb));
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_value(const WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk, int i);
WOLFSSL_API int wolfSSL_sk_X509_NAME_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API void wolfSSL_sk_X509_NAME_pop_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    void (*f) (WOLFSSL_X509_NAME*));
WOLFSSL_API void wolfSSL_sk_X509_NAME_free(WOLF_STACK_OF(WOLFSSL_X509_NAME) *);

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)*
     wolfSSL_sk_X509_NAME_ENTRY_new(WOLF_SK_COMPARE_CB(WOLFSSL_X509_NAME_ENTRY, cb));
WOLFSSL_API int  wolfSSL_sk_X509_NAME_ENTRY_push(WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk,
                                           WOLFSSL_X509_NAME_ENTRY* name_entry);
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY*
                 wolfSSL_sk_X509_NAME_ENTRY_value(const WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk, int i);
WOLFSSL_API int  wolfSSL_sk_X509_NAME_ENTRY_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk);
WOLFSSL_API void wolfSSL_sk_X509_NAME_ENTRY_free(WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk);


WOLFSSL_API int wolfSSL_sk_X509_OBJECT_num(const WOLF_STACK_OF(WOLFSSL_X509_OBJECT) *s);

WOLFSSL_API int wolfSSL_X509_NAME_print_ex(WOLFSSL_BIO* bio,WOLFSSL_X509_NAME* name,int indent,
        unsigned long flags);
#ifndef NO_FILESYSTEM
WOLFSSL_API int wolfSSL_X509_NAME_print_ex_fp(XFILE fp,WOLFSSL_X509_NAME* name,int indent,
        unsigned long flags);
#endif

WOLFSSL_API WOLFSSL_STACK *wolfSSL_sk_CONF_VALUE_new(WOLF_SK_COMPARE_CB(WOLFSSL_CONF_VALUE, compFunc));
WOLFSSL_API void wolfSSL_sk_CONF_VALUE_free(struct WOLFSSL_STACK *sk);
WOLFSSL_API int wolfSSL_sk_CONF_VALUE_num(const WOLFSSL_STACK *sk);
WOLFSSL_API WOLFSSL_CONF_VALUE *wolfSSL_sk_CONF_VALUE_value(
        const struct WOLFSSL_STACK *sk, int i);
WOLFSSL_API int wolfSSL_sk_CONF_VALUE_push(WOLF_STACK_OF(WOLFSSL_CONF_VALUE)* sk,
        WOLFSSL_CONF_VALUE* val);
#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API WOLFSSL_ASN1_BIT_STRING* wolfSSL_ASN1_BIT_STRING_new(void);
WOLFSSL_API void wolfSSL_ASN1_BIT_STRING_free(WOLFSSL_ASN1_BIT_STRING* str);
WOLFSSL_API WOLFSSL_ASN1_BIT_STRING* wolfSSL_X509_get0_pubkey_bitstr(
                            const WOLFSSL_X509* x);
WOLFSSL_API int wolfSSL_ASN1_BIT_STRING_get_bit(
                            const WOLFSSL_ASN1_BIT_STRING* str, int i);
WOLFSSL_API int wolfSSL_ASN1_BIT_STRING_set_bit(
                            WOLFSSL_ASN1_BIT_STRING* str, int pos, int val);
WOLFSSL_API int wolfSSL_i2d_ASN1_BIT_STRING(const WOLFSSL_ASN1_BIT_STRING* bstr,
        unsigned char** pp);
WOLFSSL_API WOLFSSL_ASN1_BIT_STRING* wolfSSL_d2i_ASN1_BIT_STRING(
        WOLFSSL_ASN1_BIT_STRING** out, const byte** src, long len);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

WOLFSSL_API int  wolfSSL_version(WOLFSSL* ssl);

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

WOLFSSL_API int wolfSSL_get_state(const WOLFSSL* ssl);

WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_value(WOLF_STACK_OF(WOLFSSL_X509)*, int i);

WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_shift(WOLF_STACK_OF(WOLFSSL_X509)*);

WOLFSSL_API void* wolfSSL_sk_X509_OBJECT_value(WOLF_STACK_OF(WOLFSSL_X509_OBJECT)*, int i);
#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || defined(HAVE_EX_DATA)
WOLFSSL_API void* wolfSSL_SESSION_get_ex_data(const WOLFSSL_SESSION* session, int idx);

WOLFSSL_API int   wolfSSL_SESSION_set_ex_data(WOLFSSL_SESSION* session, int idx, void* data);
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
WOLFSSL_API int wolfSSL_SESSION_set_ex_data_with_cleanup(
    WOLFSSL_SESSION* session,
    int idx,
    void* data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);
#endif
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

WOLFSSL_API const unsigned char* wolfSSL_SESSION_get_id(
        const WOLFSSL_SESSION* sess, unsigned int* idLen);

WOLFSSL_API int wolfSSL_SESSION_print(WOLFSSL_BIO* bp, const WOLFSSL_SESSION* session);

WOLFSSL_API int wolfSSL_set_tlsext_host_name(WOLFSSL* ssl, const char* host_name);

WOLFSSL_API const char* wolfSSL_get_servername(WOLFSSL* ssl, unsigned char type);

WOLFSSL_API WOLFSSL_CTX* wolfSSL_set_SSL_CTX(WOLFSSL* ssl,WOLFSSL_CTX* ctx);

WOLFSSL_API VerifyCallback wolfSSL_CTX_get_verify_callback(WOLFSSL_CTX* ctx);

WOLFSSL_API VerifyCallback wolfSSL_get_verify_callback(WOLFSSL* ssl);

#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || HAVE_LIGHTY */

#ifdef HAVE_SNI
/* SNI received callback type */
typedef int (*CallbackSniRecv)(WOLFSSL *ssl, int *ret, void* exArg);

WOLFSSL_API void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX* ctx,
        CallbackSniRecv cb);

WOLFSSL_API int  wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX* ctx, void* arg);
#endif

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

#ifdef HAVE_SNI
WOLFSSL_API int wolfSSL_CTX_set_tlsext_servername_callback(WOLFSSL_CTX* ctx,
        CallbackSniRecv cb);
#endif

WOLFSSL_API void wolfSSL_ERR_remove_thread_state(void* pid);

/* support for deprecated old name */
#define WOLFSSL_ERR_remove_thread_state wolfSSL_ERR_remove_thread_state

#ifndef NO_FILESYSTEM
WOLFSSL_API void wolfSSL_print_all_errors_fp(XFILE fp);
#endif

WOLFSSL_API int wolfSSL_THREADID_set_callback(
                    void (*threadid_func)(WOLFSSL_CRYPTO_THREADID*));

WOLFSSL_API void wolfSSL_THREADID_set_numeric(void* id, unsigned long val);
WOLFSSL_API void wolfSSL_THREADID_current(WOLFSSL_CRYPTO_THREADID* id);
WOLFSSL_API unsigned long wolfSSL_THREADID_hash(
                                    const WOLFSSL_CRYPTO_THREADID* id);

WOLFSSL_API WOLFSSL_X509_LOOKUP_TYPE wolfSSL_X509_OBJECT_get_type(
        const WOLFSSL_X509_OBJECT* obj);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_OBJECT)*
        wolfSSL_X509_STORE_get0_objects(WOLFSSL_X509_STORE* store);
WOLFSSL_API WOLFSSL_X509_OBJECT*
        wolfSSL_sk_X509_OBJECT_delete(WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* sk, int i);
WOLFSSL_API WOLFSSL_X509_OBJECT* wolfSSL_X509_OBJECT_new(void);
WOLFSSL_API void wolfSSL_X509_OBJECT_free(WOLFSSL_X509_OBJECT *obj);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_X509_OBJECT_get0_X509(const WOLFSSL_X509_OBJECT *obj);
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_X509_OBJECT_get0_X509_CRL(WOLFSSL_X509_OBJECT *obj);

WOLFSSL_API WOLFSSL_X509_OBJECT *wolfSSL_X509_OBJECT_retrieve_by_subject(
        WOLF_STACK_OF(WOLFSSL_X509_OBJECT) *sk,
        WOLFSSL_X509_LOOKUP_TYPE type,
        WOLFSSL_X509_NAME *name);
#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
#include <wolfssl/openssl/stack.h>
WOLFSSL_API void wolfSSL_sk_X509_pop_free(WOLF_STACK_OF(WOLFSSL_X509)* sk, void (*f) (WOLFSSL_X509*));
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && (defined(HAVE_ECC) || \
    defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))
WOLFSSL_API int wolfSSL_CTX_set1_curves_list(WOLFSSL_CTX* ctx, const char* names);
WOLFSSL_API int wolfSSL_set1_curves_list(WOLFSSL* ssl, const char* names);
#endif

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX)
WOLFSSL_API int wolfSSL_get_verify_mode(const WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_get_verify_mode(const WOLFSSL_CTX* ctx);
#endif

#ifdef WOLFSSL_JNI
WOLFSSL_API int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr);
WOLFSSL_API void* wolfSSL_get_jobject(WOLFSSL* ssl);
#endif /* WOLFSSL_JNI */


#ifdef WOLFSSL_ASYNC_CRYPT
WOLFSSL_API int wolfSSL_AsyncPoll(WOLFSSL* ssl, WOLF_EVENT_FLAG flags);
WOLFSSL_API int wolfSSL_CTX_AsyncPoll(WOLFSSL_CTX* ctx, WOLF_EVENT** events, int maxEvents,
    WOLF_EVENT_FLAG flags, int* eventCount);
#endif /* WOLFSSL_ASYNC_CRYPT */

typedef void (*Rem_Sess_Cb)(WOLFSSL_CTX*, WOLFSSL_SESSION*);

#ifdef OPENSSL_EXTRA
typedef void (*SSL_Msg_Cb)(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg);

#if defined(HAVE_SECRET_CALLBACK)
typedef void (*wolfSSL_CTX_keylog_cb_func)
            (const WOLFSSL* ssl, const char* line);
WOLFSSL_API void wolfSSL_CTX_set_keylog_callback(WOLFSSL_CTX* ctx,
    wolfSSL_CTX_keylog_cb_func cb);
WOLFSSL_API wolfSSL_CTX_keylog_cb_func wolfSSL_CTX_get_keylog_callback(
    const WOLFSSL_CTX* ctx);
#endif /* HAVE_SECRET_CALLBACK */

WOLFSSL_API int wolfSSL_CTX_set_msg_callback(WOLFSSL_CTX *ctx, SSL_Msg_Cb cb);
WOLFSSL_API int wolfSSL_set_msg_callback(WOLFSSL *ssl, SSL_Msg_Cb cb);
WOLFSSL_API int wolfSSL_CTX_set_msg_callback_arg(WOLFSSL_CTX *ctx, void* arg);
WOLFSSL_API int wolfSSL_set_msg_callback_arg(WOLFSSL *ssl, void* arg);
WOLFSSL_API unsigned long wolfSSL_ERR_peek_error_line_data(const char **file,
    int *line, const char **data, int *flags);
WOLFSSL_API int wolfSSL_CTX_set_alpn_protos(WOLFSSL_CTX *ctx,
    const unsigned char *protos, unsigned int protos_len);
WOLFSSL_API int wolfSSL_set_alpn_protos(WOLFSSL* ssl,
        const unsigned char* protos, unsigned int protos_len);
WOLFSSL_API void *wolfSSL_OPENSSL_memdup(const void *data,
    size_t siz, const char* file, int line);
WOLFSSL_API void wolfSSL_OPENSSL_cleanse(void *ptr, size_t len);
WOLFSSL_API void wolfSSL_ERR_load_BIO_strings(void);
WOLFSSL_API void wolfSSL_DH_get0_pqg(const WOLFSSL_DH* dh,
        const WOLFSSL_BIGNUM** p, const WOLFSSL_BIGNUM** q,
        const WOLFSSL_BIGNUM** g);
WOLFSSL_API void wolfSSL_DH_get0_key(const WOLFSSL_DH *dh,
        const WOLFSSL_BIGNUM **pub_key, const WOLFSSL_BIGNUM **priv_key);
WOLFSSL_API int wolfSSL_DH_set0_key(WOLFSSL_DH *dh, WOLFSSL_BIGNUM *pub_key,
        WOLFSSL_BIGNUM *priv_key);
#endif

#if defined(HAVE_OCSP) && !defined(NO_ASN_TIME)
    WOLFSSL_API int wolfSSL_get_ocsp_producedDate(
        WOLFSSL *ssl,
        byte *producedDate,
        size_t producedDate_space,
        int *producedDateFormat);
    WOLFSSL_API int wolfSSL_get_ocsp_producedDate_tm(WOLFSSL *ssl,
        struct tm *produced_tm);
#endif

#if defined(OPENSSL_ALL) \
    || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA) \
    || defined(HAVE_STUNNEL)
WOLFSSL_API void wolfSSL_OPENSSL_config(char *config_name);
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
/* Not an OpenSSL API. */
WOLFSSL_LOCAL int wolfSSL_get_ocsp_response(WOLFSSL* ssl, byte** response);
/* Not an OpenSSL API. */
WOLFSSL_LOCAL char* wolfSSL_get_ocsp_url(WOLFSSL* ssl);
/* Not an OpenSSL API. */
WOLFSSL_API int wolfSSL_set_ocsp_url(WOLFSSL* ssl, char* url);
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_SECRET_CALLBACK)
WOLFSSL_API long wolfSSL_SSL_CTX_get_timeout(const WOLFSSL_CTX *ctx);
WOLFSSL_API long wolfSSL_get_timeout(WOLFSSL* ssl);
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_CIPHER) *wolfSSL_get_ciphers_compat(const WOLFSSL *ssl);
WOLFSSL_API int wolfSSL_X509_NAME_digest(const WOLFSSL_X509_NAME *data,
    const WOLFSSL_EVP_MD *type, unsigned char *md, unsigned int *len);
WOLFSSL_API int wolfSSL_SSL_CTX_set_tmp_ecdh(WOLFSSL_CTX *ctx,
    WOLFSSL_EC_KEY *ecdh);
WOLFSSL_API WOLFSSL_BIO *wolfSSL_SSL_get_rbio(const WOLFSSL *s);
WOLFSSL_API WOLFSSL_BIO *wolfSSL_SSL_get_wbio(const WOLFSSL *s);
WOLFSSL_API int wolfSSL_SSL_do_handshake(WOLFSSL *s);
#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_OPENSSL_init_ssl(word64 opts,
    const WOLFSSL_INIT_SETTINGS *settings);
WOLFSSL_API WOLFSSL_INIT_SETTINGS* wolfSSL_OPENSSL_INIT_new(void);
WOLFSSL_API void wolfSSL_OPENSSL_INIT_free(WOLFSSL_INIT_SETTINGS* init);
WOLFSSL_API int  wolfSSL_OPENSSL_INIT_set_config_appname(
        WOLFSSL_INIT_SETTINGS* init, char* appname);
#endif
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
WOLFSSL_API int wolfSSL_SSL_in_init(const WOLFSSL* ssl);
#else
WOLFSSL_API int wolfSSL_SSL_in_init(WOLFSSL* ssl);
#endif
WOLFSSL_API int wolfSSL_SSL_in_before(const WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SSL_in_connect_init(WOLFSSL* ssl);

#ifndef NO_SESSION_CACHE
    WOLFSSL_API int wolfSSL_SSL_CTX_remove_session(WOLFSSL_CTX* ctx,
        WOLFSSL_SESSION *c);
    WOLFSSL_API WOLFSSL_SESSION *wolfSSL_SSL_get0_session(const WOLFSSL *s);
#endif

WOLFSSL_API int wolfSSL_i2a_ASN1_INTEGER(WOLFSSL_BIO *bp,
    const WOLFSSL_ASN1_INTEGER *a);

#ifdef HAVE_SESSION_TICKET
typedef int (*ticketCompatCb)(WOLFSSL *ssl, unsigned char *name, unsigned char *iv,
    WOLFSSL_EVP_CIPHER_CTX *ectx, WOLFSSL_HMAC_CTX *hctx, int enc);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_ticket_key_cb(WOLFSSL_CTX* ctx, ticketCompatCb cb);
#endif

#if defined(HAVE_OCSP) || defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
WOLFSSL_API int wolfSSL_CTX_get_extra_chain_certs(WOLFSSL_CTX* ctx,
    WOLF_STACK_OF(X509)** chain);
typedef int(*tlsextStatusCb)(WOLFSSL* ssl, void*);
WOLFSSL_API int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb);

WOLFSSL_API int wolfSSL_CTX_get0_chain_certs(WOLFSSL_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509) **sk);
WOLFSSL_API int wolfSSL_get0_chain_certs(WOLFSSL *ssl,
        WOLF_STACK_OF(WOLFSSL_X509) **sk);

WOLFSSL_API int wolfSSL_X509_STORE_CTX_get1_issuer(WOLFSSL_X509 **issuer,
    WOLFSSL_X509_STORE_CTX *ctx, WOLFSSL_X509 *x);

WOLFSSL_API void wolfSSL_X509_email_free(WOLF_STACK_OF(WOLFSSL_STRING) *sk);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_STRING) *wolfSSL_X509_get1_ocsp(WOLFSSL_X509 *x);

WOLFSSL_API int wolfSSL_X509_check_issued(WOLFSSL_X509 *issuer,
    WOLFSSL_X509 *subject);

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_STRING)* wolfSSL_sk_WOLFSSL_STRING_new(void);
WOLFSSL_API void wolfSSL_WOLFSSL_STRING_free(WOLFSSL_STRING s);
WOLFSSL_API void wolfSSL_sk_WOLFSSL_STRING_free(WOLF_STACK_OF(WOLFSSL_STRING)* sk);
WOLFSSL_API WOLFSSL_STRING wolfSSL_sk_WOLFSSL_STRING_value(
    WOLF_STACK_OF(WOLFSSL_STRING)* strings, int idx);
WOLFSSL_API int wolfSSL_sk_WOLFSSL_STRING_num(
    WOLF_STACK_OF(WOLFSSL_STRING)* strings);
#endif /* HAVE_OCSP || OPENSSL_EXTRA || OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

WOLFSSL_API int PEM_write_bio_WOLFSSL_X509(WOLFSSL_BIO *bio,
    WOLFSSL_X509 *cert);

#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    !defined(NO_WOLFSSL_SERVER)
WOLFSSL_API long wolfSSL_CTX_get_tlsext_ticket_keys(WOLFSSL_CTX *ctx,
     unsigned char *keys, int keylen);
WOLFSSL_API long wolfSSL_CTX_set_tlsext_ticket_keys(WOLFSSL_CTX *ctx,
     const void *keys_vp, int keylen);
#endif

WOLFSSL_API void wolfSSL_get0_alpn_selected(const WOLFSSL *ssl,
        const unsigned char **data, unsigned int *len);
WOLFSSL_API int wolfSSL_select_next_proto(unsigned char **out,
        unsigned char *outlen,
        const unsigned char *in, unsigned int inlen,
        const unsigned char *client,
        unsigned int client_len);
WOLFSSL_API void wolfSSL_set_alpn_select_cb(WOLFSSL *ssl,
        int (*cb) (WOLFSSL *ssl,
            const unsigned char **out,
            unsigned char *outlen,
            const unsigned char *in,
            unsigned int inlen,
            void *arg), void *arg);
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

#ifndef NO_ASN
WOLFSSL_API int wolfSSL_X509_check_host(WOLFSSL_X509 *x, const char *chk,
    size_t chklen, unsigned int flags, char **peername);
WOLFSSL_API int wolfSSL_X509_check_ip_asc(WOLFSSL_X509 *x, const char *ipasc,
        unsigned int flags);
#endif
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
WOLFSSL_API int wolfSSL_X509_check_email(WOLFSSL_X509 *x, const char *chk,
                                         size_t chkLen, unsigned int flags);
#endif /* OPENSSL_EXTRA && WOLFSSL_CERT_GEN */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_WPAS)
WOLFSSL_API const unsigned char *wolfSSL_SESSION_get0_id_context(
                    const WOLFSSL_SESSION *sess, unsigned int *sid_ctx_length);
#endif
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
WOLFSSL_API int wolfSSL_SESSION_set1_id(WOLFSSL_SESSION *s,
                                const unsigned char *sid, unsigned int sid_len);
WOLFSSL_API int wolfSSL_SESSION_set1_id_context(WOLFSSL_SESSION *s,
                        const unsigned char *sid_ctx, unsigned int sid_ctx_len);
WOLFSSL_API WOLFSSL_X509_ALGOR* wolfSSL_X509_ALGOR_new(void);
WOLFSSL_API void wolfSSL_X509_ALGOR_free(WOLFSSL_X509_ALGOR *alg);
WOLFSSL_API const WOLFSSL_X509_ALGOR* wolfSSL_X509_get0_tbs_sigalg(const WOLFSSL_X509 *x);
WOLFSSL_API void wolfSSL_X509_ALGOR_get0(const WOLFSSL_ASN1_OBJECT **paobj, int *pptype, const void **ppval, const WOLFSSL_X509_ALGOR *algor);
WOLFSSL_API int wolfSSL_X509_ALGOR_set0(WOLFSSL_X509_ALGOR *algor, WOLFSSL_ASN1_OBJECT *aobj, int ptype, void *pval);
WOLFSSL_API int wolfSSL_i2d_X509_ALGOR(const WOLFSSL_X509_ALGOR* alg,
        unsigned char** pp);
WOLFSSL_API WOLFSSL_X509_ALGOR* wolfSSL_d2i_X509_ALGOR(WOLFSSL_X509_ALGOR** out,
        const byte** src, long len);
WOLFSSL_API WOLFSSL_ASN1_TYPE* wolfSSL_ASN1_TYPE_new(void);
WOLFSSL_API void wolfSSL_ASN1_TYPE_free(WOLFSSL_ASN1_TYPE* at);
WOLFSSL_API int wolfSSL_i2d_ASN1_TYPE(WOLFSSL_ASN1_TYPE* at,
                                      unsigned char** pp);
WOLFSSL_API WOLFSSL_X509_PUBKEY *wolfSSL_X509_PUBKEY_new(void);
WOLFSSL_API void wolfSSL_X509_PUBKEY_free(WOLFSSL_X509_PUBKEY *x);
WOLFSSL_API WOLFSSL_X509_PUBKEY *wolfSSL_X509_get_X509_PUBKEY(const WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_PUBKEY_get0_param(WOLFSSL_ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, WOLFSSL_X509_ALGOR **pa, WOLFSSL_X509_PUBKEY *pub);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_X509_PUBKEY_get(WOLFSSL_X509_PUBKEY* key);
WOLFSSL_API int wolfSSL_X509_PUBKEY_set(WOLFSSL_X509_PUBKEY **x, WOLFSSL_EVP_PKEY *key);
WOLFSSL_API int wolfSSL_i2t_ASN1_OBJECT(char *buf, int buf_len, WOLFSSL_ASN1_OBJECT *a);
WOLFSSL_API WOLFSSL_ASN1_OBJECT *wolfSSL_d2i_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT **a,
                                                         const unsigned char **der,
                                                         long length);
WOLFSSL_API int wolfSSL_i2a_ASN1_OBJECT(WOLFSSL_BIO *bp, WOLFSSL_ASN1_OBJECT *a);
WOLFSSL_API int wolfSSL_i2d_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT *a, unsigned char **pp);
WOLFSSL_API void WOLFSSL_CTX_set_tmp_dh_callback(WOLFSSL_CTX *ctx, WOLFSSL_DH *(*dh) (WOLFSSL *ssl, int is_export, int keylength));
#ifndef OPENSSL_COEXIST
#define SSL_CTX_set_tmp_dh_callback WOLFSSL_CTX_set_tmp_dh_callback
#endif
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_COMP) *WOLFSSL_COMP_get_compression_methods(void);
#ifndef OPENSSL_COEXIST
#define SSL_COMP_get_compression_methods WOLFSSL_COMP_get_compression_methods
#endif
WOLFSSL_API int wolfSSL_X509_STORE_load_locations(WOLFSSL_X509_STORE *str, const char *file, const char *dir);
WOLFSSL_API int wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE *str);
WOLFSSL_API int wolfSSL_X509_STORE_add_crl(WOLFSSL_X509_STORE *ctx, WOLFSSL_X509_CRL *x);
WOLFSSL_API int wolfSSL_sk_SSL_CIPHER_num(const WOLF_STACK_OF(WOLFSSL_CIPHER)* p);
WOLFSSL_API int wolfSSL_sk_SSL_CIPHER_find(
        WOLF_STACK_OF(WOLFSSL_CIPHER)* sk, const WOLFSSL_CIPHER* toFind);
WOLFSSL_API void wolfSSL_sk_SSL_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);
WOLFSSL_API int wolfSSL_sk_SSL_COMP_zero(WOLFSSL_STACK* st);
WOLFSSL_API int wolfSSL_sk_SSL_COMP_num(WOLF_STACK_OF(WOLFSSL_COMP)* sk);
WOLFSSL_API WOLFSSL_CIPHER* wolfSSL_sk_SSL_CIPHER_value(WOLFSSL_STACK* sk, int i);
WOLFSSL_API void wolfSSL_ERR_load_SSL_strings(void);
#ifndef OPENSSL_COEXIST
#define ERR_load_SSL_strings wolfSSL_ERR_load_SSL_strings
#endif
WOLFSSL_API void wolfSSL_EC_POINT_dump(const char *msg, const WOLFSSL_EC_POINT *p);

WOLFSSL_API const char *wolfSSL_ASN1_tag2str(int tag);
WOLFSSL_API int wolfSSL_ASN1_STRING_print_ex(WOLFSSL_BIO *out, WOLFSSL_ASN1_STRING *str, unsigned long flags);
WOLFSSL_API int wolfSSL_ASN1_STRING_print(WOLFSSL_BIO *out, WOLFSSL_ASN1_STRING *str);
WOLFSSL_API int wolfSSL_ASN1_TIME_get_length(const WOLFSSL_ASN1_TIME *t);
WOLFSSL_API unsigned char* wolfSSL_ASN1_TIME_get_data(const WOLFSSL_ASN1_TIME *t);
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_ASN1_TIME_to_generalizedtime(WOLFSSL_ASN1_TIME *t,
                                                                WOLFSSL_ASN1_TIME **out);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_ASN1_UTCTIME_set(WOLFSSL_ASN1_TIME *s, time_t t);
WOLFSSL_API int wolfSSL_i2c_ASN1_INTEGER(WOLFSSL_ASN1_INTEGER *a, unsigned char **pp);
WOLFSSL_API int wolfSSL_a2i_ASN1_INTEGER(WOLFSSL_BIO *bio, WOLFSSL_ASN1_INTEGER *asn1,
        char *buf, int size);
WOLFSSL_API int wolfSSL_X509_CA_num(WOLFSSL_X509_STORE *store);
WOLFSSL_API long wolfSSL_X509_get_version(const WOLFSSL_X509 *x);
WOLFSSL_API int wolfSSL_X509_get_signature_nid(const WOLFSSL_X509* x);

#ifndef WOLFCRYPT_ONLY
WOLFSSL_API int wolfSSL_PEM_write_bio_PKCS8PrivateKey(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY* pkey, const WOLFSSL_EVP_CIPHER* enc, char* passwd,
    int passwdSz, wc_pem_password_cb* cb, void* ctx);
WOLFSSL_API int wolfSSL_PEM_write_bio_PKCS8_PRIV_KEY_INFO(WOLFSSL_BIO* bio,
        WOLFSSL_PKCS8_PRIV_KEY_INFO* keyInfo);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API int wolfSSL_PEM_write_PKCS8PrivateKey(
    XFILE fp, WOLFSSL_EVP_PKEY* pkey, const WOLFSSL_EVP_CIPHER* enc,
    char* passwd, int passwdSz, wc_pem_password_cb* cb, void* ctx);
#endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PKCS8PrivateKey_bio(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY** pkey, wc_pem_password_cb* cb, void* u);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_AutoPrivateKey(
    WOLFSSL_EVP_PKEY** pkey, const unsigned char** data, long length);
#endif /* !WOLFCRYPT_ONLY */

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef WOLFSSL_HAVE_TLS_UNIQUE
WOLFSSL_API size_t wolfSSL_get_finished(const WOLFSSL *ssl, void *buf, size_t count);
WOLFSSL_API size_t wolfSSL_get_peer_finished(const WOLFSSL *ssl, void *buf, size_t count);
#endif /* WOLFSSL_HAVE_TLS_UNIQUE */

#ifdef HAVE_PK_CALLBACKS
WOLFSSL_API int wolfSSL_IsPrivatePkSet(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_IsPrivatePkSet(WOLFSSL_CTX* ctx);
#endif

#ifdef HAVE_ENCRYPT_THEN_MAC
WOLFSSL_API int wolfSSL_CTX_AllowEncryptThenMac(WOLFSSL_CTX* ctx, int set);
WOLFSSL_API int wolfSSL_AllowEncryptThenMac(WOLFSSL *s, int set);
#endif

/* This feature is used to set a fixed ephemeral key and is for testing only */
/* Currently allows ECDHE and DHE only */
#ifdef WOLFSSL_STATIC_EPHEMERAL
WOLFSSL_API int wolfSSL_CTX_set_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const char* key, unsigned int keySz, int format);
WOLFSSL_API int wolfSSL_set_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const char* key, unsigned int keySz, int format);

/* returns pointer to loaded key as ASN.1/DER */
WOLFSSL_API int wolfSSL_CTX_get_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);
WOLFSSL_API int wolfSSL_get_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);
#endif

#ifdef HAVE_RPK
/* cert type for client_certificate_type/server_certificate_type extensions */
enum {
    WOLFSSL_CERT_TYPE_UNKNOWN = -1,
    WOLFSSL_CERT_TYPE_X509 = 0,
    WOLFSSL_CERT_TYPE_RPK  = 2
};
#define MAX_CLIENT_CERT_TYPE_CNT 2
#define MAX_SERVER_CERT_TYPE_CNT 2

WOLFSSL_API int wolfSSL_CTX_set_client_cert_type(WOLFSSL_CTX* ctx,
                                          const char* buf, int len);
WOLFSSL_API int wolfSSL_CTX_set_server_cert_type(WOLFSSL_CTX* ctx,
                                          const char* buf, int len);
WOLFSSL_API int wolfSSL_set_client_cert_type(WOLFSSL* ssl,
                                          const char* buf, int len);
WOLFSSL_API int wolfSSL_set_server_cert_type(WOLFSSL* ssl,
                                          const char* buf, int len);
WOLFSSL_API int wolfSSL_get_negotiated_client_cert_type(WOLFSSL* ssl, int* tp);
WOLFSSL_API int wolfSSL_get_negotiated_server_cert_type(WOLFSSL* ssl, int* tp);
#endif /* HAVE_RPK */


#if defined(OPENSSL_EXTRA)
#ifndef WOLFCRYPT_ONLY
WOLFSSL_API int wolfSSL_EVP_PKEY_param_check(WOLFSSL_EVP_PKEY_CTX* ctx);
#endif
WOLFSSL_API void wolfSSL_CTX_set_security_level(WOLFSSL_CTX* ctx, int level);
WOLFSSL_API int wolfSSL_CTX_get_security_level(const WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_SESSION_is_resumable(const WOLFSSL_SESSION *s);

WOLFSSL_API void wolfSSL_CRYPTO_free(void *str, const char *file, int line);
WOLFSSL_API void *wolfSSL_CRYPTO_malloc(size_t num, const char *file, int line);

WOLFSSL_API WOLFSSL_CONF_CTX* wolfSSL_CONF_CTX_new(void);
WOLFSSL_API void wolfSSL_CONF_CTX_free(WOLFSSL_CONF_CTX* cctx);
WOLFSSL_API void wolfSSL_CONF_CTX_set_ssl_ctx(WOLFSSL_CONF_CTX* cctx, WOLFSSL_CTX *ctx);
WOLFSSL_API unsigned int wolfSSL_CONF_CTX_set_flags(WOLFSSL_CONF_CTX* cctx, unsigned int flags);
WOLFSSL_API int wolfSSL_CONF_CTX_finish(WOLFSSL_CONF_CTX* cctx);

#define WOLFSSL_CONF_FLAG_CMDLINE       0x1
#define WOLFSSL_CONF_FLAG_FILE          0x2
#define WOLFSSL_CONF_FLAG_CLIENT        0x4
#define WOLFSSL_CONF_FLAG_SERVER        0x8
#define WOLFSSL_CONF_FLAG_SHOW_ERRORS   0x10
#define WOLFSSL_CONF_FLAG_CERTIFICATE   0x20

#define WOLFSSL_CONF_TYPE_UNKNOWN       0x0
#define WOLFSSL_CONF_TYPE_STRING        0x1
#define WOLFSSL_CONF_TYPE_FILE          0x2
#define WOLFSSL_CONF_TYPE_DIR           0x3

WOLFSSL_API int wolfSSL_CONF_cmd(WOLFSSL_CONF_CTX* cctx, const char* cmd, const char* value);
WOLFSSL_API int wolfSSL_CONF_cmd_value_type(WOLFSSL_CONF_CTX *cctx, const char *cmd);
#endif /* OPENSSL_EXTRA */

#if defined(WOLFSSL_DTLS_CID)
WOLFSSL_API int wolfSSL_dtls_cid_use(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_dtls_cid_is_enabled(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid,
    unsigned int size);
WOLFSSL_API int wolfSSL_dtls_cid_get_rx_size(WOLFSSL* ssl,
    unsigned int* size);
WOLFSSL_API int wolfSSL_dtls_cid_get_rx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);
WOLFSSL_API int wolfSSL_dtls_cid_get0_rx(WOLFSSL* ssl, unsigned char** cid);
WOLFSSL_API int wolfSSL_dtls_cid_get_tx_size(WOLFSSL* ssl,
    unsigned int* size);
WOLFSSL_API int wolfSSL_dtls_cid_get_tx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);
WOLFSSL_API int wolfSSL_dtls_cid_get0_tx(WOLFSSL* ssl, unsigned char** cid);
WOLFSSL_API int wolfSSL_dtls_cid_max_size(void);
WOLFSSL_API const unsigned char* wolfSSL_dtls_cid_parse(const unsigned char* msg,
        unsigned int msgSz, unsigned int cidSz);
#endif /* defined(WOLFSSL_DTLS_CID) */

#ifdef WOLFSSL_DTLS_CH_FRAG
    WOLFSSL_API int wolfSSL_dtls13_allow_ch_frag(WOLFSSL *ssl, int enabled);
#endif
#ifdef WOLFSSL_DTLS13_NO_HRR_ON_RESUME
    WOLFSSL_API int wolfSSL_dtls13_no_hrr_on_resume(WOLFSSL *ssl, int enabled);
#endif

/*  */
#define SSL2_VERSION                     0x0002
#define SSL3_VERSION                     0x0300
#define TLS1_VERSION                     0x0301
#define TLS1_1_VERSION                   0x0302
#define TLS1_2_VERSION                   0x0303
#define TLS1_3_VERSION                   0x0304
#define DTLS1_VERSION                    0xFEFF
#define DTLS1_2_VERSION                  0xFEFD
#define DTLS1_3_VERSION                  0xFEFC

/* These minimums where determined whilst referencing their RFC specs. The
 * values represent the minimum sizes of the data types in the required struct
 * for the `extension_data` field. A length of 0 was assumed when necassary.
 *
 * Documents Used for the respective extension:
 *  - https://datatracker.ietf.org/doc/html/rfc6066
 *      - Server Name Indication (SNI)
 *      - Maximum Fragment Length Negotiation (MFL)
 *      - Trusted CA Indication (TCA)
 *      - Certificate Status Request (CSR)
 *      - Truncate HMAC (THM)
 *  - https://datatracker.ietf.org/doc/html/rfc8446
 *      - Early Data Indication (EDI)
 *      - Pre-Shared Key (PSK)
 *      - Pre-Shared Key Exchange Modes (PKM)
 *      - Key Share (KS)
 *      - Post-Handshake Authentication (PHA)
 *      - Signature Algorithms (SA)
 *      - Signature Algorithms Certificate (SAC)
 *      - Support Groups (EC)
 *      - Cookie (CKE)
 *      - Supported Versions (SV)
 *      - Certificate Authorities (CAN)
 *  - https://datatracker.ietf.org/doc/html/rfc6961
 *      - Certificate Status Request v2 (CSR2)
 *  - https://datatracker.ietf.org/doc/rfc9146/
 *      - Connection Identifier (CID)
 *  - https://datatracker.ietf.org/doc/rfc7301/
 *      - Application-Layer Protocol Negotiation (ALPN)
 *  - https://datatracker.ietf.org/doc/html/rfc3711
 *      - Secure Real-time Transport Protocol (SRTP)
 *  - https://datatracker.ietf.org/doc/html/rfc7366
 *      - Encrypt Then Mac (ETM)
 *  - https://datatracker.ietf.org/doc/html/rfc7250
 *      - Client Certificate Type (CCT)
 *      - Server Certificate Type (SCT)
 *  - https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
 *      - Encrypted Client Hello (ECH)
 *  - https://datatracker.ietf.org/doc/html/rfc5746
 *      - Secure Renegotiation (SCR)
 *  - https://datatracker.ietf.org/doc/rfc4492/
 *      - Point Frame (PF)
 *  - https://datatracker.ietf.org/doc/rfc9000/
 *      - QUIC (QTP)
 *  - https://datatracker.ietf.org/doc/html/rfc5077
 *      - Session Ticket (STK)
 * Example:
 *  For `WOLFSSL_CSR_MIN_SIZE_CLIENT = 5`, 5 was determined by looking at the
 * struct below defined in its respective RFC.
 * The below struct for `CertificateStatusRequest` is made up of the types:
 *      `CertificateStatusType` is an enum with a max value of 255, thus its
 *          length is 1 byte.
 *      `OCSPStatusRequest` is a struct of the following:
 *          - `responder_id_list`: which is 2 bytes
 *          - `request_extensions`: which is 2 bytes
 *      This then gives the minimum size/length of 5 bytes for this extension
 *          for the client
 *  struct {
 *      CertificateStatusType status_type;
 *      select (status_type) {
 *          case ocsp: OCSPStatusRequest;
 *      } request;
 *  } CertificateStatusRequest;
 *  enum { ocsp(1), (255) } CertificateStatusType;
 *  struct {
 *      ResponderID responder_id_list<0..2^16-1>;
 *      Extensions  request_extensions;
 *    } OCSPStatusRequest;
 *    opaque ResponderID<1..2^16-1>;
 *    opaque Extensions<0..2^16-1>;
 */

#ifndef WOLFSSL_SNI_MIN_SIZE_CLIENT
    #define WOLFSSL_SNI_MIN_SIZE_CLIENT   4
#endif
#ifndef WOLFSSL_SNI_MIN_SIZE_SERVER
    #define WOLFSSL_SNI_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_EDI_MIN_SIZE_CLIENT
    #define WOLFSSL_EDI_MIN_SIZE_CLIENT   0
#endif
#ifndef WOLFSSL_EDI_MIN_SIZE_SERVER
    #define WOLFSSL_EDI_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_TCA_MIN_SIZE_CLIENT
    #define WOLFSSL_TCA_MIN_SIZE_CLIENT   2
#endif
#ifndef WOLFSSL_TCA_MIN_SIZE_SERVER
    #define WOLFSSL_TCA_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_CSR_MIN_SIZE_CLIENT
    #define WOLFSSL_CSR_MIN_SIZE_CLIENT   5
#endif
#ifndef WOLFSSL_CSR_MIN_SIZE_SERVER
    #define WOLFSSL_CSR_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_PKM_MIN_SIZE_CLIENT
    #define WOLFSSL_PKM_MIN_SIZE_CLIENT   1
#endif
#ifndef WOLFSSL_PKM_MIN_SIZE_SERVER
    #define WOLFSSL_PKM_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_CSR2_MIN_SIZE_CLIENT
    #define WOLFSSL_CSR2_MIN_SIZE_CLIENT  7
#endif
#ifndef WOLFSSL_CSR2_MIN_SIZE_SERVER
    #define WOLFSSL_CSR2_MIN_SIZE_SERVER  0
#endif
#ifndef WOLFSSL_CID_MIN_SIZE_CLIENT
    #define WOLFSSL_CID_MIN_SIZE_CLIENT   1
#endif
#ifndef WOLFSSL_CID_MIN_SIZE_SERVER
    #define WOLFSSL_CID_MIN_SIZE_SERVER   1
#endif
#ifndef WOLFSSL_ALPN_MIN_SIZE_CLIENT
    #define WOLFSSL_ALPN_MIN_SIZE_CLIENT  2
#endif
#ifndef WOLFSSL_ALPN_MIN_SIZE_SERVER
    #define WOLFSSL_ALPN_MIN_SIZE_SERVER  2
#endif
#ifndef WOLFSSL_SRTP_MIN_SIZE_CLIENT
    #define WOLFSSL_SRTP_MIN_SIZE_CLIENT  3
#endif
#ifndef WOLFSSL_SRTP_MIN_SIZE_SERVER
    #define WOLFSSL_SRTP_MIN_SIZE_SERVER  3
#endif
#ifndef WOLFSSL_KS_MIN_SIZE_CLIENT
    #define WOLFSSL_KS_MIN_SIZE_CLIENT    1
#endif
#ifndef WOLFSSL_KS_MIN_SIZE_SERVER
    #define WOLFSSL_KS_MIN_SIZE_SERVER    1
#endif
#ifndef WOLFSSL_ETM_MIN_SIZE_CLIENT
    #define WOLFSSL_ETM_MIN_SIZE_CLIENT   0
#endif
#ifndef WOLFSSL_ETM_MIN_SIZE_SERVER
    #define WOLFSSL_ETM_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_PSK_MIN_SIZE_CLIENT
    #define WOLFSSL_PSK_MIN_SIZE_CLIENT   2
#endif
#ifndef WOLFSSL_PSK_MIN_SIZE_SERVER
    #define WOLFSSL_PSK_MIN_SIZE_SERVER   2
#endif
#ifndef WOLFSSL_CCT_MIN_SIZE_CLIENT
    #define WOLFSSL_CCT_MIN_SIZE_CLIENT   1
#endif
#ifndef WOLFSSL_CCT_MIN_SIZE_SERVER
    #define WOLFSSL_CCT_MIN_SIZE_SERVER   1
#endif
#ifndef WOLFSSL_SCT_MIN_SIZE_CLIENT
    #define WOLFSSL_SCT_MIN_SIZE_CLIENT   1
#endif
#ifndef WOLFSSL_SCT_MIN_SIZE_SERVER
    #define WOLFSSL_SCT_MIN_SIZE_SERVER   1
#endif
#ifndef WOLFSSL_PHA_MIN_SIZE_CLIENT
    #define WOLFSSL_PHA_MIN_SIZE_CLIENT   0
#endif
#ifndef WOLFSSL_PHA_MIN_SIZE_SERVER
    #define WOLFSSL_PHA_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_THM_MIN_SIZE_CLIENT
    #define WOLFSSL_THM_MIN_SIZE_CLIENT   0
#endif
#ifndef WOLFSSL_THM_MIN_SIZE_SERVER
    #define WOLFSSL_THM_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_SA_MIN_SIZE_CLIENT
    #define WOLFSSL_SA_MIN_SIZE_CLIENT    2
#endif
#ifndef WOLFSSL_SA_MIN_SIZE_SERVER
    #define WOLFSSL_SA_MIN_SIZE_SERVER    2
#endif
#ifndef WOLFSSL_SAC_MIN_SIZE_CLIENT
    #define WOLFSSL_SAC_MIN_SIZE_CLIENT   2
#endif
#ifndef WOLFSSL_SAC_MIN_SIZE_SERVER
    #define WOLFSSL_SAC_MIN_SIZE_SERVER   2
#endif
#ifndef WOLFSSL_EC_MIN_SIZE_CLIENT
    #define WOLFSSL_EC_MIN_SIZE_CLIENT    2
#endif
#ifndef WOLFSSL_EC_MIN_SIZE_SERVER
    #define WOLFSSL_EC_MIN_SIZE_SERVER    2
#endif
#ifndef WOLFSSL_ECH_MIN_SIZE_CLIENT
    #define WOLFSSL_ECH_MIN_SIZE_CLIENT   1
#endif
#ifndef WOLFSSL_ECH_MIN_SIZE_SERVER
    #define WOLFSSL_ECH_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_MFL_MIN_SIZE_CLIENT
    #define WOLFSSL_MFL_MIN_SIZE_CLIENT   1
#endif
#ifndef WOLFSSL_MFL_MIN_SIZE_SERVER
    #define WOLFSSL_MFL_MIN_SIZE_SERVER   1
#endif
#ifndef WOLFSSL_CKE_MIN_SIZE_CLIENT
    #define WOLFSSL_CKE_MIN_SIZE_CLIENT   3
#endif
#ifndef WOLFSSL_CKE_MIN_SIZE_SERVER
    #define WOLFSSL_CKE_MIN_SIZE_SERVER   3
#endif
#ifndef WOLFSSL_SV_MIN_SIZE_CLIENT
    #define WOLFSSL_SV_MIN_SIZE_CLIENT    2
#endif
#ifndef WOLFSSL_SV_MIN_SIZE_SERVER
    #define WOLFSSL_SV_MIN_SIZE_SERVER    2
#endif
#ifndef WOLFSSL_SCR_MIN_SIZE_CLIENT
    #define WOLFSSL_SCR_MIN_SIZE_CLIENT   1
#endif
#ifndef WOLFSSL_SCR_MIN_SIZE_SERVER
    #define WOLFSSL_SCR_MIN_SIZE_SERVER   1
#endif
#ifndef WOLFSSL_PF_MIN_SIZE_CLIENT
    #define WOLFSSL_PF_MIN_SIZE_CLIENT    1
#endif
#ifndef WOLFSSL_PF_MIN_SIZE_SERVER
    #define WOLFSSL_PF_MIN_SIZE_SERVER    1
#endif
#ifndef WOLFSSL_CAN_MIN_SIZE_CLIENT
    #define WOLFSSL_CAN_MIN_SIZE_CLIENT   3
#endif
#ifndef WOLFSSL_CAN_MIN_SIZE_SERVER
    #define WOLFSSL_CAN_MIN_SIZE_SERVER   3
#endif
#ifndef WOLFSSL_QTP_MIN_SIZE_CLIENT
    #define WOLFSSL_QTP_MIN_SIZE_CLIENT   0
#endif
#ifndef WOLFSSL_QTP_MIN_SIZE_SERVER
    #define WOLFSSL_QTP_MIN_SIZE_SERVER   0
#endif
#ifndef WOLFSSL_STK_MIN_SIZE_CLIENT
    #define WOLFSSL_STK_MIN_SIZE_CLIENT   0
#endif
#ifndef WOLFSSL_STK_MIN_SIZE_SERVER
    #define WOLFSSL_STK_MIN_SIZE_SERVER   0
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_SSL_H */
