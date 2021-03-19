/* ssl_types.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

/*
 * This file defines types that were previously found in wolfssl/ssl.h. Other
 * ssl header files should include this header instead of wolfssl/ssl.h to
 * prevent circular dependencies of header includes.
 */

#ifndef WOLFSSL_SSL_TYPES_H_
#define WOLFSSL_SSL_TYPES_H_

#ifdef __cplusplus
    extern "C" {
#endif

/* *NEVER* include any other ssl headers. Only wolfcrypt headers
 * may be included from this file. */
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/idea.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/random.h>

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

#define STACK_OF(x) WOLFSSL_STACK
#define OPENSSL_STACK WOLFSSL_STACK
#define _STACK OPENSSL_STACK

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
typedef struct WOLFSSL_X509_PUBKEY WOLFSSL_X509_PUBKEY;
typedef struct WOLFSSL_X509_ALGOR WOLFSSL_X509_ALGOR;
typedef struct WOLFSSL_X509_CHAIN WOLFSSL_X509_CHAIN;
typedef struct WC_PKCS12          WOLFSSL_X509_PKCS12;
typedef struct WOLFSSL_X509_INFO  WOLFSSL_X509_INFO;

typedef struct WOLFSSL_CERT_MANAGER WOLFSSL_CERT_MANAGER;
typedef struct WOLFSSL_SOCKADDR     WOLFSSL_SOCKADDR;
typedef struct WOLFSSL_CRL          WOLFSSL_CRL;
typedef struct WOLFSSL_X509_STORE_CTX WOLFSSL_X509_STORE_CTX;

typedef int (*WOLFSSL_X509_STORE_CTX_verify_cb)(int, WOLFSSL_X509_STORE_CTX *);

typedef struct WOLFSSL_RSA                  WOLFSSL_RSA;
typedef struct WOLFSSL_RSA_METHOD           WOLFSSL_RSA_METHOD;

typedef struct WOLFSSL_BIGNUM               WOLFSSL_BIGNUM;


#ifndef NO_MD4
typedef struct WOLFSSL_MD4_CTX              WOLFSSL_MD4_CTX;
typedef WOLFSSL_MD4_CTX                     MD4_CTX;
#endif
#ifndef NO_MD5
typedef struct WOLFSSL_MD5_CTX              WOLFSSL_MD5_CTX;
typedef WOLFSSL_MD5_CTX                     MD5_CTX;
#endif

typedef struct WOLFSSL_SHA_CTX              WOLFSSL_SHA_CTX;
typedef WOLFSSL_SHA_CTX                     SHA_CTX;
#ifdef WOLFSSL_SHA224
typedef struct WOLFSSL_SHA224_CTX           WOLFSSL_SHA224_CTX;
typedef WOLFSSL_SHA224_CTX                  SHA224_CTX;
#endif /* WOLFSSL_SHA224 */
typedef struct WOLFSSL_SHA256_CTX           WOLFSSL_SHA256_CTX;
typedef WOLFSSL_SHA256_CTX                  SHA256_CTX;
#ifdef WOLFSSL_SHA384
typedef struct WOLFSSL_SHA384_CTX           WOLFSSL_SHA384_CTX;
typedef WOLFSSL_SHA384_CTX SHA384_CTX;
#endif /* WOLFSSL_SHA384 */
#ifdef WOLFSSL_SHA512
typedef struct WOLFSSL_SHA512_CTX           WOLFSSL_SHA512_CTX;
typedef WOLFSSL_SHA512_CTX                  SHA512_CTX;
#endif /* WOLFSSL_SHA512 */

typedef struct WOLFSSL_RIPEMD_CTX           WOLFSSL_RIPEMD_CTX;
typedef WOLFSSL_RIPEMD_CTX                  RIPEMD_CTX;

#ifndef WOLFSSL_NOSHA3_224
typedef struct WOLFSSL_SHA3_CTX             WOLFSSL_SHA3_224_CTX;
typedef WOLFSSL_SHA3_224_CTX                SHA3_224_CTX;
#endif /* WOLFSSL_NOSHA3_224 */
#ifndef WOLFSSL_NOSHA3_256
typedef struct WOLFSSL_SHA3_CTX             WOLFSSL_SHA3_256_CTX;
typedef WOLFSSL_SHA3_256_CTX                SHA3_256_CTX;
#endif /* WOLFSSL_NOSHA3_256 */
typedef struct WOLFSSL_SHA3_CTX             WOLFSSL_SHA3_384_CTX;
typedef WOLFSSL_SHA3_384_CTX                SHA3_384_CTX;
#ifndef WOLFSSL_NOSHA3_512
typedef struct WOLFSSL_SHA3_CTX             WOLFSSL_SHA3_512_CTX;
typedef WOLFSSL_SHA3_512_CTX                SHA3_512_CTX;
#endif /* WOLFSSL_NOSHA3_512 */


/* redeclare guard */
#define WOLFSSL_TYPES_DEFINED

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
typedef struct WOLFSSL_BIO            WOLFSSL_BIO;
typedef struct WOLFSSL_BIO_METHOD     WOLFSSL_BIO_METHOD;
typedef struct WOLFSSL_X509_EXTENSION WOLFSSL_X509_EXTENSION;
typedef struct WOLFSSL_ASN1_OBJECT    WOLFSSL_ASN1_OBJECT;
typedef struct WOLFSSL_ASN1_OTHERNAME WOLFSSL_ASN1_OTHERNAME;
typedef struct WOLFSSL_X509V3_CTX     WOLFSSL_X509V3_CTX;
typedef struct WOLFSSL_v3_ext_method  WOLFSSL_v3_ext_method;

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

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

struct WOLFSSL_AUTHORITY_KEYID {
    WOLFSSL_ASN1_STRING *keyid;
    WOLFSSL_ASN1_OBJECT *issuer;
    WOLFSSL_ASN1_INTEGER *serial;
};

struct WOLFSSL_BASIC_CONSTRAINTS {
    int ca;
    WOLFSSL_ASN1_INTEGER *pathlen;
};

#endif /* OPENSSL_ALL || OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */


#define WOLFSSL_ASN1_UTCTIME          WOLFSSL_ASN1_TIME
#define WOLFSSL_ASN1_GENERALIZEDTIME  WOLFSSL_ASN1_TIME

struct WOLFSSL_ASN1_STRING {
    char strData[CTC_NAME_SIZE];
    int length;
    int type; /* type of string i.e. CTC_UTF8 */
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

typedef WOLF_STACK_OF(WOLFSSL_GENERAL_NAME) WOLFSSL_GENERAL_NAMES;

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
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT) || defined(WOLFSSL_APACHE_HTTPD)
    int ca;
    WOLFSSL_ASN1_INTEGER *pathlen;
#endif
    unsigned char dynamic; /* Use WOLFSSL_ASN1_DYNAMIC and WOLFSSL_ASN1_DYNAMIC_DATA
                            * to determine what needs to be freed. */

#if defined(WOLFSSL_APACHE_HTTPD)
    WOLFSSL_GENERAL_NAME* gn;
#endif

    struct d { /* derefrenced */
        WOLFSSL_ASN1_STRING* dNSName;
        WOLFSSL_ASN1_STRING  ia5_internal;
        WOLFSSL_ASN1_STRING* ia5; /* points to ia5_internal */
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
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
    int references;  /*number of times free should be called for complete free*/
    wolfSSL_Mutex    refMutex; /* ref count mutex */

    union {
        char* ptr; /* der format of key / or raw for NTRU */
    } pkey;
    #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    #ifndef NO_RSA
        WOLFSSL_RSA* rsa;
        byte      ownRsa; /* if struct owns RSA and should free it */
    #endif
    #ifndef NO_DSA
        WOLFSSL_DSA* dsa;
        byte      ownDsa; /* if struct owns DSA and should free it */
    #endif
    #ifdef HAVE_ECC
        WOLFSSL_EC_KEY* ecc;
        byte      ownEcc; /* if struct owns ECC and should free it */
    #endif
    #ifndef NO_DH
        WOLFSSL_DH* dh;
        byte      ownDh; /* if struct owns DH and should free it */
    #endif
    WC_RNG rng;
    #endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
    #ifdef HAVE_ECC
        int pkey_curve;
    #endif
};

/* Digest types */

#ifndef NO_MD4
struct WOLFSSL_MD4_CTX {
    int buffer[32];      /* big enough to hold, check size in Init */
};
#endif

#ifndef NO_MD5
struct WOLFSSL_MD5_CTX {
    /* big enough to hold wolfcrypt md5, but check on init */
#ifdef STM32_HASH
    void* holder[(112 + WC_ASYNC_DEV_SIZE + sizeof(STM32_HASH_Context)) / sizeof(void*)];
#else
    void* holder[(112 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
#endif
};
#endif

struct WOLFSSL_SHA_CTX {
    /* big enough to hold wolfcrypt Sha, but check on init */
#if defined(STM32_HASH)
    void* holder[(112 + WC_ASYNC_DEV_SIZE + sizeof(STM32_HASH_Context)) / sizeof(void*)];
#else
    void* holder[(112 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
#endif
    #ifdef WOLF_CRYPTO_CB
    void* cryptocb_holder[(sizeof(int) + sizeof(void*) + 4) / sizeof(void*)];
    #endif
};
enum {
    SHA_DIGEST_LENGTH = 20
};

#ifdef WOLFSSL_SHA224
/* Using ALIGN16 because when AES-NI is enabled digest and buffer in Sha256
 * struct are 16 byte aligned. Any dereference to those elements after casting
 * to Sha224, is expected to also be 16 byte aligned addresses.  */
struct WOLFSSL_SHA224_CTX {
    /* big enough to hold wolfcrypt Sha224, but check on init */
    ALIGN16 void* holder[(272 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
};
enum {
    SHA224_DIGEST_LENGTH = 28
};
#endif /* WOLFSSL_SHA224 */
/* Using ALIGN16 because when AES-NI is enabled digest and buffer in Sha256
 * struct are 16 byte aligned. Any dereference to those elements after casting
 * to Sha256, is expected to also be 16 byte aligned addresses.  */
struct WOLFSSL_SHA256_CTX {
    /* big enough to hold wolfcrypt Sha256, but check on init */
    ALIGN16 void* holder[(272 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
};
enum {
    SHA256_DIGEST_LENGTH = 32
};
#ifdef WOLFSSL_SHA384
struct WOLFSSL_SHA384_CTX {
    /* big enough to hold wolfCrypt Sha384, but check on init */
    void* holder[(256 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
};
enum {
    SHA384_DIGEST_LENGTH = 48
};
#endif /* WOLFSSL_SHA384 */
#ifdef WOLFSSL_SHA512
struct WOLFSSL_SHA512_CTX {
    /* big enough to hold wolfCrypt Sha384, but check on init */
    void* holder[(288 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
};
enum {
    SHA512_DIGEST_LENGTH = 64
};
#endif /* WOLFSSL_SHA512 */

struct WOLFSSL_RIPEMD_CTX {
    int holder[32];   /* big enough to hold wolfcrypt, but check on init */
};

/* Using ALIGN16 because when AES-NI is enabled digest and buffer in Sha3
 * struct are 16 byte aligned. Any dereference to those elements after casting
 * to Sha3 is expected to also be 16 byte aligned addresses.  */
struct WOLFSSL_SHA3_CTX {
    /* big enough to hold wolfcrypt Sha3, but check on init */
    ALIGN16 void* holder[(424 + WC_ASYNC_DEV_SIZE) / sizeof(void*)];
};

#ifndef WOLFSSL_NOSHA3_224
enum {
    SHA3_224_DIGEST_LENGTH = 28
};
#endif /* WOLFSSL_NOSHA3_224 */

#ifndef WOLFSSL_NOSHA3_256
enum {
    SHA3_256_DIGEST_LENGTH = 32
};
#endif /* WOLFSSL_NOSHA3_256 */

enum {
    SHA3_384_DIGEST_LENGTH = 48
};
#ifndef WOLFSSL_NOSHA3_512
enum {
    SHA3_512_DIGEST_LENGTH = 64
};
#endif /* WOLFSSL_NOSHA3_512 */

typedef union {
    #ifndef NO_MD4
        WOLFSSL_MD4_CTX    md4;
    #endif
    #ifndef NO_MD5
        WOLFSSL_MD5_CTX    md5;
    #endif
    WOLFSSL_SHA_CTX    sha;
    #ifdef WOLFSSL_SHA224
        WOLFSSL_SHA224_CTX sha224;
    #endif
    WOLFSSL_SHA256_CTX sha256;
    #ifdef WOLFSSL_SHA384
        WOLFSSL_SHA384_CTX sha384;
    #endif
    #ifdef WOLFSSL_SHA512
        WOLFSSL_SHA512_CTX sha512;
    #endif
    #ifdef WOLFSSL_RIPEMD
        WOLFSSL_RIPEMD_CTX ripemd;
    #endif
    #ifndef WOLFSSL_NOSHA3_224
        WOLFSSL_SHA3_224_CTX sha3_224;
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        WOLFSSL_SHA3_256_CTX sha3_256;
    #endif
        WOLFSSL_SHA3_384_CTX sha3_384;
    #ifndef WOLFSSL_NOSHA3_512
        WOLFSSL_SHA3_512_CTX sha3_512;
    #endif
} WOLFSSL_Hasher;

typedef struct WOLFSSL_EVP_PKEY_CTX WOLFSSL_EVP_PKEY_CTX;
typedef struct WOLFSSL_EVP_CIPHER_CTX WOLFSSL_EVP_CIPHER_CTX;

struct WOLFSSL_EVP_MD_CTX {
    union {
        WOLFSSL_Hasher digest;
    #ifndef NO_HMAC
        Hmac hmac;
    #endif
    } hash;
    enum wc_HashType macType;
    WOLFSSL_EVP_PKEY_CTX *pctx;
#ifndef NO_HMAC
    unsigned int isHMAC;
#endif
};


typedef union {
#ifndef NO_AES
    Aes  aes;
#ifdef WOLFSSL_AES_XTS
    XtsAes xts;
#endif
#endif
#ifndef NO_DES3
    Des  des;
    Des3 des3;
#endif
    Arc4 arc4;
#ifdef HAVE_IDEA
    Idea idea;
#endif
#ifdef WOLFSSL_QT
    int (*ctrl) (WOLFSSL_EVP_CIPHER_CTX *, int type, int arg, void *ptr);
#endif
} WOLFSSL_Cipher;

typedef struct WOLFSSL_EVP_PKEY WOLFSSL_PKCS8_PRIV_KEY_INFO;
#ifndef WOLFSSL_EVP_TYPE_DEFINED /* guard on redeclaration */
typedef char WOLFSSL_EVP_CIPHER;
typedef struct WOLFSSL_EVP_PKEY     WOLFSSL_EVP_PKEY;
typedef struct WOLFSSL_EVP_MD_CTX   WOLFSSL_EVP_MD_CTX;
typedef char   WOLFSSL_EVP_MD;

typedef WOLFSSL_EVP_MD         EVP_MD;
typedef WOLFSSL_EVP_CIPHER     EVP_CIPHER;
typedef WOLFSSL_EVP_MD_CTX     EVP_MD_CTX;
typedef WOLFSSL_EVP_CIPHER_CTX EVP_CIPHER_CTX;

typedef WOLFSSL_EVP_PKEY       EVP_PKEY;
typedef WOLFSSL_EVP_PKEY       PKCS8_PRIV_KEY_INFO;
#define WOLFSSL_EVP_TYPE_DEFINED
#endif

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

#define WOLFSSL_EVP_PKEY_DEFAULT EVP_PKEY_RSA /* default key type */

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

struct WOLFSSL_BIGNUM {
    int neg;        /* openssh deference */
    void *internal; /* our big num */
#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    sp_int fp;
#elif defined(USE_FAST_MATH) && !defined(HAVE_WOLF_BIGINT)
    fp_int fp;
#endif
};

struct WOLFSSL_RSA_METHOD {
    int flags;
    char *name;
};
typedef WOLFSSL_RSA_METHOD                   RSA_METHOD;

#ifndef WOLFSSL_RSA_TYPE_DEFINED /* guard on redeclaration */
#define WOLFSSL_RSA_TYPE_DEFINED
struct WOLFSSL_RSA {
#ifdef WC_RSA_BLINDING
    WC_RNG* rng;              /* for PrivateDecrypt blinding */
#endif
    WOLFSSL_BIGNUM* n;
    WOLFSSL_BIGNUM* e;
    WOLFSSL_BIGNUM* d;
    WOLFSSL_BIGNUM* p;
    WOLFSSL_BIGNUM* q;
    WOLFSSL_BIGNUM* dmp1;      /* dP */
    WOLFSSL_BIGNUM* dmq1;      /* dQ */
    WOLFSSL_BIGNUM* iqmp;      /* u */
    void*          heap;
    void*          internal;  /* our RSA */
    char           inSet;     /* internal set from external ? */
    char           exSet;     /* external set from internal ? */
    char           ownRng;    /* flag for if the rng should be free'd */
#if defined(OPENSSL_EXTRA)
    WOLFSSL_RSA_METHOD* meth;
#endif
#if defined(HAVE_EX_DATA)
    WOLFSSL_CRYPTO_EX_DATA ex_data;  /* external data */
#endif
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
    wolfSSL_Mutex    refMutex;                       /* ref count mutex */
    int              refCount;                       /* reference count */
#endif
};
#endif
typedef WOLFSSL_RSA                          RSA;

enum BIO_TYPE {
    WOLFSSL_BIO_BUFFER = 1,
    WOLFSSL_BIO_SOCKET = 2,
    WOLFSSL_BIO_SSL    = 3,
    WOLFSSL_BIO_MEMORY = 4,
    WOLFSSL_BIO_BIO    = 5,
    WOLFSSL_BIO_FILE   = 6,
    WOLFSSL_BIO_BASE64 = 7,
    WOLFSSL_BIO_MD     = 8
};

enum BIO_FLAGS {
    WOLFSSL_BIO_FLAG_BASE64_NO_NL = 0x01,
    WOLFSSL_BIO_FLAG_READ         = 0x02,
    WOLFSSL_BIO_FLAG_WRITE        = 0x04,
    WOLFSSL_BIO_FLAG_IO_SPECIAL   = 0x08,
    WOLFSSL_BIO_FLAG_RETRY        = 0x10
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

typedef struct WOLFSSL_BUF_MEM {
    char*  data;   /* dereferenced */
    size_t length; /* current length */
    size_t max;    /* maximum length */
} WOLFSSL_BUF_MEM;

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

/* wolfSSL BIO type */
typedef long (*wolf_bio_info_cb)(WOLFSSL_BIO *bio, int event, const char *parg,
                                 int iarg, long larg, long return_value);

struct WOLFSSL_BIO {
    WOLFSSL_BUF_MEM* mem_buf;
    WOLFSSL_BIO_METHOD* method;
    WOLFSSL_BIO* prev;          /* previous in chain */
    WOLFSSL_BIO* next;          /* next in chain */
    WOLFSSL_BIO* pair;          /* BIO paired with */
    void*        heap;          /* user heap hint */
    void*        ptr;           /* WOLFSSL, file descriptor, MD, or mem buf */
    void*        usrCtx;        /* user set pointer */
    const char*  ip;            /* IP address for wolfIO_TcpConnect */
    word16       port;          /* Port for wolfIO_TcpConnect */
    char*        infoArg;       /* BIO callback argument */
    wolf_bio_info_cb infoCb;    /* BIO callback */
    int          wrSz;          /* write buffer size (mem) */
    int          wrIdx;         /* current index for write buffer */
    int          rdIdx;         /* current read index */
    int          readRq;        /* read request */
    int          num;           /* socket num or length */
    int          eof;           /* eof flag */
    int          flags;
    byte         type;          /* method type */
    byte         init:1;        /* bio has been initialized */
    byte         shutdown:1;    /* close flag */
#ifdef HAVE_EX_DATA
    WOLFSSL_CRYPTO_EX_DATA ex_data;
#endif
};

typedef struct WOLFSSL_COMP_METHOD {
    int type;            /* stunnel dereference */
} WOLFSSL_COMP_METHOD;

typedef struct WOLFSSL_COMP {
    int id;
    const char *name;
    WOLFSSL_COMP_METHOD *method;
} WOLFSSL_COMP;


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
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    int                   isDynamic;
    WOLFSSL_X509_VERIFY_PARAM* param;    /* certificate validation parameter */
#endif
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    WOLFSSL_X509_STORE_CTX_verify_cb verify_cb;
#endif
#ifdef HAVE_EX_DATA
    WOLFSSL_CRYPTO_EX_DATA ex_data;
#endif
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && defined(HAVE_CRL)
    WOLFSSL_X509_CRL *crl; /* points to cm->crl */
#endif
};

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_WPAS_SMALL) || defined(WOLFSSL_IP_ALT_NAME)
    #define WOLFSSL_MAX_IPSTR 46 /* max ip size IPv4 mapped IPv6 */
#endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */


#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
#define WOLFSSL_USE_CHECK_TIME 0x2
#define WOLFSSL_NO_CHECK_TIME  0x200000
#define WOLFSSL_HOST_NAME_MAX  256

#define WOLFSSL_VPARAM_DEFAULT          0x1
#define WOLFSSL_VPARAM_OVERWRITE        0x2
#define WOLFSSL_VPARAM_RESET_FLAGS      0x4
#define WOLFSSL_VPARAM_LOCKED           0x8
#define WOLFSSL_VPARAM_ONCE             0x10

struct WOLFSSL_X509_VERIFY_PARAM {
    time_t         check_time;
    unsigned int   inherit_flags;
    unsigned long  flags;
    char           hostName[WOLFSSL_HOST_NAME_MAX];
    unsigned int  hostFlags;
    char ipasc[WOLFSSL_MAX_IPSTR];
};
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */


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

struct WOLFSSL_X509_STORE_CTX {
    WOLFSSL_X509_STORE* store;    /* Store full of a CA cert chain */
    WOLFSSL_X509* current_cert;   /* current X509 (OPENSSL_EXTRA) */
#ifdef WOLFSSL_ASIO
    WOLFSSL_X509* current_issuer; /* asio dereference */
#endif
    WOLFSSL_X509_CHAIN* sesChain; /* pointer to WOLFSSL_SESSION peer chain */
    WOLFSSL_STACK* chain;
#ifdef OPENSSL_EXTRA
    WOLFSSL_X509_VERIFY_PARAM* param; /* certificate validation parameter */
#endif
    char* domain;                /* subject CN domain name */
#if defined(HAVE_EX_DATA) || defined(FORTRESS)
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
};

typedef char* WOLFSSL_STRING;

/* Valid Alert types from page 16/17
 * Add alert string to the function wolfSSL_alert_type_string_long in src/ssl.c
 */
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
    unknown_ca                      =  48,
    decode_error                    =  50,
    decrypt_error                   =  51,
    #ifdef WOLFSSL_MYSQL_COMPATIBLE
    /* catch name conflict for enum protocol with MYSQL build */
    wc_protocol_version             =  70,
    #else
    protocol_version                =  70,
    #endif
    inappropriate_fallback          =  86,
    no_renegotiation                = 100,
    missing_extension               = 109,
    unsupported_extension           = 110, /**< RFC 5246, section 7.2.2 */
    unrecognized_name               = 112, /**< RFC 6066, section 3 */
    bad_certificate_status_response = 113, /**< RFC 6066, section 8 */
    unknown_psk_identity            = 115, /**< RFC 4279, section 2 */
    certificate_required            = 116, /**< RFC 8446, section 8.2 */
    no_application_protocol         = 120
};


enum AlertLevel {
    alert_warning = 1,
    alert_fatal   = 2
};

/* WS_RETURN_CODE macro
 * Some OpenSSL APIs specify "0" as the return value when an error occurs.
 * However, some corresponding wolfSSL APIs　return negative values. Such
 * functions should use this macro to fill this gap. Users who want them
 * to return the same return value as OpenSSL can define
 * WOLFSSL_ERR_CODE_OPENSSL.
 * Give item1 a variable that contains the potentially negative
 * wolfSSL-defined return value or the return value itself, and
 * give item2 the openSSL-defined return value.
 * Note that this macro replaces only negative return values with the
 * specified value.
 * Since wolfSSL 4.7.0, the following functions use this macro:
 * - wolfSSL_CTX_load_verify_locations
 * - wolfSSL_X509_LOOKUP_load_file
 */
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    #define WS_RETURN_CODE(item1,item2) \
      ((item1 < 0) ? item2 : item1)
#else
    #define WS_RETURN_CODE(item1,item2)  (item1)
#endif

/* Maximum master key length (SECRET_LEN) */
#define WOLFSSL_MAX_MASTER_KEY_LENGTH 48
/* Maximum number of groups that can be set */
#define WOLFSSL_MAX_GROUP_COUNT       10

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

typedef WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);


#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Smaller subset of X509 compatibility functions. Avoid increasing the size of
 * this subset and its memory usage */

struct WOLFSSL_X509_NAME_ENTRY {
    WOLFSSL_ASN1_OBJECT* object;  /* static object just for keeping grp, type */
    WOLFSSL_ASN1_STRING* value;  /* points to data, for lighttpd port */
    int nid; /* i.e. ASN_COMMON_NAME */
    int set;
    int size;
};

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
#endif /* OPENSSL_ALL || OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(OPENSSL_EXTRA_X509_SMALL)
struct WOLFSSL_ASN1_BIT_STRING {
    int length;
    int type;
    byte* data;
    long flags;
};
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || OPENSSL_EXTRA_X509_SMALL */


/* These are bit-masks */
enum {
    WOLFSSL_OCSP_URL_OVERRIDE = 1,
    WOLFSSL_OCSP_NO_NONCE     = 2,
    WOLFSSL_OCSP_CHECKALL     = 4,

    WOLFSSL_CRL_CHECKALL = 1,
    WOLFSSL_CRL_CHECK    = 2,
};

/* Separated out from other enums because of size */
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
    SSL_OP_EPHEMERAL_RSA                          = 0x00000800,
    WOLFSSL_OP_NO_SSLv3                           = 0x00001000,
    WOLFSSL_OP_NO_TLSv1                           = 0x00002000,
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
    WOLFSSL_OP_NO_TLSv1_1                         = 0x04000000,
    WOLFSSL_OP_NO_TLSv1_2                         = 0x08000000,
    SSL_OP_NO_COMPRESSION                         = 0x10000000,
    WOLFSSL_OP_NO_TLSv1_3                         = 0x20000000,
    WOLFSSL_OP_NO_SSLv2                           = 0x40000000,
    SSL_OP_ALL   =
                    (SSL_OP_MICROSOFT_SESS_ID_BUG
                  | SSL_OP_NETSCAPE_CHALLENGE_BUG
                  | SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
                  | SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
                  | SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
                  | SSL_OP_MSIE_SSLV2_RSA_PADDING
                  | SSL_OP_SSLEAY_080_CLIENT_DH_BUG
                  | SSL_OP_TLS_D5_BUG
                  | SSL_OP_TLS_BLOCK_PADDING_BUG
                  | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
                  | SSL_OP_TLS_ROLLBACK_BUG),
};


#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_WEBSERVER)
/* for compatibility these must be macros */
#define SSL_OP_NO_SSLv2   WOLFSSL_OP_NO_SSLv2
#define SSL_OP_NO_SSLv3   WOLFSSL_OP_NO_SSLv3
#define SSL_OP_NO_TLSv1   WOLFSSL_OP_NO_TLSv1
#define SSL_OP_NO_TLSv1_1 WOLFSSL_OP_NO_TLSv1_1
#define SSL_OP_NO_TLSv1_2 WOLFSSL_OP_NO_TLSv1_2
#if !(!defined(WOLFSSL_TLS13) && defined(WOLFSSL_APACHE_HTTPD)) /* apache uses this to determine if TLS 1.3 is enabled */
#define SSL_OP_NO_TLSv1_3 WOLFSSL_OP_NO_TLSv1_3
#endif

#define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | \
    SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3)

#define SSL_NOTHING 1
#define SSL_WRITING 2
#define SSL_READING 3

enum {
#ifdef HAVE_OCSP
    /* OCSP Flags */
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

    /* OCSP Types */
    OCSP_CERTID   = 2,
    OCSP_REQUEST  = 4,
    OCSP_RESPONSE = 8,
    OCSP_BASICRESP = 16,
#endif

    ASN1_GENERALIZEDTIME = 4,
    SSL_MAX_SSL_SESSION_ID_LENGTH = 32,

    SSL_ST_CONNECT = 0x1000,
    SSL_ST_ACCEPT  = 0x2000,
    SSL_ST_MASK    = 0x0FFF,

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
    SSL_CB_MODE_READ = 1,
    SSL_CB_MODE_WRITE = 2,

    SSL_MODE_ENABLE_PARTIAL_WRITE = 2,
    SSL_MODE_AUTO_RETRY = 3, /* wolfSSL default is to block with blocking io
                              * and auto retry */
    SSL_MODE_RELEASE_BUFFERS = -1, /* For libwebsockets build. No current use. */

    BIO_CLOSE   = 1,
    BIO_NOCLOSE = 0,

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
    X509_V_ERR_APPLICATION_VERIFICATION,

    X509_R_CERT_ALREADY_IN_HASH_TABLE,

    CRYPTO_LOCK = 1,
    CRYPTO_NUM_LOCKS = 10,

    ASN1_STRFLGS_ESC_MSB = 4
};
#endif

enum { /* ssl Constants */
    WOLFSSL_ERROR_NONE      =  0,   /* for most functions */
    WOLFSSL_FAILURE         =  0,   /* for some functions */
    WOLFSSL_SUCCESS         =  1,
    WOLFSSL_SHUTDOWN_NOT_DONE =  2,  /* call wolfSSL_shutdown again to complete */

    WOLFSSL_ALPN_NOT_FOUND  = -9,
    WOLFSSL_BAD_CERTTYPE    = -8,
    WOLFSSL_BAD_STAT        = -7,
    WOLFSSL_BAD_PATH        = -6,
    WOLFSSL_BAD_FILETYPE    = -5,
    WOLFSSL_BAD_FILE        = -4,
    WOLFSSL_NOT_IMPLEMENTED = -3,
    WOLFSSL_UNKNOWN         = -2,
    WOLFSSL_FATAL_ERROR     = -1,

    WOLFSSL_FILETYPE_ASN1    = 2,
    WOLFSSL_FILETYPE_PEM     = 1,
    WOLFSSL_FILETYPE_DEFAULT = 2, /* ASN1 */
    WOLFSSL_FILETYPE_RAW     = 3, /* NTRU raw key blob */

    WOLFSSL_VERIFY_NONE                 = 0,
    WOLFSSL_VERIFY_PEER                 = 1,
    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    WOLFSSL_VERIFY_CLIENT_ONCE          = 4,
    WOLFSSL_VERIFY_FAIL_EXCEPT_PSK      = 8,

    WOLFSSL_SESS_CACHE_OFF                = 0x0000,
    WOLFSSL_SESS_CACHE_CLIENT             = 0x0001,
    WOLFSSL_SESS_CACHE_SERVER             = 0x0002,
    WOLFSSL_SESS_CACHE_BOTH               = 0x0003,
    WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR      = 0x0008,
    WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100,
    WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE  = 0x0200,
    WOLFSSL_SESS_CACHE_NO_INTERNAL        = 0x0300,

    WOLFSSL_ERROR_WANT_READ        =  2,
    WOLFSSL_ERROR_WANT_WRITE       =  3,
    WOLFSSL_ERROR_WANT_CONNECT     =  7,
    WOLFSSL_ERROR_WANT_ACCEPT      =  8,
    WOLFSSL_ERROR_SYSCALL          =  5,
    WOLFSSL_ERROR_WANT_X509_LOOKUP = 83,
    WOLFSSL_ERROR_ZERO_RETURN      =  6,
    WOLFSSL_ERROR_SSL              = 85,

    WOLFSSL_SENT_SHUTDOWN     = 1,
    WOLFSSL_RECEIVED_SHUTDOWN = 2,
    WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4,

    WOLFSSL_R_SSL_HANDSHAKE_FAILURE           = 101,
    WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102,
    WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103,
    WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104,

    WOLF_PEM_BUFSIZE = 1024
};


/* extra begins */
#ifdef OPENSSL_EXTRA
enum {  /* ERR Constants */
    ERR_TXT_STRING = 1
};

/* bio misc */
enum {
    WOLFSSL_BIO_ERROR = -1,
    WOLFSSL_BIO_UNSET = -2,
    WOLFSSL_BIO_SIZE  = 17000 /* default BIO write size if not set */
};
#endif


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
    WOLFSSL_TLSV1_3  = 4,
    WOLFSSL_USER_CA  = 1,          /* user added as trusted */
    WOLFSSL_CHAIN_CA = 2           /* added to cache from trusted chain */
};

typedef void (*CallbackCACache)(unsigned char* der, int sz, int type);
typedef void (*CbMissingCRL)(const char* url);
typedef int  (*CbOCSPIO)(void*, const char*, int,
                                         unsigned char*, int, unsigned char**);
typedef void (*CbOCSPRespFree)(void*,unsigned char*);

#ifdef HAVE_CRL_IO
typedef int  (*CbCrlIO)(WOLFSSL_CRL* crl, const char* url, int urlSz);
#endif

typedef int (*CallbackMacEncrypt)(WOLFSSL* ssl, unsigned char* macOut,
       const unsigned char* macIn, unsigned int macInSz, int macContent,
       int macVerify, unsigned char* encOut, const unsigned char* encIn,
       unsigned int encSz, void* ctx);
typedef int (*CallbackDecryptVerify)(WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int verify, unsigned int* padSz,
       void* ctx);
typedef int (*CallbackEncryptMac)(WOLFSSL* ssl, unsigned char* macOut,
       int content, int macVerify, unsigned char* encOut,
       const unsigned char* encIn, unsigned int encSz, void* ctx);
typedef int (*CallbackVerifyDecrypt)(WOLFSSL* ssl,
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int verify, unsigned int* padSz,
       void* ctx);


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
#ifdef HAVE_IDEA
    wolfssl_idea,
#endif
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
    wolfssl_sha256 = 4,     /* needs to match hash.h wc_MACAlgorithm */
    wolfssl_sha384,
    wolfssl_sha512
};


/* Server Name Indication */
#ifdef HAVE_SNI

/* SNI types */
enum {
    WOLFSSL_SNI_HOST_NAME = 0
};

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
#endif /* NO_WOLFSSL_SERVER */

/* SNI status */
enum {
    WOLFSSL_SNI_NO_MATCH   = 0,
    WOLFSSL_SNI_FAKE_MATCH = 1, /**< @see WOLFSSL_SNI_ANSWER_ON_MISMATCH */
    WOLFSSL_SNI_REAL_MATCH = 2,
    WOLFSSL_SNI_FORCE_KEEP = 3  /** Used with -DWOLFSSL_ALWAYS_KEEP_SNI */
};

/* SNI received callback type */
typedef int (*CallbackSniRecv)(WOLFSSL *ssl, int *ret, void* exArg);

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
#endif /* HAVE_TRUSTED_CA */


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

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY)
typedef int (*CallbackALPNSelect)(WOLFSSL* ssl, const unsigned char** out,
    unsigned char* outLen, const unsigned char* in, unsigned int inLen,
    void *arg);
#endif
#endif /* HAVE_ALPN */


/* Maximum Fragment Length */
#ifdef HAVE_MAX_FRAGMENT

/* Fragment lengths */
enum {
    WOLFSSL_MFL_2_9  = 1, /*  512 bytes */
    WOLFSSL_MFL_2_10 = 2, /* 1024 bytes */
    WOLFSSL_MFL_2_11 = 3, /* 2048 bytes */
    WOLFSSL_MFL_2_12 = 4, /* 4096 bytes */
    WOLFSSL_MFL_2_13 = 5, /* 8192 bytes *//* wolfSSL ONLY!!! */
    WOLFSSL_MFL_2_8  = 6, /*  256 bytes *//* wolfSSL ONLY!!! */
    WOLFSSL_MFL_MIN  = WOLFSSL_MFL_2_9,
    WOLFSSL_MFL_MAX  = WOLFSSL_MFL_2_8,
};
#endif /* HAVE_MAX_FRAGMENT */

/* Certificate Status Request */
/* Certificate Status Type */
enum {
    WOLFSSL_CSR_OCSP = 1
};

/* Certificate Status Options (flags) */
enum {
    WOLFSSL_CSR_OCSP_USE_NONCE = 0x01
};

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
    WOLFSSL_ECC_X448      = 30,
    WOLFSSL_ECC_MAX       = 30,

    WOLFSSL_FFDHE_2048    = 256,
    WOLFSSL_FFDHE_3072    = 257,
    WOLFSSL_FFDHE_4096    = 258,
    WOLFSSL_FFDHE_6144    = 259,
    WOLFSSL_FFDHE_8192    = 260,
};

enum {
    WOLFSSL_EC_PF_UNCOMPRESSED = 0,
#if 0 /* Not Supported */
    WOLFSSL_EC_PF_X962_COMP_PRIME = 1,
    WOLFSSL_EC_PF_X962_COMP_CHAR2 = 2,
#endif
};

/* Session Ticket */
#ifdef HAVE_SESSION_TICKET

#if !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && !defined(WOLFSSL_NO_SERVER)
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
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
typedef int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*);
#endif /* NO_WOLFSSL_CLIENT */

#define WOLFSSL_TICKET_NAME_SZ 16
#define WOLFSSL_TICKET_IV_SZ   16
#define WOLFSSL_TICKET_MAC_SZ  32

enum TicketEncRet {
    WOLFSSL_TICKET_RET_FATAL  = -1,  /* fatal error, don't use ticket */
    WOLFSSL_TICKET_RET_OK     =  0,  /* ok, use ticket */
    WOLFSSL_TICKET_RET_REJECT,       /* don't use ticket, but not fatal */
    WOLFSSL_TICKET_RET_CREATE        /* existing ticket ok and create new one */
};

#ifndef NO_WOLFSSL_SERVER
typedef int (*SessionTicketEncCb)(WOLFSSL*,
                                 unsigned char key_name[WOLFSSL_TICKET_NAME_SZ],
                                 unsigned char iv[WOLFSSL_TICKET_IV_SZ],
                                 unsigned char mac[WOLFSSL_TICKET_MAC_SZ],
                                 int enc, unsigned char*, int, int*, void*);
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
#endif /* QSH */

typedef int (*HandShakeDoneCb)(WOLFSSL*, void*);

#ifdef WOLFSSL_CALLBACKS
typedef int (*HandShakeCallBack)(HandShakeInfo*);
typedef int (*TimeoutCallBack)(TimeoutInfo*);
#endif /* WOLFSSL_CALLBACKS */

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)
typedef int (*wolf_sk_compare_cb)(const void* a,
                                  const void* b);
typedef unsigned long (*wolf_sk_hash_cb) (const void *v);
#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || HAVE_LIGHTY */


#ifdef OPENSSL_EXTRA
typedef void (*SSL_Msg_Cb)(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg);
#endif



#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif /* WOLFSSL_SSL_TYPES_H_ */
