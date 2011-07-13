/* ssl.h
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
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


/*  ssl.h defines openssl compatibility layer 
 *
 */



#ifndef CYASSL_OPENSSL_H_
#define CYASSL_OPENSSL_H_

#include "ctc_settings.h"   /* for users not using preprocessor flags */

#ifndef NO_FILESYSTEM
    #include <stdio.h>   /* ERR_print fp */
#endif

#ifdef YASSL_PREFIX
    #include "prefix_ssl.h"
#endif

#define CYASSL_VERSION "2.0.0rc2"

#ifdef _WIN32
    /* wincrypt.h clashes */
    #undef X509_NAME
    #undef OCSP_REQUEST 
    #undef OCSP_RESPONSE
#endif

#ifdef __cplusplus
    extern "C" {
#endif



typedef struct SSL          SSL;          
typedef struct SSL_SESSION  SSL_SESSION;
typedef struct SSL_METHOD   SSL_METHOD;
typedef struct SSL_CTX      SSL_CTX;

typedef struct X509       X509;
typedef struct X509_NAME  X509_NAME;
typedef struct X509_CHAIN X509_CHAIN;


/* redeclare guard */
#define SSL_TYPES_DEFINED




typedef struct EVP_PKEY       EVP_PKEY;
typedef struct RSA            RSA;
typedef struct BIO            BIO;
typedef struct BIO_METHOD     BIO_METHOD;
typedef struct SSL_CIPHER     SSL_CIPHER;
typedef struct X509_LOOKUP    X509_LOOKUP;
typedef struct X509_LOOKUP_METHOD X509_LOOKUP_METHOD;
typedef struct X509_CRL       X509_CRL;
typedef struct X509_EXTENSION X509_EXTENSION;
typedef struct ASN1_TIME      ASN1_TIME;
typedef struct ASN1_INTEGER   ASN1_INTEGER;
typedef struct ASN1_OBJECT    ASN1_OBJECT;
typedef struct ASN1_STRING    ASN1_STRING;
typedef struct CRYPTO_dynlock_value CRYPTO_dynlock_value;

#define ASN1_UTCTIME ASN1_TIME

typedef struct MD4_CTX {
    int buffer[32];      /* big enough to hold, check size in Init */
} MD4_CTX;


typedef struct COMP_METHOD {
    int type;            /* stunnel dereference */
} COMP_METHOD;


typedef struct X509_STORE {
    int cache;          /* stunnel dereference */
} X509_STORE;


typedef struct X509_REVOKED {
    ASN1_INTEGER* serialNumber;          /* stunnel dereference */
} X509_REVOKED;


typedef struct X509_OBJECT {
    union {
        char* ptr;
        X509_CRL* crl;           /* stunnel dereference */
    } data;
} X509_OBJECT;


/* in cyassl_int.h too, change there !! */
typedef struct X509_STORE_CTX {
    int   error;
    int   error_depth;
    X509* current_cert;          /* stunnel dereference */
    char* domain;                /* subject CN domain name */
    /* in cyassl_int.h too, change there !! */
} X509_STORE_CTX;


CYASSL_API SSL_METHOD *SSLv3_server_method(void);
CYASSL_API SSL_METHOD *SSLv3_client_method(void);
CYASSL_API SSL_METHOD *TLSv1_server_method(void);  
CYASSL_API SSL_METHOD *TLSv1_client_method(void);
CYASSL_API SSL_METHOD *TLSv1_1_server_method(void);  
CYASSL_API SSL_METHOD *TLSv1_1_client_method(void);
CYASSL_API SSL_METHOD *TLSv1_2_server_method(void);  
CYASSL_API SSL_METHOD *TLSv1_2_client_method(void);

#ifdef CYASSL_DTLS
    CYASSL_API SSL_METHOD *DTLSv1_client_method(void);
    CYASSL_API SSL_METHOD *DTLSv1_server_method(void);
#endif

#ifndef NO_FILESYSTEM

CYASSL_API int SSL_CTX_use_certificate_file(SSL_CTX*, const char*, int);
CYASSL_API int SSL_CTX_use_PrivateKey_file(SSL_CTX*, const char*, int);
CYASSL_API int SSL_CTX_load_verify_locations(SSL_CTX*, const char*,const char*);
CYASSL_API int SSL_CTX_use_certificate_chain_file(SSL_CTX *, const char *file);
CYASSL_API int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX*, const char*, int);

#ifdef CYASSL_DER_LOAD
    CYASSL_API int CyaSSL_CTX_load_verify_locations(SSL_CTX*, const char*, int);
#endif

#ifdef HAVE_NTRU
    CYASSL_API int CyaSSL_CTX_use_NTRUPrivateKey_file(SSL_CTX*, const char*);
    /* load NTRU private key blob */
#endif

CYASSL_API int CyaSSL_PemCertToDer(const char*, unsigned char*, int);

#endif /* NO_FILESYSTEM */

CYASSL_API SSL_CTX* SSL_CTX_new(SSL_METHOD*);
CYASSL_API SSL* SSL_new(SSL_CTX*);
CYASSL_API int  SSL_set_fd (SSL*, int);
CYASSL_API int  SSL_get_fd(const SSL*);
CYASSL_API int  SSL_connect(SSL*);           /* please see note at top of README
                                             if you get an error from connect */
CYASSL_API int  SSL_write(SSL*, const void*, int);
CYASSL_API int  SSL_read(SSL*, void*, int);
CYASSL_API int  SSL_accept(SSL*);
CYASSL_API void SSL_CTX_free(SSL_CTX*);
CYASSL_API void SSL_free(SSL*);
CYASSL_API int  SSL_shutdown(SSL*);

CYASSL_API void SSL_CTX_set_quiet_shutdown(SSL_CTX*, int);

CYASSL_API int  SSL_get_error(SSL*, int);

CYASSL_API int          SSL_set_session(SSL *ssl, SSL_SESSION *session);
CYASSL_API SSL_SESSION* SSL_get_session(SSL* ssl);
CYASSL_API void         SSL_flush_sessions(SSL_CTX *ctx, long tm);


typedef int (*VerifyCallback)(int, X509_STORE_CTX*);
typedef int (*pem_password_cb)(char*, int, int, void*);

CYASSL_API void SSL_CTX_set_verify(SSL_CTX*,int,VerifyCallback verify_callback);


CYASSL_API int  SSL_pending(SSL*);


CYASSL_API void SSL_load_error_strings(void);
CYASSL_API int  SSL_library_init(void);
CYASSL_API long SSL_CTX_set_session_cache_mode(SSL_CTX*, long);

/* only supports full name from cipher_name[] delimited by : */
CYASSL_API int  SSL_CTX_set_cipher_list(SSL_CTX*, const char*);

CYASSL_API char* ERR_error_string(unsigned long,char*);
CYASSL_API void  ERR_error_string_n(unsigned long e,char *buf,unsigned long sz);


/* extras */

#define STACK_OF(x) x

CYASSL_API int  SSL_set_ex_data(SSL*, int, void*);
CYASSL_API int  SSL_get_shutdown(const SSL*);
CYASSL_API int  SSL_set_rfd(SSL*, int);
CYASSL_API int  SSL_set_wfd(SSL*, int);
CYASSL_API void SSL_set_shutdown(SSL*, int);
CYASSL_API int  SSL_set_session_id_context(SSL*, const unsigned char*,
                                           unsigned int);
CYASSL_API void SSL_set_connect_state(SSL*);
CYASSL_API void SSL_set_accept_state(SSL*);
CYASSL_API int  SSL_session_reused(SSL*);
CYASSL_API void SSL_SESSION_free(SSL_SESSION* session);

CYASSL_API const char*  SSL_get_version(SSL*);
CYASSL_API SSL_CIPHER*  SSL_get_current_cipher(SSL*);
CYASSL_API char*        SSL_CIPHER_description(SSL_CIPHER*, char*, int);
CYASSL_API const char*  SSL_CIPHER_get_name(const SSL_CIPHER* cipher);
CYASSL_API SSL_SESSION* SSL_get1_session(SSL* ssl);  /* what's ref count */

CYASSL_API void X509_free(X509*);
CYASSL_API void OPENSSL_free(void*);

CYASSL_API int OCSP_parse_url(char* url, char** host, char** port, char** path,
                              int* ssl);

CYASSL_API SSL_METHOD* SSLv23_client_method(void);
CYASSL_API SSL_METHOD* SSLv2_client_method(void);
CYASSL_API SSL_METHOD* SSLv2_server_method(void);

CYASSL_API void MD4_Init(MD4_CTX*);
CYASSL_API void MD4_Update(MD4_CTX*, const void*, unsigned long);
CYASSL_API void MD4_Final(unsigned char*, MD4_CTX*);

CYASSL_API BIO* BIO_new(BIO_METHOD*);
CYASSL_API int  BIO_free(BIO*);
CYASSL_API int  BIO_free_all(BIO*);
CYASSL_API int  BIO_read(BIO*, void*, int);
CYASSL_API int  BIO_write(BIO*, const void*, int);
CYASSL_API BIO* BIO_push(BIO*, BIO* append);
CYASSL_API BIO* BIO_pop(BIO*);
CYASSL_API int  BIO_flush(BIO*);
CYASSL_API int  BIO_pending(BIO*);

CYASSL_API BIO_METHOD* BIO_f_buffer(void);
CYASSL_API long        BIO_set_write_buffer_size(BIO*, long size);
CYASSL_API BIO_METHOD* BIO_f_ssl(void);
CYASSL_API BIO*        BIO_new_socket(int sfd, int flag);
CYASSL_API void        SSL_set_bio(SSL*, BIO* rd, BIO* wr);
CYASSL_API int         BIO_eof(BIO*);
CYASSL_API long        BIO_set_ssl(BIO*, SSL*, int flag);

CYASSL_API BIO_METHOD* BIO_s_mem(void);
CYASSL_API BIO_METHOD* BIO_f_base64(void);
CYASSL_API void        BIO_set_flags(BIO*, int);

CYASSL_API void OpenSSL_add_all_algorithms(void);
CYASSL_API int  SSLeay_add_ssl_algorithms(void);
CYASSL_API int  SSLeay_add_all_algorithms(void);

CYASSL_API void        RAND_screen(void);
CYASSL_API const char* RAND_file_name(char*, unsigned long);
CYASSL_API int         RAND_write_file(const char*);
CYASSL_API int         RAND_load_file(const char*, long);
CYASSL_API int         RAND_egd(const char*);

CYASSL_API COMP_METHOD* COMP_zlib(void);
CYASSL_API COMP_METHOD* COMP_rle(void);
CYASSL_API int SSL_COMP_add_compression_method(int, void*);

CYASSL_API int SSL_get_ex_new_index(long, void*, void*, void*, void*);

CYASSL_API void CRYPTO_set_id_callback(unsigned long (*f)(void));
CYASSL_API void CRYPTO_set_locking_callback(void (*f)(int, int, const char*,
                                                      int));
CYASSL_API void CRYPTO_set_dynlock_create_callback(CRYPTO_dynlock_value* (*f)
                                                   (const char*, int));
CYASSL_API void CRYPTO_set_dynlock_lock_callback(void (*f)(int,
                                      CRYPTO_dynlock_value*, const char*, int));
CYASSL_API void CRYPTO_set_dynlock_destroy_callback(void (*f)
                                     (CRYPTO_dynlock_value*, const char*, int));
CYASSL_API int  CRYPTO_num_locks(void);

CYASSL_API X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX*);
CYASSL_API int   X509_STORE_CTX_get_error(X509_STORE_CTX*);
CYASSL_API int   X509_STORE_CTX_get_error_depth(X509_STORE_CTX*);

CYASSL_API char*       X509_NAME_oneline(X509_NAME*, char*, int);
CYASSL_API X509_NAME*  X509_get_issuer_name(X509*);
CYASSL_API X509_NAME*  X509_get_subject_name(X509*);
CYASSL_API const char* X509_verify_cert_error_string(long);

CYASSL_API int X509_LOOKUP_add_dir(X509_LOOKUP*, const char*, long);
CYASSL_API int X509_LOOKUP_load_file(X509_LOOKUP*, const char*, long);
CYASSL_API X509_LOOKUP_METHOD* X509_LOOKUP_hash_dir(void);
CYASSL_API X509_LOOKUP_METHOD* X509_LOOKUP_file(void);

CYASSL_API X509_LOOKUP* X509_STORE_add_lookup(X509_STORE*, X509_LOOKUP_METHOD*);
CYASSL_API X509_STORE*  X509_STORE_new(void);
CYASSL_API int          X509_STORE_get_by_subject(X509_STORE_CTX*, int,
                                                  X509_NAME*, X509_OBJECT*);
CYASSL_API int  X509_STORE_CTX_init(X509_STORE_CTX*, X509_STORE*, X509*,
                                    STACK_OF(X509)*);
CYASSL_API void X509_STORE_CTX_cleanup(X509_STORE_CTX*);

CYASSL_API ASN1_TIME* X509_CRL_get_lastUpdate(X509_CRL*);
CYASSL_API ASN1_TIME* X509_CRL_get_nextUpdate(X509_CRL*);

CYASSL_API EVP_PKEY* X509_get_pubkey(X509*);
CYASSL_API int       X509_CRL_verify(X509_CRL*, EVP_PKEY*);
CYASSL_API void      X509_STORE_CTX_set_error(X509_STORE_CTX*, int);
CYASSL_API void      X509_OBJECT_free_contents(X509_OBJECT*);
CYASSL_API void      EVP_PKEY_free(EVP_PKEY*);
CYASSL_API int       X509_cmp_current_time(const ASN1_TIME*);
CYASSL_API int       sk_X509_REVOKED_num(X509_REVOKED*);

CYASSL_API X509_REVOKED* X509_CRL_get_REVOKED(X509_CRL*);
CYASSL_API X509_REVOKED* sk_X509_REVOKED_value(X509_REVOKED*, int);

CYASSL_API ASN1_INTEGER* X509_get_serialNumber(X509*);

CYASSL_API int ASN1_TIME_print(BIO*, const ASN1_TIME*);

CYASSL_API int  ASN1_INTEGER_cmp(const ASN1_INTEGER*, const ASN1_INTEGER*);
CYASSL_API long ASN1_INTEGER_get(const ASN1_INTEGER*);

CYASSL_API STACK_OF(X509_NAME)* SSL_load_client_CA_file(const char*);

CYASSL_API void  SSL_CTX_set_client_CA_list(SSL_CTX*, STACK_OF(X509_NAME)*);
CYASSL_API void* X509_STORE_CTX_get_ex_data(X509_STORE_CTX*, int);
CYASSL_API int   SSL_get_ex_data_X509_STORE_CTX_idx(void);
CYASSL_API void* SSL_get_ex_data(const SSL*, int);

CYASSL_API void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX*,void* userdata);
CYASSL_API void SSL_CTX_set_default_passwd_cb(SSL_CTX*, pem_password_cb);


CYASSL_API long SSL_CTX_set_timeout(SSL_CTX*, long);
CYASSL_API void SSL_CTX_set_info_callback(SSL_CTX*, void (*)(void));

CYASSL_API unsigned long ERR_peek_error(void);
CYASSL_API int           ERR_GET_REASON(int);

CYASSL_API char* SSL_alert_type_string_long(int);
CYASSL_API char* SSL_alert_desc_string_long(int);
CYASSL_API char* SSL_state_string_long(SSL*);

CYASSL_API void RSA_free(RSA*);
CYASSL_API RSA* RSA_generate_key(int, unsigned long, void(*)(int, int, void*),
                                 void*);
CYASSL_API void SSL_CTX_set_tmp_rsa_callback(SSL_CTX*, RSA*(*)(SSL*, int, int));

CYASSL_API int PEM_def_callback(char*, int num, int w, void* key);

CYASSL_API long SSL_CTX_sess_accept(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_connect(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_accept_good(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_connect_good(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_accept_renegotiate(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_connect_renegotiate(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_hits(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_cb_hits(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_cache_full(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_misses(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_timeouts(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_number(SSL_CTX*);
CYASSL_API long SSL_CTX_sess_get_cache_size(SSL_CTX*);


#define SSL_DEFAULT_CIPHER_LIST ""   /* default all */
#define RSA_F4 0x10001L

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

    ASN1_GENERALIZEDTIME = 4,

    SSL_OP_MICROSOFT_SESS_ID_BUG = 1,
    SSL_OP_NETSCAPE_CHALLENGE_BUG = 2,
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 3,
    SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 4,
    SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 5,
    SSL_OP_MSIE_SSLV2_RSA_PADDING = 6,
    SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 7,
    SSL_OP_TLS_D5_BUG = 8,
    SSL_OP_TLS_BLOCK_PADDING_BUG = 9,
    SSL_OP_TLS_ROLLBACK_BUG = 10,
    SSL_OP_ALL = 11,
    SSL_OP_EPHEMERAL_RSA = 12,
    SSL_OP_NO_SSLv3 = 13,
    SSL_OP_NO_TLSv1 = 14,
    SSL_OP_PKCS1_CHECK_1 = 15,
    SSL_OP_PKCS1_CHECK_2 = 16,
    SSL_OP_NETSCAPE_CA_DN_BUG = 17,
    SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 18,
    SSL_OP_SINGLE_DH_USE = 19,
    SSL_OP_NO_TICKET = 20,
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 21,
    SSL_OP_NO_QUERY_MTU = 22,
    SSL_OP_COOKIE_EXCHANGE = 23,
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 24,
    SSL_OP_SINGLE_ECDH_USE = 25,
    SSL_OP_CIPHER_SERVER_PREFERENCE = 26,

    SSL_MAX_SSL_SESSION_ID_LENGTH = 32,

    EVP_R_BAD_DECRYPT = 2,

    SSL_CB_LOOP = 4,
    SSL_ST_CONNECT = 5,
    SSL_ST_ACCEPT  = 6,
    SSL_CB_ALERT   = 7,
    SSL_CB_READ    = 8,
    SSL_CB_HANDSHAKE_DONE = 9,

    SSL_MODE_ENABLE_PARTIAL_WRITE = 2,

    BIO_FLAGS_BASE64_NO_NL = 1,
    BIO_CLOSE   = 1,
    BIO_NOCLOSE = 0,

    NID_undef = 0,

    X509_FILETYPE_PEM = 8,
    X509_LU_X509      = 9,
    X509_LU_CRL       = 12,
    
    X509_V_ERR_CRL_SIGNATURE_FAILURE = 13,
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 14,
    X509_V_ERR_CRL_HAS_EXPIRED                = 15,
    X509_V_ERR_CERT_REVOKED                   = 16,
    X509_V_ERR_CERT_CHAIN_TOO_LONG            = 17,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT      = 18,
    X509_V_ERR_CERT_NOT_YET_VALID             = 19,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 20,
    X509_V_ERR_CERT_HAS_EXPIRED               = 21,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD  = 22,

    X509_V_OK = 0,

    CRYPTO_LOCK = 1,
    CRYPTO_NUM_LOCKS = 10
};

/* extras end */

#ifndef NO_FILESYSTEM
/* CyaSSL extension, provide last error from SSL_get_error
   since not using thread storage error queue */
CYASSL_API void  ERR_print_errors_fp(FILE*, int err);
#endif

enum { /* ssl Constants */
    SSL_ERROR_NONE      =  0,   /* for most functions */
    SSL_FAILURE         =  0,   /* for some functions */
    SSL_SUCCESS	        =  1,

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

    SSL_SESS_CACHE_OFF                = 30,
    SSL_SESS_CACHE_CLIENT             = 31,
    SSL_SESS_CACHE_SERVER             = 32,
    SSL_SESS_CACHE_BOTH               = 33,
    SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34,
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35,

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
    typedef unsigned int (*psk_client_callback)(SSL*, const char*, char*,
                                    unsigned int, unsigned char*, unsigned int);
    CYASSL_API void SSL_CTX_set_psk_client_callback(SSL_CTX*,
                                                    psk_client_callback);
    CYASSL_API void SSL_set_psk_client_callback(SSL*, psk_client_callback);

    CYASSL_API const char* SSL_get_psk_identity_hint(const SSL*);
    CYASSL_API const char* SSL_get_psk_identity(const SSL*);

    CYASSL_API int SSL_CTX_use_psk_identity_hint(SSL_CTX*, const char*);
    CYASSL_API int SSL_use_psk_identity_hint(SSL*, const char*);

    typedef unsigned int (*psk_server_callback)(SSL*, const char*,
                          unsigned char*, unsigned int);
    CYASSL_API void SSL_CTX_set_psk_server_callback(SSL_CTX*,
                                                    psk_server_callback);
    CYASSL_API void SSL_set_psk_server_callback(SSL*, psk_server_callback);

    #define PSK_TYPES_DEFINED
#endif /* NO_PSK */


/* extra begins */

enum {  /* ERR Constants */
    ERR_TXT_STRING = 1
};

CYASSL_API unsigned long ERR_get_error_line_data(const char**, int*,
                                                 const char**, int *);

CYASSL_API unsigned long ERR_get_error(void);
CYASSL_API void          ERR_clear_error(void);


CYASSL_API int  RAND_status(void);
CYASSL_API int  RAND_bytes(unsigned char* buf, int num);
CYASSL_API SSL_METHOD *SSLv23_server_method(void);
CYASSL_API long SSL_CTX_set_options(SSL_CTX*, long);
CYASSL_API int  SSL_CTX_check_private_key(SSL_CTX*);


CYASSL_API void ERR_free_strings(void);
CYASSL_API void ERR_remove_state(unsigned long);
CYASSL_API void EVP_cleanup(void);

CYASSL_API void CRYPTO_cleanup_all_ex_data(void);
CYASSL_API long SSL_CTX_set_mode(SSL_CTX* ctx, long mode);
CYASSL_API long SSL_CTX_get_mode(SSL_CTX* ctx);
CYASSL_API void SSL_CTX_set_default_read_ahead(SSL_CTX* ctx, int m);

CYASSL_API long SSL_CTX_sess_set_cache_size(SSL_CTX*, long);

CYASSL_API int  SSL_CTX_set_default_verify_paths(SSL_CTX*);
CYASSL_API int  SSL_CTX_set_session_id_context(SSL_CTX*, const unsigned char*,
                                    unsigned int);

CYASSL_API X509*      SSL_get_peer_certificate(SSL* ssl);

CYASSL_API int SSL_want_read(SSL*);
CYASSL_API int SSL_want_write(SSL*);

CYASSL_API int BIO_printf(BIO*, const char*, ...);
CYASSL_API int ASN1_UTCTIME_print(BIO*, const ASN1_UTCTIME*);

CYASSL_API int   sk_num(X509_REVOKED*);
CYASSL_API void* sk_value(X509_REVOKED*, int);

/* stunnel 4.28 needs */
CYASSL_API void* SSL_CTX_get_ex_data(const SSL_CTX*, int);
CYASSL_API int   SSL_CTX_set_ex_data(SSL_CTX*, int, void*);
CYASSL_API void  SSL_CTX_sess_set_get_cb(SSL_CTX*, SSL_SESSION*(*f)(SSL*,
                                         unsigned char*, int, int*));
CYASSL_API void  SSL_CTX_sess_set_new_cb(SSL_CTX*, int (*f)(SSL*,SSL_SESSION*));
CYASSL_API void  SSL_CTX_sess_set_remove_cb(SSL_CTX*, void (*f)(SSL_CTX*,
                                                                SSL_SESSION*));

CYASSL_API int          i2d_SSL_SESSION(SSL_SESSION*, unsigned char**);
CYASSL_API SSL_SESSION* d2i_SSL_SESSION(SSL_SESSION**,const unsigned char**,
                                        long);

CYASSL_API long SSL_SESSION_get_timeout(const SSL_SESSION*);
CYASSL_API long SSL_SESSION_get_time(const SSL_SESSION*);
CYASSL_API int  SSL_CTX_get_ex_new_index(long, void*, void*, void*, void*);

/* extra ends */


/* CyaSSL extensions */

/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
CYASSL_API int CyaSSL_check_domain_name(SSL* ssl, const char* dn);

/* need to call once to load library (session cache) */
CYASSL_API int CyaSSL_Init(void);
/* call when done to cleanup/free session cache mutex / resources  */
CYASSL_API int CyaSSL_Cleanup(void);

/* turn logging on, only if compiled in */
CYASSL_API int  CyaSSL_Debugging_ON(void);
/* turn logging off */
CYASSL_API void CyaSSL_Debugging_OFF(void);

/* do accept or connect depedning on side */
CYASSL_API int CyaSSL_negotiate(SSL* ssl);
/* turn on CyaSSL data compression */
CYASSL_API int CyaSSL_set_compression(SSL* ssl);

/* get CyaSSL peer X509_CHAIN */
CYASSL_API X509_CHAIN* CyaSSL_get_peer_chain(SSL* ssl);
/* peer chain count */
CYASSL_API int  CyaSSL_get_chain_count(X509_CHAIN* chain);
/* index cert length */
CYASSL_API int  CyaSSL_get_chain_length(X509_CHAIN*, int idx);
/* index cert */
CYASSL_API unsigned char* CyaSSL_get_chain_cert(X509_CHAIN*, int idx);
/* get index cert in PEM */
CYASSL_API int  CyaSSL_get_chain_cert_pem(X509_CHAIN*, int idx,
                                unsigned char* buffer, int inLen, int* outLen);
CYASSL_API const unsigned char* CyaSSL_get_sessionID(const SSL_SESSION* sess);
CYASSL_API int  CyaSSL_X509_get_serial_number(X509*, unsigned char*, int*);

/* server CTX Diffie-Hellman parameters */
CYASSL_API int  CyaSSL_SetTmpDH(SSL*, unsigned char* p, int pSz,
                                unsigned char* g, int gSz);

#ifndef _WIN32
    #ifndef NO_WRITEV
        #ifdef __PPU
            #include <sys/types.h>
            #include <sys/socket.h>
        #else
            #include <sys/uio.h>
        #endif
        /* allow writev style writing */
        CYASSL_API int CyaSSL_writev(SSL* ssl, const struct iovec* iov,
                                     int iovcnt);
    #endif
#endif


/* SSL_CTX versions */
CYASSL_API int CyaSSL_CTX_load_verify_buffer(SSL_CTX*, const unsigned char*,
                                             long, int);
CYASSL_API int CyaSSL_CTX_use_certificate_buffer(SSL_CTX*, const unsigned char*,                                                 long,int);
CYASSL_API int CyaSSL_CTX_use_PrivateKey_buffer(SSL_CTX*, const unsigned char*,
                                                long, int);
CYASSL_API int CyaSSL_CTX_use_certificate_chain_buffer(SSL_CTX*, 
                                                    const unsigned char*, long);

/* SSL versions */
CYASSL_API int CyaSSL_use_certificate_buffer(SSL*, const unsigned char*, long, 
                                             int);
CYASSL_API int CyaSSL_use_PrivateKey_buffer(SSL*, const unsigned char*, long,
                                            int);
CYASSL_API int CyaSSL_use_certificate_chain_buffer(SSL*,const unsigned char*, 
                                                   long);

/* I/O callbacks */
typedef int (*CallbackIORecv)(char *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(char *buf, int sz, void *ctx);

CYASSL_API void CyaSSL_SetIORecv(SSL_CTX*, CallbackIORecv);
CYASSL_API void CyaSSL_SetIOSend(SSL_CTX*, CallbackIOSend);

CYASSL_API void CyaSSL_SetIOReadCtx(SSL* ssl, void *ctx);
CYASSL_API void CyaSSL_SetIOWriteCtx(SSL* ssl, void *ctx);


#ifdef CYASSL_CALLBACKS

/* used internally by CyaSSL while OpenSSL types aren't */
#include "cyassl_callbacks.h"

typedef int (*HandShakeCallBack)(HandShakeInfo*);
typedef int (*TimeoutCallBack)(TimeoutInfo*);

/* CyaSSL connect extension allowing HandShakeCallBack and/or TimeoutCallBack
   for diagnostics */
CYASSL_API int CyaSSL_connect_ex(SSL*, HandShakeCallBack, TimeoutCallBack,
                                 Timeval);
CYASSL_API int CyaSSL_accept_ex(SSL*, HandShakeCallBack, TimeoutCallBack,
                                Timeval);

#endif /* CYASSL_CALLBACKS */


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* CyaSSL_openssl_h__ */
