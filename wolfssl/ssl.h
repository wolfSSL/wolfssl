/* ssl.h
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
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/types.h>

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

#ifdef OPENSSL_COEXIST
    /* mode to allow wolfSSL and OpenSSL to exist together */
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
    #endif

    /* make sure old names are disabled */
    #ifndef NO_OLD_SSL_NAMES
        #define NO_OLD_SSL_NAMES
    #endif
    #ifndef NO_OLD_WC_NAMES
        #define NO_OLD_WC_NAMES
    #endif

#elif (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    #include <wolfssl/openssl/bn.h>
    #include <wolfssl/openssl/hmac.h>

    /* We need the old SSL names */
    #ifdef NO_OLD_SSL_NAMES
        #undef NO_OLD_SSL_NAMES
    #endif
    #ifdef NO_OLD_WC_NAMES
        #undef NO_OLD_WC_NAMES
    #endif
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#include <wolfssl/ssl_types.h>

#include <wolfssl/wolfio.h>

#define WOLFSSL_X509_L_FILE_LOAD  0x1
#define WOLFSSL_X509_L_ADD_DIR    0x2
#define WOLFSSL_X509_L_ADD_STORE  0x3
#define WOLFSSL_X509_L_LOAD_STORE 0x4

#define WOLFSSL_NO_WILDCARDS   0x4

#define WOLFSSL_ASN1_BOOLEAN                int

/* CTX Method EX Constructor Functions */
WOLFSSL_API WOLFSSL_METHOD *wolfTLS_client_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLS_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_client_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_client_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_client_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_client_method_ex(void* heap);
#ifdef WOLFSSL_TLS13
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_client_method_ex(void* heap);
#endif

WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_server_method_ex(void* heap);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_client_method_ex(void* heap);

#ifdef WOLFSSL_DTLS
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_server_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_client_method_ex(void* heap);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_server_method_ex(void* heap);
#endif

/* CTX Method Constructor Functions */
WOLFSSL_API WOLFSSL_METHOD *wolfTLS_client_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLS_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv3_client_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_client_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);
WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_method(void);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);
#ifdef WOLFSSL_TLS13
    WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_method(void);
    WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_server_method(void);
    WOLFSSL_ABI WOLFSSL_API WOLFSSL_METHOD *wolfTLSv1_3_client_method(void);
#endif

#ifdef WOLFSSL_DTLS
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_server_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLS_client_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_client_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_server_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_client_method(void);
    WOLFSSL_API WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);
#endif

#ifdef HAVE_POLY1305
    WOLFSSL_API int wolfSSL_use_old_poly(WOLFSSL*, int);
#endif

#ifdef WOLFSSL_SESSION_EXPORT
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

WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX*,
                                                              const char*, int);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX*,
                                                              const char*, int);

#endif

#ifndef NO_CERTS
#define WOLFSSL_LOAD_FLAG_NONE          0x00000000
#define WOLFSSL_LOAD_FLAG_IGNORE_ERR    0x00000001
#define WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY 0x00000002
#define WOLFSSL_LOAD_FLAG_PEM_CA_ONLY   0x00000004

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

WOLFSSL_API int wolfSSL_CTX_load_verify_locations_ex(WOLFSSL_CTX*, const char*,
                                                const char*, unsigned int);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX*,
                                                      const char*, const char*);
#ifdef WOLFSSL_TRUST_PEER_CERT
WOLFSSL_API int wolfSSL_CTX_trust_peer_cert(WOLFSSL_CTX*, const char*, int);
#endif
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_file(
                                                     WOLFSSL_CTX*, const char*);
WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_file_format(WOLFSSL_CTX *,
                                                  const char *file, int format);
WOLFSSL_API int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX*, const char*, int);

WOLFSSL_ABI WOLFSSL_API int wolfSSL_use_certificate_file(WOLFSSL*, const char*,
                                                                           int);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_use_PrivateKey_file(WOLFSSL*, const char*,
                                                                           int);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_use_certificate_chain_file(WOLFSSL*,
                                                                   const char*);
WOLFSSL_API int wolfSSL_use_certificate_chain_file_format(WOLFSSL*,
                                                  const char *file, int format);
WOLFSSL_API int wolfSSL_use_RSAPrivateKey_file(WOLFSSL*, const char*, int);

#ifdef WOLFSSL_DER_LOAD
    WOLFSSL_API int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX*,
                                                    const char*, int);
#endif

#ifdef HAVE_NTRU
    WOLFSSL_API int wolfSSL_CTX_use_NTRUPrivateKey_file(WOLFSSL_CTX*, const char*);
    /* load NTRU private key blob */
#endif

#endif /* !NO_FILESYSTEM && !NO_CERTS */

WOLFSSL_API WOLFSSL_CTX* wolfSSL_CTX_new_ex(WOLFSSL_METHOD* method, void* heap);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);
#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_CTX_up_ref(WOLFSSL_CTX*);
WOLFSSL_API int wolfSSL_CTX_set_ecdh_auto(WOLFSSL_CTX* ctx, int onoff);
#endif
WOLFSSL_ABI WOLFSSL_API WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);
WOLFSSL_API WOLFSSL_CTX* wolfSSL_get_SSL_CTX(WOLFSSL* ssl);
WOLFSSL_API WOLFSSL_X509_VERIFY_PARAM* wolfSSL_CTX_get0_param(WOLFSSL_CTX* ctx);
WOLFSSL_API WOLFSSL_X509_VERIFY_PARAM* wolfSSL_get0_param(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_set1_param(WOLFSSL_CTX* ctx, WOLFSSL_X509_VERIFY_PARAM *vpm);
WOLFSSL_API int  wolfSSL_is_server(WOLFSSL*);
WOLFSSL_API WOLFSSL* wolfSSL_write_dup(WOLFSSL*);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_set_fd (WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_write_fd (WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_read_fd (WOLFSSL*, int);
WOLFSSL_API char* wolfSSL_get_cipher_list(int priority);
WOLFSSL_API char* wolfSSL_get_cipher_list_ex(WOLFSSL* ssl, int priority);
WOLFSSL_API int  wolfSSL_get_ciphers(char*, int);
WOLFSSL_API int wolfSSL_get_ciphers_iana(char*, int);
WOLFSSL_API const char* wolfSSL_get_cipher_name(WOLFSSL* ssl);
WOLFSSL_API const char* wolfSSL_get_cipher_name_from_suite(const unsigned char,
    const unsigned char);
WOLFSSL_API const char* wolfSSL_get_cipher_name_iana_from_suite(
    const unsigned char, const unsigned char);
WOLFSSL_API int wolfSSL_get_cipher_suite_from_name(const char* name,
    byte* cipherSuite0, byte* cipherSuite, int* flags);
WOLFSSL_API const char* wolfSSL_get_shared_ciphers(WOLFSSL* ssl, char* buf,
    int len);
WOLFSSL_API const char* wolfSSL_get_curve_name(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_get_fd(const WOLFSSL*);
/* please see note at top of README if you get an error from connect */
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_connect(WOLFSSL*);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_write(WOLFSSL*, const void*, int);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_read(WOLFSSL*, void*, int);
WOLFSSL_API int  wolfSSL_peek(WOLFSSL*, void*, int);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_accept(WOLFSSL*);
WOLFSSL_API int  wolfSSL_CTX_mutual_auth(WOLFSSL_CTX* ctx, int req);
WOLFSSL_API int  wolfSSL_mutual_auth(WOLFSSL* ssl, int req);
#ifdef WOLFSSL_TLS13
WOLFSSL_API int  wolfSSL_send_hrr_cookie(WOLFSSL* ssl,
    const unsigned char* secret, unsigned int secretSz);
WOLFSSL_API int  wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_no_dhe_psk(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_update_keys(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_key_update_response(WOLFSSL* ssl, int* required);
WOLFSSL_API int  wolfSSL_CTX_allow_post_handshake_auth(WOLFSSL_CTX* ctx);
WOLFSSL_API int  wolfSSL_allow_post_handshake_auth(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_request_certificate(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_CTX_set1_groups_list(WOLFSSL_CTX *ctx, char *list);
WOLFSSL_API int  wolfSSL_set1_groups_list(WOLFSSL *ssl, char *list);

WOLFSSL_API int  wolfSSL_preferred_group(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_CTX_set_groups(WOLFSSL_CTX* ctx, int* groups,
                                        int count);
WOLFSSL_API int  wolfSSL_set_groups(WOLFSSL* ssl, int* groups, int count);

#ifdef OPENSSL_EXTRA
WOLFSSL_API int  wolfSSL_CTX_set1_groups(WOLFSSL_CTX* ctx, int* groups,
                                        int count);
WOLFSSL_API int  wolfSSL_set1_groups(WOLFSSL* ssl, int* groups, int count);
#endif

WOLFSSL_API int  wolfSSL_connect_TLSv13(WOLFSSL*);
WOLFSSL_API int  wolfSSL_accept_TLSv13(WOLFSSL*);

#ifdef WOLFSSL_EARLY_DATA

#define WOLFSSL_EARLY_DATA_NOT_SENT    0
#define WOLFSSL_EARLY_DATA_REJECTED    1
#define WOLFSSL_EARLY_DATA_ACCEPTED    2

WOLFSSL_API int  wolfSSL_CTX_set_max_early_data(WOLFSSL_CTX* ctx,
                                                unsigned int sz);
WOLFSSL_API int  wolfSSL_set_max_early_data(WOLFSSL* ssl, unsigned int sz);
WOLFSSL_API int  wolfSSL_write_early_data(WOLFSSL* ssl, const void* data,
                                          int sz, int* outSz);
WOLFSSL_API int  wolfSSL_read_early_data(WOLFSSL* ssl, void* data, int sz,
                                         int* outSz);
WOLFSSL_API int  wolfSSL_get_early_data_status(const WOLFSSL* ssl);
#endif /* WOLFSSL_EARLY_DATA */
#endif /* WOLFSSL_TLS13 */
WOLFSSL_ABI WOLFSSL_API void wolfSSL_CTX_free(WOLFSSL_CTX*);
WOLFSSL_ABI WOLFSSL_API void wolfSSL_free(WOLFSSL*);
WOLFSSL_ABI WOLFSSL_API int  wolfSSL_shutdown(WOLFSSL*);
WOLFSSL_API int  wolfSSL_send(WOLFSSL*, const void*, int sz, int flags);
WOLFSSL_API int  wolfSSL_recv(WOLFSSL*, void*, int sz, int flags);

WOLFSSL_API void wolfSSL_CTX_set_quiet_shutdown(WOLFSSL_CTX*, int);
WOLFSSL_API void wolfSSL_set_quiet_shutdown(WOLFSSL*, int);

WOLFSSL_ABI WOLFSSL_API int  wolfSSL_get_error(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_get_alert_history(WOLFSSL*, WOLFSSL_ALERT_HISTORY *);

WOLFSSL_ABI WOLFSSL_API int  wolfSSL_set_session(WOLFSSL*, WOLFSSL_SESSION*);
WOLFSSL_API long wolfSSL_SSL_SESSION_set_timeout(WOLFSSL_SESSION*, long);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL*);
WOLFSSL_ABI WOLFSSL_API void wolfSSL_flush_sessions(WOLFSSL_CTX*, long);
WOLFSSL_API int  wolfSSL_SetServerID(WOLFSSL*, const unsigned char*, int, int);

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX)
WOLFSSL_API int  wolfSSL_BIO_new_bio_pair(WOLFSSL_BIO**, size_t,
                     WOLFSSL_BIO**, size_t);

WOLFSSL_API int wolfSSL_RSA_padding_add_PKCS1_PSS(WOLFSSL_RSA *rsa,
                                                  unsigned char *EM,
                                                  const unsigned char *mHash,
                                                  const WOLFSSL_EVP_MD *hashAlg,
                                                  int saltLen);
WOLFSSL_API int wolfSSL_RSA_verify_PKCS1_PSS(WOLFSSL_RSA *rsa, const unsigned char *mHash,
                                          const WOLFSSL_EVP_MD *hashAlg,
                                          const unsigned char *EM, int saltLen);
WOLFSSL_API WOLFSSL_RSA* wolfSSL_d2i_RSAPrivateKey_bio(WOLFSSL_BIO*, WOLFSSL_RSA**);
WOLFSSL_API int wolfSSL_CTX_use_certificate_ASN1(WOLFSSL_CTX*,
                                           int, const unsigned char*);
WOLFSSL_API int wolfSSL_CTX_use_RSAPrivateKey(WOLFSSL_CTX*, WOLFSSL_RSA*);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_bio(WOLFSSL_BIO*, WOLFSSL_EVP_PKEY**);
#endif /* OPENSSL_ALL || WOLFSSL_ASIO */

#ifdef SESSION_INDEX
WOLFSSL_API int wolfSSL_GetSessionIndex(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_GetSessionAtIndex(int index, WOLFSSL_SESSION* session);
#endif /* SESSION_INDEX */

#if defined(SESSION_CERTS)
WOLFSSL_API
    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);
WOLFSSL_API WOLFSSL_X509* wolfSSL_SESSION_get0_peer(WOLFSSL_SESSION* session);
#endif /* SESSION_INDEX && SESSION_CERTS */

typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*);
typedef void (CallbackInfoState)(const WOLFSSL*, int, int);

#if defined(HAVE_EX_DATA) || defined(FORTRESS)
typedef int  (WOLFSSL_CRYPTO_EX_new)(void* p, void* ptr,
        WOLFSSL_CRYPTO_EX_DATA* a, int idx, long argValue, void* arg);
typedef int  (WOLFSSL_CRYPTO_EX_dup)(WOLFSSL_CRYPTO_EX_DATA* out,
        WOLFSSL_CRYPTO_EX_DATA* in, void* inPtr, int idx, long argV, void* arg);
typedef void (WOLFSSL_CRYPTO_EX_free)(void* p, void* ptr,
        WOLFSSL_CRYPTO_EX_DATA* a, int idx, long argValue, void* arg);

WOLFSSL_API int  wolfSSL_get_ex_new_index(long argValue, void* arg,
        WOLFSSL_CRYPTO_EX_new* a, WOLFSSL_CRYPTO_EX_dup* b,
        WOLFSSL_CRYPTO_EX_free* c);
#endif

WOLFSSL_API void wolfSSL_CTX_set_verify(WOLFSSL_CTX*, int,
                                      VerifyCallback verify_callback);

#ifdef OPENSSL_ALL
typedef int (*CertVerifyCallback)(WOLFSSL_X509_STORE_CTX* store, void* arg);
WOLFSSL_API void wolfSSL_CTX_set_cert_verify_callback(WOLFSSL_CTX* ctx,
    CertVerifyCallback cb, void* arg);
#endif

WOLFSSL_API void wolfSSL_set_verify(WOLFSSL*, int, VerifyCallback verify_callback);
WOLFSSL_API void wolfSSL_set_verify_result(WOLFSSL*, long);

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
WOLFSSL_API int wolfSSL_verify_client_post_handshake(WOLFSSL*);
WOLFSSL_API int wolfSSL_CTX_set_post_handshake_auth(WOLFSSL_CTX*, int);
WOLFSSL_API int wolfSSL_set_post_handshake_auth(WOLFSSL*, int);
#endif

WOLFSSL_API void wolfSSL_SetCertCbCtx(WOLFSSL*, void*);

WOLFSSL_ABI WOLFSSL_API int  wolfSSL_pending(WOLFSSL*);

WOLFSSL_API void wolfSSL_load_error_strings(void);
WOLFSSL_API int  wolfSSL_library_init(void);
WOLFSSL_ABI WOLFSSL_API long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX*,
                                                                          long);

#ifdef HAVE_SECRET_CALLBACK
typedef int (*SessionSecretCb)(WOLFSSL* ssl, void* secret, int* secretSz,
                               void* ctx);
WOLFSSL_API int  wolfSSL_set_session_secret_cb(WOLFSSL*, SessionSecretCb,
                                               void*);
#ifdef WOLFSSL_TLS13
typedef int (*Tls13SecretCb)(WOLFSSL* ssl, int id, const unsigned char* secret,
                             int secretSz, void* ctx);
WOLFSSL_API int  wolfSSL_set_tls13_secret_cb(WOLFSSL*, Tls13SecretCb, void*);
#endif
#endif /* HAVE_SECRET_CALLBACK */

/* session cache persistence */
WOLFSSL_API int  wolfSSL_save_session_cache(const char*);
WOLFSSL_API int  wolfSSL_restore_session_cache(const char*);
WOLFSSL_API int  wolfSSL_memsave_session_cache(void*, int);
WOLFSSL_API int  wolfSSL_memrestore_session_cache(const void*, int);
WOLFSSL_API int  wolfSSL_get_session_cache_memsize(void);

/* certificate cache persistence, uses ctx since certs are per ctx */
WOLFSSL_API int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX*, const char*);
WOLFSSL_API int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX*, const char*);
WOLFSSL_API int  wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX*, void*, int, int*);
WOLFSSL_API int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX*, const void*, int);
WOLFSSL_API int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX*);

/* only supports full name from cipher_name[] delimited by : */
WOLFSSL_API int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX*, const char*);
WOLFSSL_API int  wolfSSL_set_cipher_list(WOLFSSL*, const char*);

#ifdef HAVE_KEYING_MATERIAL
/* Keying Material Exporter for TLS */
WOLFSSL_API int wolfSSL_export_keying_material(WOLFSSL *ssl,
        unsigned char *out, size_t outLen,
        const char *label, size_t labelLen,
        const unsigned char *context, size_t contextLen,
        int use_context);
#endif /* HAVE_KEYING_MATERIAL */

/* Nonblocking DTLS helper functions */
WOLFSSL_API void wolfSSL_dtls_set_using_nonblock(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_dtls_get_using_nonblock(WOLFSSL*);
#define wolfSSL_set_using_nonblock wolfSSL_dtls_set_using_nonblock
#define wolfSSL_get_using_nonblock wolfSSL_dtls_get_using_nonblock
    /* The old names are deprecated. */
WOLFSSL_API int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_DTLSv1_get_timeout(WOLFSSL* ssl,
        WOLFSSL_TIMEVAL* timeleft);
WOLFSSL_API void wolfSSL_DTLSv1_set_initial_timeout_duration(WOLFSSL* ssl,
    word32 duration_ms);
WOLFSSL_API int  wolfSSL_DTLSv1_handle_timeout(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int);
WOLFSSL_API int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int);
WOLFSSL_API int  wolfSSL_dtls_got_timeout(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_dtls_retransmit(WOLFSSL*);
WOLFSSL_API int  wolfSSL_dtls(WOLFSSL* ssl);

WOLFSSL_API int  wolfSSL_dtls_set_peer(WOLFSSL*, void*, unsigned int);
WOLFSSL_API int  wolfSSL_dtls_get_peer(WOLFSSL*, void*, unsigned int*);

WOLFSSL_API int  wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_dtls_set_sctp(WOLFSSL*);
WOLFSSL_API int  wolfSSL_CTX_dtls_set_mtu(WOLFSSL_CTX*, unsigned short);
WOLFSSL_API int  wolfSSL_dtls_set_mtu(WOLFSSL*, unsigned short);

WOLFSSL_API int  wolfSSL_dtls_get_drop_stats(WOLFSSL*,
                                             unsigned int*, unsigned int*);
WOLFSSL_API int  wolfSSL_CTX_mcast_set_member_id(WOLFSSL_CTX*, unsigned short);
WOLFSSL_API int  wolfSSL_set_secret(WOLFSSL*, unsigned short,
                     const unsigned char*, unsigned int,
                     const unsigned char*, const unsigned char*,
                     const unsigned char*);
WOLFSSL_API int  wolfSSL_mcast_read(WOLFSSL*, unsigned short*, void*, int);
WOLFSSL_API int  wolfSSL_mcast_peer_add(WOLFSSL*, unsigned short, int);
WOLFSSL_API int  wolfSSL_mcast_peer_known(WOLFSSL*, unsigned short);
WOLFSSL_API int  wolfSSL_mcast_get_max_peers(void);
typedef int (*CallbackMcastHighwater)(unsigned short peerId,
                                      unsigned int maxSeq,
                                      unsigned int curSeq, void* ctx);
WOLFSSL_API int  wolfSSL_CTX_mcast_set_highwater_cb(WOLFSSL_CTX*,
                                                    unsigned int,
                                                    unsigned int,
                                                    unsigned int,
                                                    CallbackMcastHighwater);
WOLFSSL_API int  wolfSSL_mcast_set_highwater_ctx(WOLFSSL*, void*);

WOLFSSL_API int   wolfSSL_ERR_GET_LIB(unsigned long err);
WOLFSSL_API int   wolfSSL_ERR_GET_REASON(unsigned long err);
WOLFSSL_API char* wolfSSL_ERR_error_string(unsigned long,char*);
WOLFSSL_API void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long sz);
WOLFSSL_API const char* wolfSSL_ERR_reason_error_string(unsigned long);

/* extras */

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap);
WOLFSSL_API void wolfSSL_sk_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_free_node(WOLFSSL_STACK* in);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_dup(WOLFSSL_STACK* sk);
WOLFSSL_API int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* in);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* sk, int idx);
WOLFSSL_API int wolfSSL_sk_push(WOLFSSL_STACK *st, const void *data);

#if defined(HAVE_OCSP)
#include "wolfssl/ocsp.h"
#include "wolfssl/wolfcrypt/asn.h"
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
WOLFSSL_API int wolfSSL_sk_ACCESS_DESCRIPTION_push(
                                       WOLF_STACK_OF(ACCESS_DESCRIPTION)* sk,
                                       WOLFSSL_ACCESS_DESCRIPTION* access);
#endif /* defined(OPENSSL_ALL) || defined(WOLFSSL_QT) */

WOLFSSL_API int wolfSSL_sk_X509_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
                                                            WOLFSSL_X509* x509);
WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk);
WOLFSSL_API void wolfSSL_sk_X509_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk);
WOLFSSL_API WOLFSSL_GENERAL_NAME* wolfSSL_GENERAL_NAME_new(void);
WOLFSSL_API void wolfSSL_GENERAL_NAME_free(WOLFSSL_GENERAL_NAME* gn);
WOLFSSL_API WOLFSSL_GENERAL_NAMES* wolfSSL_GENERAL_NAMES_dup(
                                             WOLFSSL_GENERAL_NAMES* gns);
WOLFSSL_API int wolfSSL_sk_GENERAL_NAME_push(WOLFSSL_GENERAL_NAMES* sk,
                                             WOLFSSL_GENERAL_NAME* gn);
WOLFSSL_API WOLFSSL_GENERAL_NAME* wolfSSL_sk_GENERAL_NAME_value(
        WOLFSSL_STACK* sk, int i);
WOLFSSL_API int wolfSSL_sk_GENERAL_NAME_num(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_GENERAL_NAME_pop_free(WOLFSSL_STACK* sk,
                                       void (*f) (WOLFSSL_GENERAL_NAME*));
WOLFSSL_API void wolfSSL_sk_GENERAL_NAME_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_GENERAL_NAMES_free(WOLFSSL_GENERAL_NAMES* name);
WOLFSSL_API int wolfSSL_sk_ACCESS_DESCRIPTION_num(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_AUTHORITY_INFO_ACCESS_free(
        WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)* sk);
WOLFSSL_API WOLFSSL_ACCESS_DESCRIPTION* wolfSSL_sk_ACCESS_DESCRIPTION_value(
        WOLFSSL_STACK* sk, int idx);
WOLFSSL_API void wolfSSL_sk_ACCESS_DESCRIPTION_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_ACCESS_DESCRIPTION_pop_free(WOLFSSL_STACK* sk,
        void (*f) (WOLFSSL_ACCESS_DESCRIPTION*));
WOLFSSL_API void wolfSSL_ACCESS_DESCRIPTION_free(WOLFSSL_ACCESS_DESCRIPTION* access);
WOLFSSL_API void wolfSSL_sk_X509_EXTENSION_pop_free(
        WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk,
        void (*f) (WOLFSSL_X509_EXTENSION*));
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
                            WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk, int idx);
WOLFSSL_API int  wolfSSL_set_ex_data(WOLFSSL*, int, void*);
WOLFSSL_API int  wolfSSL_get_shutdown(const WOLFSSL*);
WOLFSSL_API int  wolfSSL_set_rfd(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_wfd(WOLFSSL*, int);
WOLFSSL_API void wolfSSL_set_shutdown(WOLFSSL*, int);
WOLFSSL_API int  wolfSSL_set_session_id_context(WOLFSSL*, const unsigned char*,
                                           unsigned int);
WOLFSSL_API void wolfSSL_set_connect_state(WOLFSSL*);
WOLFSSL_API void wolfSSL_set_accept_state(WOLFSSL*);
WOLFSSL_API int  wolfSSL_session_reused(WOLFSSL*);
WOLFSSL_API int wolfSSL_SESSION_up_ref(WOLFSSL_SESSION* session);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_SESSION_dup(WOLFSSL_SESSION* session);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_SESSION_new(void);
WOLFSSL_API void wolfSSL_SESSION_free(WOLFSSL_SESSION* session);
WOLFSSL_API int  wolfSSL_is_init_finished(WOLFSSL*);

WOLFSSL_API const char*  wolfSSL_get_version(const WOLFSSL*);
WOLFSSL_API int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);
WOLFSSL_API WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL*);
WOLFSSL_API char* wolfSSL_CIPHER_description(const WOLFSSL_CIPHER*, char*, int);
WOLFSSL_API const char*  wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API const char*  wolfSSL_CIPHER_get_version(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API word32       wolfSSL_CIPHER_get_id(const WOLFSSL_CIPHER* cipher);
WOLFSSL_API const WOLFSSL_CIPHER* wolfSSL_get_cipher_by_value(word16 value);
WOLFSSL_API const char*  wolfSSL_SESSION_CIPHER_get_name(WOLFSSL_SESSION* session);
WOLFSSL_API const char*  wolfSSL_get_cipher(WOLFSSL*);
WOLFSSL_API void wolfSSL_sk_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);
WOLFSSL_API WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);
                           /* what's ref count */

WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_new(void);
#if defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_ALL)
WOLFSSL_API int wolfSSL_RSA_up_ref(WOLFSSL_RSA* rsa);
WOLFSSL_API int wolfSSL_X509_up_ref(WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_EVP_PKEY_up_ref(WOLFSSL_EVP_PKEY* pkey);
#endif

WOLFSSL_API int wolfSSL_OCSP_parse_url(char* url, char** host, char** port,
                                     char** path, int* ssl);

WOLFSSL_API WOLFSSL_METHOD* wolfSSLv23_client_method(void);
WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_client_method(void);
WOLFSSL_API WOLFSSL_METHOD* wolfSSLv2_server_method(void);

WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new(WOLFSSL_BIO_METHOD*);
WOLFSSL_API int  wolfSSL_BIO_free(WOLFSSL_BIO*);
WOLFSSL_API void wolfSSL_BIO_vfree(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_free_all(WOLFSSL_BIO*);
WOLFSSL_API int wolfSSL_BIO_gets(WOLFSSL_BIO* bio, char* buf, int sz);
WOLFSSL_API int wolfSSL_BIO_puts(WOLFSSL_BIO* bio, const char* buf);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_next(WOLFSSL_BIO* bio);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_find_type(WOLFSSL_BIO* bio, int type);
WOLFSSL_API int  wolfSSL_BIO_read(WOLFSSL_BIO*, void*, int);
WOLFSSL_API int  wolfSSL_BIO_write(WOLFSSL_BIO*, const void*, int);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO*, WOLFSSL_BIO* append);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_flush(WOLFSSL_BIO*);
WOLFSSL_API int  wolfSSL_BIO_pending(WOLFSSL_BIO*);
WOLFSSL_API void wolfSSL_BIO_set_callback(WOLFSSL_BIO *bio,
                                          wolf_bio_info_cb callback_func);
WOLFSSL_API wolf_bio_info_cb wolfSSL_BIO_get_callback(WOLFSSL_BIO *bio);
WOLFSSL_API void  wolfSSL_BIO_set_callback_arg(WOLFSSL_BIO *bio, char *arg);
WOLFSSL_API char* wolfSSL_BIO_get_callback_arg(const WOLFSSL_BIO *bio);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_md(void);
WOLFSSL_API int wolfSSL_BIO_get_md_ctx(WOLFSSL_BIO *bio,
                                                WOLFSSL_EVP_MD_CTX **mdcp);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void);
WOLFSSL_API long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO*, long size);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void);
WOLFSSL_API WOLFSSL_BIO*        wolfSSL_BIO_new_socket(int sfd, int flag);
WOLFSSL_API int         wolfSSL_BIO_eof(WOLFSSL_BIO*);

WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void);
WOLFSSL_API WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void);
WOLFSSL_API void wolfSSL_BIO_set_flags(WOLFSSL_BIO*, int);
WOLFSSL_API void wolfSSL_BIO_clear_flags(WOLFSSL_BIO *bio, int flags);
WOLFSSL_API int wolfSSL_BIO_set_ex_data(WOLFSSL_BIO *bio, int idx, void *data);
WOLFSSL_API void *wolfSSL_BIO_get_ex_data(WOLFSSL_BIO *bio, int idx);
WOLFSSL_API long wolfSSL_BIO_set_nbio(WOLFSSL_BIO*, long);

WOLFSSL_API int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,void* p);

WOLFSSL_API void wolfSSL_BIO_set_init(WOLFSSL_BIO*, int);
WOLFSSL_API void wolfSSL_BIO_set_data(WOLFSSL_BIO*, void*);
WOLFSSL_API void* wolfSSL_BIO_get_data(WOLFSSL_BIO*);
WOLFSSL_API void wolfSSL_BIO_set_shutdown(WOLFSSL_BIO*, int);
WOLFSSL_API int wolfSSL_BIO_get_shutdown(WOLFSSL_BIO*);
WOLFSSL_API void wolfSSL_BIO_clear_retry_flags(WOLFSSL_BIO*);
WOLFSSL_API int wolfSSL_BIO_should_retry(WOLFSSL_BIO *bio);

WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_meth_new(int, const char*);
WOLFSSL_API void wolfSSL_BIO_meth_free(WOLFSSL_BIO_METHOD*);
WOLFSSL_API int wolfSSL_BIO_meth_set_write(WOLFSSL_BIO_METHOD*, wolfSSL_BIO_meth_write_cb);
WOLFSSL_API int wolfSSL_BIO_meth_set_read(WOLFSSL_BIO_METHOD*, wolfSSL_BIO_meth_read_cb);
WOLFSSL_API int wolfSSL_BIO_meth_set_puts(WOLFSSL_BIO_METHOD*, wolfSSL_BIO_meth_puts_cb);
WOLFSSL_API int wolfSSL_BIO_meth_set_gets(WOLFSSL_BIO_METHOD*, wolfSSL_BIO_meth_gets_cb);
WOLFSSL_API int wolfSSL_BIO_meth_set_ctrl(WOLFSSL_BIO_METHOD*, wolfSSL_BIO_meth_ctrl_get_cb);
WOLFSSL_API int wolfSSL_BIO_meth_set_create(WOLFSSL_BIO_METHOD*, wolfSSL_BIO_meth_create_cb);
WOLFSSL_API int wolfSSL_BIO_meth_set_destroy(WOLFSSL_BIO_METHOD*, wolfSSL_BIO_meth_destroy_cb);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(const void* buf, int len);

WOLFSSL_API long wolfSSL_BIO_set_ssl(WOLFSSL_BIO*, WOLFSSL*, int flag);
#ifndef NO_FILESYSTEM
WOLFSSL_API long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int flag);
#endif
WOLFSSL_API int wolfSSL_BIO_set_close(WOLFSSL_BIO *b, long flag);
WOLFSSL_API void wolfSSL_set_bio(WOLFSSL*, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr);

#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_file(void);
WOLFSSL_API WOLFSSL_BIO *wolfSSL_BIO_new_fd(int fd, int close_flag);
#endif

WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_bio(void);
WOLFSSL_API WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void);

WOLFSSL_API WOLFSSL_BIO *wolfSSL_BIO_new_connect(const char *str);
WOLFSSL_API long wolfSSL_BIO_set_conn_port(WOLFSSL_BIO *b, char* port);
WOLFSSL_API long wolfSSL_BIO_do_connect(WOLFSSL_BIO *b);

WOLFSSL_API long wolfSSL_BIO_do_handshake(WOLFSSL_BIO *b);

WOLFSSL_API long wolfSSL_BIO_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, void *parg);
WOLFSSL_API long wolfSSL_BIO_int_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, int iarg);

WOLFSSL_API int  wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size);
WOLFSSL_API int  wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2);
WOLFSSL_API int  wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *b);
WOLFSSL_API int  wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf);
WOLFSSL_API int  wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num);
WOLFSSL_API int  wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num);
WOLFSSL_API int  wolfSSL_BIO_reset(WOLFSSL_BIO *bio);

WOLFSSL_API int  wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs);
WOLFSSL_API int  wolfSSL_BIO_tell(WOLFSSL_BIO* bio);
WOLFSSL_API int  wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name);
WOLFSSL_API long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v);
WOLFSSL_API long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **m);
WOLFSSL_API int wolfSSL_BIO_get_len(WOLFSSL_BIO *bio);

WOLFSSL_API void        wolfSSL_RAND_screen(void);
WOLFSSL_API const char* wolfSSL_RAND_file_name(char*, unsigned long);
WOLFSSL_API int         wolfSSL_RAND_write_file(const char*);
WOLFSSL_API int         wolfSSL_RAND_load_file(const char*, long);
WOLFSSL_API int         wolfSSL_RAND_egd(const char*);
WOLFSSL_API int         wolfSSL_RAND_seed(const void*, int);
WOLFSSL_API void        wolfSSL_RAND_Cleanup(void);
WOLFSSL_API void        wolfSSL_RAND_add(const void*, int, double);
WOLFSSL_API int         wolfSSL_RAND_poll(void);

WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void);
WOLFSSL_API WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void);
WOLFSSL_API int wolfSSL_COMP_add_compression_method(int, void*);

WOLFSSL_API unsigned long wolfSSL_thread_id(void);
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

WOLFSSL_API void  wolfSSL_X509_STORE_CTX_set_verify_cb(WOLFSSL_X509_STORE_CTX *ctx,
                                  WOLFSSL_X509_STORE_CTX_verify_cb verify_cb);
WOLFSSL_API void wolfSSL_X509_STORE_set_verify_cb(WOLFSSL_X509_STORE *st,
                                 WOLFSSL_X509_STORE_CTX_verify_cb verify_cb);
WOLFSSL_API int wolfSSL_i2d_X509_NAME(WOLFSSL_X509_NAME* n,
                                                           unsigned char** out);
WOLFSSL_API WOLFSSL_X509_NAME *wolfSSL_d2i_X509_NAME(WOLFSSL_X509_NAME **name,
                                              unsigned char **in, long length);
#ifndef NO_RSA
WOLFSSL_API int wolfSSL_RSA_print(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa, int offset);
#endif
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
WOLFSSL_ABI WOLFSSL_API char* wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME*,
                                                                    char*, int);
#if defined(OPENSSL_EXTRA) && defined(XSNPRINTF)
WOLFSSL_API char* wolfSSL_X509_get_name_oneline(WOLFSSL_X509_NAME*, char*, int);
#endif
WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_get_issuer_name(
                                                                 WOLFSSL_X509*);
WOLFSSL_API unsigned long  wolfSSL_X509_issuer_name_hash(const WOLFSSL_X509* x509);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_get_subject_name(
                                                                 WOLFSSL_X509*);
WOLFSSL_API unsigned long  wolfSSL_X509_subject_name_hash(const WOLFSSL_X509* x509);
WOLFSSL_API int  wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509*, int);
WOLFSSL_API int  wolfSSL_X509_ext_get_critical_by_NID(WOLFSSL_X509*, int);
WOLFSSL_API int  wolfSSL_X509_get_isCA(WOLFSSL_X509*);
WOLFSSL_API int  wolfSSL_X509_get_isSet_pathLength(WOLFSSL_X509*);
WOLFSSL_API unsigned int wolfSSL_X509_get_pathLength(WOLFSSL_X509*);
WOLFSSL_API unsigned int wolfSSL_X509_get_keyUsage(WOLFSSL_X509*);
WOLFSSL_API unsigned char* wolfSSL_X509_get_authorityKeyID(
                                            WOLFSSL_X509*, unsigned char*, int*);
WOLFSSL_API unsigned char* wolfSSL_X509_get_subjectKeyID(
                                            WOLFSSL_X509*, unsigned char*, int*);

WOLFSSL_API int wolfSSL_X509_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API int wolfSSL_X509_REQ_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);
#endif
WOLFSSL_API int wolfSSL_X509_set_subject_name(WOLFSSL_X509*,
                                              WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_X509_set_issuer_name(WOLFSSL_X509*,
                                              WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_X509_set_pubkey(WOLFSSL_X509*, WOLFSSL_EVP_PKEY*);
WOLFSSL_API int wolfSSL_X509_set_notAfter(WOLFSSL_X509* x509,
        const WOLFSSL_ASN1_TIME* t);
WOLFSSL_API int wolfSSL_X509_set_notBefore(WOLFSSL_X509* x509,
        const WOLFSSL_ASN1_TIME* t);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(const WOLFSSL_X509* x509);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(const WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_set_serialNumber(WOLFSSL_X509* x509,
        WOLFSSL_ASN1_INTEGER* s);
WOLFSSL_API int wolfSSL_X509_set_version(WOLFSSL_X509* x509, long v);
WOLFSSL_API int wolfSSL_X509_sign(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey,
        const WOLFSSL_EVP_MD* md);
WOLFSSL_API int wolfSSL_X509_sign_ctx(WOLFSSL_X509 *x509, WOLFSSL_EVP_MD_CTX *ctx);


WOLFSSL_API int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_X509_NAME_get_text_by_NID(
                                            WOLFSSL_X509_NAME*, int, char*, int);
WOLFSSL_API int wolfSSL_X509_NAME_get_index_by_NID(
                                           WOLFSSL_X509_NAME*, int, int);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_X509_NAME_ENTRY_get_data(WOLFSSL_X509_NAME_ENTRY*);

WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_new(void);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_dup(WOLFSSL_ASN1_STRING* asn1);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_type_new(int type);
WOLFSSL_API int wolfSSL_ASN1_STRING_type(const WOLFSSL_ASN1_STRING* asn1);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_d2i_DISPLAYTEXT(WOLFSSL_ASN1_STRING **asn, const unsigned char **in, long len);
WOLFSSL_API int wolfSSL_ASN1_STRING_cmp(const WOLFSSL_ASN1_STRING *a, const WOLFSSL_ASN1_STRING *b);
WOLFSSL_API void wolfSSL_ASN1_STRING_free(WOLFSSL_ASN1_STRING* asn1);
WOLFSSL_API int wolfSSL_ASN1_STRING_set(WOLFSSL_ASN1_STRING* asn1,
                                                  const void* data, int dataSz);
WOLFSSL_API unsigned char* wolfSSL_ASN1_STRING_data(WOLFSSL_ASN1_STRING*);
WOLFSSL_API int wolfSSL_ASN1_STRING_length(WOLFSSL_ASN1_STRING*);
WOLFSSL_API int         wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API const char* wolfSSL_X509_verify_cert_error_string(long);
WOLFSSL_API int wolfSSL_X509_get_signature_type(WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_X509_get_signature(WOLFSSL_X509*, unsigned char*, int*);
WOLFSSL_API int wolfSSL_X509_get_pubkey_buffer(WOLFSSL_X509*, unsigned char*,
        int*);
WOLFSSL_API int wolfSSL_X509_get_pubkey_type(WOLFSSL_X509* x509);

WOLFSSL_API int wolfSSL_X509_LOOKUP_add_dir(WOLFSSL_X509_LOOKUP*,const char*,long);
WOLFSSL_API int wolfSSL_X509_LOOKUP_load_file(WOLFSSL_X509_LOOKUP*, const char*,
                                            long);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_hash_dir(void);
WOLFSSL_API WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_file(void);
WOLFSSL_API int wolfSSL_X509_LOOKUP_ctrl(WOLFSSL_X509_LOOKUP *ctx, int cmd,
        const char *argc, long argl, char **ret);

WOLFSSL_API WOLFSSL_X509_LOOKUP* wolfSSL_X509_STORE_add_lookup(WOLFSSL_X509_STORE*,
                                                    WOLFSSL_X509_LOOKUP_METHOD*);
WOLFSSL_API WOLFSSL_X509_STORE*  wolfSSL_X509_STORE_new(void);
WOLFSSL_API void         wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE*);
WOLFSSL_API int          wolfSSL_X509_STORE_add_cert(
                                              WOLFSSL_X509_STORE*, WOLFSSL_X509*);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get1_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_X509_STORE_CTX *wolfSSL_X509_STORE_CTX_get0_parent_ctx(
                                                   WOLFSSL_X509_STORE_CTX *ctx);
WOLFSSL_API int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store,
                                                            unsigned long flag);
WOLFSSL_API int          wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE*);
WOLFSSL_API int          wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX*,
                                   int, WOLFSSL_X509_NAME*, WOLFSSL_X509_OBJECT*);
WOLFSSL_API WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void);
WOLFSSL_API int  wolfSSL_X509_STORE_CTX_init(WOLFSSL_X509_STORE_CTX*,
                      WOLFSSL_X509_STORE*, WOLFSSL_X509*, WOLF_STACK_OF(WOLFSSL_X509)*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_trusted_stack(WOLFSSL_X509_STORE_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509) *sk);

WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_lastUpdate(WOLFSSL_X509_CRL*);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_nextUpdate(WOLFSSL_X509_CRL*);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_X509_gmtime_adj(WOLFSSL_ASN1_TIME *s, long adj);

WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_X509_get_pubkey(WOLFSSL_X509*);
WOLFSSL_API int       wolfSSL_X509_CRL_verify(WOLFSSL_X509_CRL*, WOLFSSL_EVP_PKEY*);
WOLFSSL_API void      wolfSSL_X509_OBJECT_free_contents(WOLFSSL_X509_OBJECT*);
WOLFSSL_API WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY_bio(
        WOLFSSL_BIO* bio, WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY_bio(WOLFSSL_BIO* bio,
                                         WOLFSSL_EVP_PKEY** out);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY(WOLFSSL_EVP_PKEY** key,
        const unsigned char** in, long inSz);
WOLFSSL_API int wolfSSL_i2d_PUBKEY(const WOLFSSL_EVP_PKEY *key, unsigned char **der);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey(int type,
        WOLFSSL_EVP_PKEY** out, const unsigned char **in, long inSz);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_EVP(WOLFSSL_EVP_PKEY** key,
        unsigned char** in, long inSz);
WOLFSSL_API int wolfSSL_i2d_PrivateKey(const WOLFSSL_EVP_PKEY* key,
        unsigned char** der);
WOLFSSL_API int       wolfSSL_X509_cmp_current_time(const WOLFSSL_ASN1_TIME*);
#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_X509_cmp_time(const WOLFSSL_ASN1_TIME* asnTime,
        time_t *cmpTime);
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_X509_time_adj_ex(WOLFSSL_ASN1_TIME *asnTime,
    int offset_day, long offset_sec, time_t *in_tm);
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_X509_time_adj(WOLFSSL_ASN1_TIME *asnTime,
    long offset_sec, time_t *in_tm);
WOLFSSL_API int       wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED*);
WOLFSSL_API void      wolfSSL_X509_STORE_CTX_set_time(WOLFSSL_X509_STORE_CTX*,
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
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set1_host(WOLFSSL_X509_VERIFY_PARAM* pParam,
                                                    const char* name,
                                                    unsigned int nameSz);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(
        WOLFSSL_X509_VERIFY_PARAM *param, const char *ipasc);
WOLFSSL_API int wolfSSL_X509_VERIFY_PARAM_set1(WOLFSSL_X509_VERIFY_PARAM* to,
                                    const WOLFSSL_X509_VERIFY_PARAM* from);
WOLFSSL_API int wolfSSL_X509_load_crl_file(WOLFSSL_X509_LOOKUP *ctx, 
                                              const char *file, int type);
#endif
WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_X509_CRL_get_REVOKED(WOLFSSL_X509_CRL*);
WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
                                                      WOLFSSL_X509_REVOKED*,int);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_X509_get_serialNumber(WOLFSSL_X509*);
WOLFSSL_API void wolfSSL_ASN1_INTEGER_free(WOLFSSL_ASN1_INTEGER*);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_new(void);
WOLFSSL_API WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_dup(
                                              const WOLFSSL_ASN1_INTEGER* src);
WOLFSSL_API int wolfSSL_ASN1_INTEGER_set(WOLFSSL_ASN1_INTEGER *a, long v);

WOLFSSL_API int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO*, const WOLFSSL_ASN1_TIME*);

WOLFSSL_API char* wolfSSL_ASN1_TIME_to_string(WOLFSSL_ASN1_TIME* t,
                                                            char* buf, int len);
WOLFSSL_API int  wolfSSL_ASN1_INTEGER_cmp(const WOLFSSL_ASN1_INTEGER*,
                                       const WOLFSSL_ASN1_INTEGER*);
WOLFSSL_API long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER*);

#ifdef OPENSSL_EXTRA
WOLFSSL_API WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
                                       WOLFSSL_BIGNUM *bn);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_adj(WOLFSSL_ASN1_TIME*, time_t,
                                                     int, long);
WOLFSSL_API WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_new(void);
WOLFSSL_API void wolfSSL_ASN1_TIME_free(WOLFSSL_ASN1_TIME* t);
#endif

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_load_client_CA_file(const char*);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_CTX_get_client_CA_list(
        const WOLFSSL_CTX *s);
/* deprecated function name */
#define wolfSSL_SSL_CTX_get_client_CA_list wolfSSL_CTX_get_client_CA_list

WOLFSSL_API void  wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX*,
                                               WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_get_client_CA_list(
            const WOLFSSL* ssl);

typedef int (*client_cert_cb)(WOLFSSL *ssl, WOLFSSL_X509 **x509,
                              WOLFSSL_EVP_PKEY **pkey);
WOLFSSL_API void wolfSSL_CTX_set_client_cert_cb(WOLFSSL_CTX *ctx, client_cert_cb);

WOLFSSL_API void* wolfSSL_X509_STORE_CTX_get_ex_data(
        WOLFSSL_X509_STORE_CTX* ctx, int idx);
WOLFSSL_API int  wolfSSL_X509_STORE_CTX_set_ex_data(WOLFSSL_X509_STORE_CTX* ctx,
        int idx, void *data);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_set_depth(WOLFSSL_X509_STORE_CTX* ctx,
        int depth);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_current_issuer(
        WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_X509_STORE* wolfSSL_X509_STORE_CTX_get0_store(
        WOLFSSL_X509_STORE_CTX* ctx);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_cert(
        WOLFSSL_X509_STORE_CTX*);
WOLFSSL_API int  wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);
WOLFSSL_API void wolfSSL_X509_STORE_CTX_set_error(
                                           WOLFSSL_X509_STORE_CTX* ctx, int er);
void wolfSSL_X509_STORE_CTX_set_error_depth(WOLFSSL_X509_STORE_CTX* ctx,
                                                                     int depth);
WOLFSSL_API void* wolfSSL_get_ex_data(const WOLFSSL*, int);

WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX*,
                                                          void* userdata);
WOLFSSL_API void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX*,
                                                   pem_password_cb*);
WOLFSSL_API pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX *ctx);
WOLFSSL_API void *wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx);

WOLFSSL_API void wolfSSL_CTX_set_info_callback(WOLFSSL_CTX*,
                          void (*)(const WOLFSSL* ssl, int type, int val));

WOLFSSL_API unsigned long wolfSSL_ERR_peek_error(void);
WOLFSSL_API int           wolfSSL_GET_REASON(int);

WOLFSSL_API const char* wolfSSL_alert_type_string_long(int);
WOLFSSL_API const char* wolfSSL_alert_desc_string_long(int);
WOLFSSL_API const char* wolfSSL_state_string_long(const WOLFSSL*);

WOLFSSL_API WOLFSSL_RSA* wolfSSL_RSA_generate_key(int, unsigned long,
                                               void(*)(int, int, void*), void*);
WOLFSSL_API WOLFSSL_RSA *wolfSSL_d2i_RSAPublicKey(WOLFSSL_RSA **r,
                                            const unsigned char **pp, long len);
WOLFSSL_API WOLFSSL_RSA *wolfSSL_d2i_RSAPrivateKey(WOLFSSL_RSA**,
                                            const unsigned char**, long);
WOLFSSL_API int wolfSSL_i2d_RSAPublicKey(WOLFSSL_RSA *r, const unsigned char **pp);
WOLFSSL_API int wolfSSL_i2d_RSAPrivateKey(WOLFSSL_RSA *r, unsigned char **pp);
WOLFSSL_API void wolfSSL_CTX_set_tmp_rsa_callback(WOLFSSL_CTX *,
                                           WOLFSSL_RSA *(*)(WOLFSSL *, int, int));

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

WOLFSSL_API long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX*, WOLFSSL_X509*);
WOLFSSL_API long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX*, long);
WOLFSSL_API long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX*);

WOLFSSL_API long wolfSSL_CTX_get_session_cache_mode(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX*, int v);
WOLFSSL_API long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX*, void* arg);
WOLFSSL_API long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(
        WOLFSSL_CTX*, void* arg);
WOLFSSL_API int  wolfSSL_CTX_add_client_CA(WOLFSSL_CTX*, WOLFSSL_X509*);
WOLFSSL_API int  wolfSSL_CTX_set_srp_password(WOLFSSL_CTX*, char*);
WOLFSSL_API int  wolfSSL_CTX_set_srp_username(WOLFSSL_CTX*, char*);
WOLFSSL_API int  wolfSSL_CTX_set_srp_strength(WOLFSSL_CTX *ctx, int strength);

WOLFSSL_API char* wolfSSL_get_srp_username(WOLFSSL *ssl);

WOLFSSL_API long wolfSSL_set_options(WOLFSSL *s, long op);
WOLFSSL_API long wolfSSL_get_options(const WOLFSSL *s);
WOLFSSL_API long wolfSSL_clear_options(WOLFSSL *s,  long op);
WOLFSSL_API long wolfSSL_clear_num_renegotiations(WOLFSSL *s);
WOLFSSL_API long wolfSSL_total_renegotiations(WOLFSSL *s);
WOLFSSL_API long wolfSSL_num_renegotiations(WOLFSSL* s);
WOLFSSL_API int  wolfSSL_SSL_renegotiate_pending(WOLFSSL *s);
WOLFSSL_API long wolfSSL_set_tmp_dh(WOLFSSL *s, WOLFSSL_DH *dh);
WOLFSSL_API long wolfSSL_set_tlsext_debug_arg(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type);
WOLFSSL_API long wolfSSL_set_tlsext_status_exts(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_tlsext_status_ids(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_set_tlsext_status_ids(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char **resp);
WOLFSSL_API long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char *resp, int len);

WOLFSSL_API void wolfSSL_CONF_modules_unload(int all);
WOLFSSL_API char* wolfSSL_CONF_get1_default_config_file(void);
WOLFSSL_API long wolfSSL_get_tlsext_status_exts(WOLFSSL *s, void *arg);
WOLFSSL_API long wolfSSL_get_verify_result(const WOLFSSL *ssl);

#define WOLFSSL_DEFAULT_CIPHER_LIST ""   /* default all */


/* extras end */

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
/* wolfSSL extension, provide last error from SSL_get_error
   since not using thread storage error queue */
#ifdef FUSION_RTOS
    #include <fclstdio.h>
#else
    #include <stdio.h>
#endif
WOLFSSL_API void  wolfSSL_ERR_print_errors_fp(XFILE, int err);
#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
WOLFSSL_API void wolfSSL_ERR_dump_errors_fp(XFILE fp);
WOLFSSL_API void wolfSSL_ERR_print_errors_cb(int (*cb)(const char *str,
                                                size_t len, void *u), void *u);
#endif
#endif
WOLFSSL_API void wolfSSL_ERR_print_errors(WOLFSSL_BIO *bio);


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
    #define SSL_FILETYPE_RAW WOLFSSL_FILETYPE_RAW

    #define SSL_VERIFY_NONE WOLFSSL_VERIFY_NONE
    #define SSL_VERIFY_PEER WOLFSSL_VERIFY_PEER
    #define SSL_VERIFY_FAIL_IF_NO_PEER_CERT WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
    #define SSL_VERIFY_CLIENT_ONCE WOLFSSL_VERIFY_CLIENT_ONCE
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

    #define PEM_BUFSIZE WOLF_PEM_BUFSIZE
#endif

#ifndef NO_PSK
    typedef unsigned int (*wc_psk_client_callback)(WOLFSSL*, const char*, char*,
                                    unsigned int, unsigned char*, unsigned int);
    WOLFSSL_API void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX*,
                                                    wc_psk_client_callback);
    WOLFSSL_API void wolfSSL_set_psk_client_callback(WOLFSSL*,
                                                    wc_psk_client_callback);
#ifdef WOLFSSL_TLS13
    typedef unsigned int (*wc_psk_client_tls13_callback)(WOLFSSL*, const char*,
               char*, unsigned int, unsigned char*, unsigned int, const char**);
    WOLFSSL_API void wolfSSL_CTX_set_psk_client_tls13_callback(WOLFSSL_CTX*,
                                                  wc_psk_client_tls13_callback);
    WOLFSSL_API void wolfSSL_set_psk_client_tls13_callback(WOLFSSL*,
                                                  wc_psk_client_tls13_callback);
#endif

    WOLFSSL_API const char* wolfSSL_get_psk_identity_hint(const WOLFSSL*);
    WOLFSSL_API const char* wolfSSL_get_psk_identity(const WOLFSSL*);

    WOLFSSL_API int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX*, const char*);
    WOLFSSL_API int wolfSSL_use_psk_identity_hint(WOLFSSL*, const char*);

    typedef unsigned int (*wc_psk_server_callback)(WOLFSSL*, const char*,
                          unsigned char*, unsigned int);
    WOLFSSL_API void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX*,
                                                    wc_psk_server_callback);
    WOLFSSL_API void wolfSSL_set_psk_server_callback(WOLFSSL*,
                                                    wc_psk_server_callback);
#ifdef WOLFSSL_TLS13
    typedef unsigned int (*wc_psk_server_tls13_callback)(WOLFSSL*, const char*,
                          unsigned char*, unsigned int, const char**);
    WOLFSSL_API void wolfSSL_CTX_set_psk_server_tls13_callback(WOLFSSL_CTX*,
                                                  wc_psk_server_tls13_callback);
    WOLFSSL_API void wolfSSL_set_psk_server_tls13_callback(WOLFSSL*,
                                                  wc_psk_server_tls13_callback);
#endif
    WOLFSSL_API void* wolfSSL_get_psk_callback_ctx(WOLFSSL*);
    WOLFSSL_API int   wolfSSL_set_psk_callback_ctx(WOLFSSL*, void*);

    WOLFSSL_API void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX*);
    WOLFSSL_API int   wolfSSL_CTX_set_psk_callback_ctx(WOLFSSL_CTX*, void*);

    #define PSK_TYPES_DEFINED
#endif /* NO_PSK */


#ifdef HAVE_ANON
    WOLFSSL_API int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX*);
#endif /* HAVE_ANON */


WOLFSSL_API void wolfSSL_ERR_put_error(int lib, int fun, int err,
                                       const char* file, int line);
WOLFSSL_API unsigned long wolfSSL_ERR_get_error_line(const char**, int*);
WOLFSSL_API unsigned long wolfSSL_ERR_get_error_line_data(const char**, int*,
                                                 const char**, int *);

WOLFSSL_API unsigned long wolfSSL_ERR_get_error(void);
WOLFSSL_API void          wolfSSL_ERR_clear_error(void);


WOLFSSL_API int  wolfSSL_RAND_status(void);
WOLFSSL_API int  wolfSSL_RAND_pseudo_bytes(unsigned char* buf, int num);
WOLFSSL_API int  wolfSSL_RAND_bytes(unsigned char* buf, int num);
WOLFSSL_API WOLFSSL_METHOD *wolfSSLv23_server_method(void);
WOLFSSL_API long wolfSSL_CTX_set_options(WOLFSSL_CTX*, long);
WOLFSSL_API long wolfSSL_CTX_get_options(WOLFSSL_CTX* ctx);
WOLFSSL_API long wolfSSL_CTX_clear_options(WOLFSSL_CTX*, long);

#if !defined(NO_CHECK_PRIVATE_KEY)
  WOLFSSL_API int  wolfSSL_CTX_check_private_key(const WOLFSSL_CTX*);
#endif
WOLFSSL_API void wolfSSL_ERR_free_strings(void);
WOLFSSL_API void wolfSSL_ERR_remove_state(unsigned long);
WOLFSSL_API int  wolfSSL_clear(WOLFSSL* ssl);
WOLFSSL_API int  wolfSSL_state(WOLFSSL* ssl);

WOLFSSL_API void wolfSSL_cleanup_all_ex_data(void);
WOLFSSL_API long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode);
WOLFSSL_API long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx);
WOLFSSL_API void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m);
WOLFSSL_API long wolfSSL_SSL_get_mode(WOLFSSL* ssl);


WOLFSSL_API int  wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX*);
WOLFSSL_API int  wolfSSL_CTX_set_session_id_context(WOLFSSL_CTX*,
                                            const unsigned char*, unsigned int);
WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL*);
#ifdef OPENSSL_EXTRA
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL*);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_set_peer_cert_chain(WOLFSSL* ssl);
#endif

#ifdef OPENSSL_EXTRA
WOLFSSL_API int wolfSSL_want(WOLFSSL*);
#endif
WOLFSSL_API int wolfSSL_want_read(WOLFSSL*);
WOLFSSL_API int wolfSSL_want_write(WOLFSSL*);

#if !defined(NO_FILESYSTEM) && defined (OPENSSL_EXTRA)
#include <stdarg.h> /* var_arg */
WOLFSSL_API int wolfSSL_BIO_vprintf(WOLFSSL_BIO* bio, const char* format,
                                                            va_list args);
#endif
WOLFSSL_API int wolfSSL_BIO_printf(WOLFSSL_BIO*, const char*, ...);
WOLFSSL_API int wolfSSL_BIO_dump(WOLFSSL_BIO *bio, const char*, int);
WOLFSSL_API int wolfSSL_ASN1_UTCTIME_print(WOLFSSL_BIO*,
                                         const WOLFSSL_ASN1_UTCTIME*);
WOLFSSL_API int wolfSSL_ASN1_GENERALIZEDTIME_print(WOLFSSL_BIO*,
                                         const WOLFSSL_ASN1_GENERALIZEDTIME*);
WOLFSSL_API void wolfSSL_ASN1_GENERALIZEDTIME_free(WOLFSSL_ASN1_GENERALIZEDTIME*);
WOLFSSL_API int wolfSSL_ASN1_TIME_check(const WOLFSSL_ASN1_TIME*);
WOLFSSL_API int wolfSSL_ASN1_TIME_diff(int *pday, int *psec,
                   const WOLFSSL_ASN1_TIME *from, const WOLFSSL_ASN1_TIME *to);
#ifdef OPENSSL_EXTRA
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_ASN1_TIME_set(WOLFSSL_ASN1_TIME *s, time_t t);
WOLFSSL_API int wolfSSL_ASN1_TIME_set_string(WOLFSSL_ASN1_TIME *s, const char *str);
#endif

WOLFSSL_API int wolfSSL_sk_num(const WOLFSSL_STACK* sk);
WOLFSSL_API void* wolfSSL_sk_value(const WOLFSSL_STACK* sk, int i);

#if (defined(HAVE_EX_DATA) || defined(FORTRESS)) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_WPAS_SMALL))
WOLFSSL_API void* wolfSSL_CRYPTO_get_ex_data(const WOLFSSL_CRYPTO_EX_DATA* ex_data,
                                            int idx);
WOLFSSL_API int wolfSSL_CRYPTO_set_ex_data(WOLFSSL_CRYPTO_EX_DATA* ex_data, int idx,
                                            void *data);
#endif

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
WOLFSSL_ABI WOLFSSL_API int wolfSSL_check_domain_name(WOLFSSL*, const char*);

/* need to call once to load library (session cache) */
WOLFSSL_ABI WOLFSSL_API int wolfSSL_Init(void);
/* call when done to cleanup/free session cache mutex / resources  */
WOLFSSL_ABI WOLFSSL_API int wolfSSL_Cleanup(void);

/* which library version do we have */
WOLFSSL_API const char* wolfSSL_lib_version(void);
WOLFSSL_API const char* wolfSSL_OpenSSL_version(void);
/* which library version do we have in hex */
WOLFSSL_API word32 wolfSSL_lib_version_hex(void);

/* do accept or connect depedning on side */
WOLFSSL_API int wolfSSL_negotiate(WOLFSSL* ssl);
/* turn on wolfSSL data compression */
WOLFSSL_API int wolfSSL_set_compression(WOLFSSL* ssl);

WOLFSSL_ABI WOLFSSL_API int wolfSSL_set_timeout(WOLFSSL*, unsigned int);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_set_timeout(WOLFSSL_CTX*, unsigned int);
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
WOLFSSL_API int  wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN*, int idx);
/* index cert */
WOLFSSL_API unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN*, int idx);
/* index cert in X509 */
WOLFSSL_API WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN*, int idx);
/* free X509 */
#define wolfSSL_FreeX509(x509) wolfSSL_X509_free((x509))
WOLFSSL_ABI WOLFSSL_API void wolfSSL_X509_free(WOLFSSL_X509*);
/* get index cert in PEM */
WOLFSSL_API int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN*, int idx,
                                unsigned char* buf, int inLen, int* outLen);
WOLFSSL_ABI WOLFSSL_API const unsigned char* wolfSSL_get_sessionID(
                                                      const WOLFSSL_SESSION* s);
WOLFSSL_API int  wolfSSL_X509_get_serial_number(WOLFSSL_X509*,unsigned char*,int*);
WOLFSSL_API char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509*);
WOLFSSL_API const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509*, int*);
WOLFSSL_API const unsigned char* wolfSSL_X509_get_tbs(WOLFSSL_X509*, int*);
WOLFSSL_ABI WOLFSSL_API const byte* wolfSSL_X509_notBefore(WOLFSSL_X509*);
WOLFSSL_ABI WOLFSSL_API const byte* wolfSSL_X509_notAfter(WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_X509_version(WOLFSSL_X509*);

WOLFSSL_API int wolfSSL_cmp_peer_cert_to_file(WOLFSSL*, const char*);

WOLFSSL_ABI WOLFSSL_API char* wolfSSL_X509_get_next_altname(WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_X509_add_altname_ex(WOLFSSL_X509*, const char*, word32, int);
WOLFSSL_API int wolfSSL_X509_add_altname(WOLFSSL_X509*, const char*, int);

WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509(WOLFSSL_X509** x509,
        const unsigned char** in, int len);
WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_d2i(WOLFSSL_X509** x509, const unsigned char* in, int len);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_REQ_d2i(WOLFSSL_X509** x509, const unsigned char* in, int len);
#endif
WOLFSSL_API int wolfSSL_i2d_X509(WOLFSSL_X509* x509, unsigned char** out);
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_d2i_X509_CRL(WOLFSSL_X509_CRL **crl,
                                                   const unsigned char *in, int len);
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_d2i_X509_CRL_bio(WOLFSSL_BIO *bp, 
                                                    WOLFSSL_X509_CRL **crl);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_d2i_X509_CRL_fp(XFILE file, WOLFSSL_X509_CRL **crl);
#endif
WOLFSSL_API void wolfSSL_X509_CRL_free(WOLFSSL_X509_CRL *crl);

#ifndef NO_FILESYSTEM
    #ifndef NO_STDIO_FILESYSTEM
    WOLFSSL_API WOLFSSL_X509*
        wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, XFILE file);
    #endif
WOLFSSL_ABI WOLFSSL_API WOLFSSL_X509*
    wolfSSL_X509_load_certificate_file(const char* fname, int format);
#endif
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_load_certificate_buffer(
    const unsigned char* buf, int sz, int format);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_REQ_load_certificate_buffer(
    const unsigned char* buf, int sz, int format);
#endif

#ifdef WOLFSSL_SEP
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_device_type(WOLFSSL_X509*, unsigned char*, int*);
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_type(WOLFSSL_X509*, unsigned char*, int*);
    WOLFSSL_API unsigned char*
           wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509*, unsigned char*, int*);
#endif

/* connect enough to get peer cert */
WOLFSSL_API int  wolfSSL_connect_cert(WOLFSSL* ssl);



/* PKCS12 compatibility */
typedef struct WC_PKCS12 WC_PKCS12;
WOLFSSL_API WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12** pkcs12);
WOLFSSL_API int wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO *bio, WC_PKCS12 *pkcs12);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API WOLFSSL_X509_PKCS12* wolfSSL_d2i_PKCS12_fp(XFILE fp,
                                       WOLFSSL_X509_PKCS12** pkcs12);
#endif
WOLFSSL_API int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
     WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert,
     WOLF_STACK_OF(WOLFSSL_X509)** ca);
WOLFSSL_API int wolfSSL_PKCS12_verify_mac(WC_PKCS12 *pkcs12, const char *psw,
        int pswLen);
WOLFSSL_API WC_PKCS12* wolfSSL_PKCS12_create(char* pass, char* name,
        WOLFSSL_EVP_PKEY* pkey, WOLFSSL_X509* cert,
        WOLF_STACK_OF(WOLFSSL_X509)* ca,
        int keyNID, int certNID, int itt, int macItt, int keytype);
WOLFSSL_API void wolfSSL_PKCS12_PBE_add(void);



#ifndef NO_DH
/* server Diffie-Hellman parameters */
WOLFSSL_API int  wolfSSL_SetTmpDH(WOLFSSL*, const unsigned char* p, int pSz,
                                const unsigned char* g, int gSz);
WOLFSSL_API int  wolfSSL_SetTmpDH_buffer(WOLFSSL*, const unsigned char* b, long sz,
                                       int format);
WOLFSSL_API int wolfSSL_SetEnableDhKeyTest(WOLFSSL*, int);
#ifndef NO_FILESYSTEM
    WOLFSSL_API int  wolfSSL_SetTmpDH_file(WOLFSSL*, const char* f, int format);
#endif

/* server ctx Diffie-Hellman parameters */
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX*, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);
WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX*, const unsigned char* b,
                                           long sz, int format);

#ifndef NO_FILESYSTEM
    WOLFSSL_API int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX*, const char* f,
                                             int format);
#endif

WOLFSSL_API int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX*, word16);
WOLFSSL_API int wolfSSL_SetMinDhKey_Sz(WOLFSSL*, word16);
WOLFSSL_API int wolfSSL_CTX_SetMaxDhKey_Sz(WOLFSSL_CTX*, word16);
WOLFSSL_API int wolfSSL_SetMaxDhKey_Sz(WOLFSSL*, word16);
WOLFSSL_API int wolfSSL_GetDhKey_Sz(WOLFSSL*);
#endif /* NO_DH */

#ifndef NO_RSA
WOLFSSL_API int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX*, short);
WOLFSSL_API int wolfSSL_SetMinRsaKey_Sz(WOLFSSL*, short);
#endif /* NO_RSA */

#ifdef HAVE_ECC
WOLFSSL_API int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX*, short);
WOLFSSL_API int wolfSSL_SetMinEccKey_Sz(WOLFSSL*, short);
#endif /* NO_RSA */

WOLFSSL_API int  wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL*, word16);
WOLFSSL_API int  wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX*, word16);

/* keyblock size in bytes or -1 */
/* need to call wolfSSL_KeepArrays before handshake to save keys */
WOLFSSL_API int wolfSSL_get_keyblock_size(WOLFSSL*);
WOLFSSL_API int wolfSSL_get_keys(WOLFSSL*,unsigned char** ms, unsigned int* msLen,
                                       unsigned char** sr, unsigned int* srLen,
                                       unsigned char** cr, unsigned int* crLen);

/* Computes EAP-TLS and EAP-TTLS keying material from the master_secret. */
WOLFSSL_API int wolfSSL_make_eap_keys(WOLFSSL*, void* key, unsigned int len,
                                                             const char* label);


#ifndef _WIN32
    #ifndef NO_WRITEV
        #ifdef __PPU
            #include <sys/types.h>
            #include <sys/socket.h>
        #elif !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_IAR_ARM) && \
              !defined(WOLFSSL_PICOTCP) && !defined(WOLFSSL_ROWLEY_ARM) && \
              !defined(WOLFSSL_EMBOS) && !defined(WOLFSSL_FROSTED) && \
              !defined(WOLFSSL_CHIBIOS) && !defined(WOLFSSL_CONTIKI) && \
              !defined(WOLFSSL_ZEPHYR)
            #include <sys/uio.h>
        #endif
        /* allow writev style writing */
        WOLFSSL_API int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);
    #endif
#endif


#ifndef NO_CERTS
    /* SSL_CTX versions */
    WOLFSSL_API int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX*);
#ifdef WOLFSSL_TRUST_PEER_CERT
    WOLFSSL_API int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX*);
    WOLFSSL_API int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
#endif
    WOLFSSL_API int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX*,
                                               const unsigned char*, long, int,
                                               int, word32);
    WOLFSSL_API int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_load_verify_chain_buffer_format(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_id(WOLFSSL_CTX*,
                                                  const unsigned char*, long,
                                                  int, long);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_Id(WOLFSSL_CTX*,
                                                  const unsigned char*, long,
                                                  int);
    WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_Label(WOLFSSL_CTX*, const char*,
                                                     int);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX*,
                                                    const unsigned char*, long);

    /* SSL versions */
    WOLFSSL_API int wolfSSL_use_certificate_buffer(WOLFSSL*, const unsigned char*,
                                               long, int);
    WOLFSSL_API int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl,
                                           const unsigned char* der, int derSz);
    WOLFSSL_API int wolfSSL_use_PrivateKey_buffer(WOLFSSL*, const unsigned char*,
                                               long, int);
    WOLFSSL_API int wolfSSL_use_PrivateKey_id(WOLFSSL*, const unsigned char*,
                                              long, int, long);
    WOLFSSL_API int wolfSSL_use_PrivateKey_Id(WOLFSSL*, const unsigned char*,
                                              long, int);
    WOLFSSL_API int wolfSSL_use_PrivateKey_Label(WOLFSSL*, const char*, int);
    WOLFSSL_API int wolfSSL_use_certificate_chain_buffer_format(WOLFSSL*,
                                               const unsigned char*, long, int);
    WOLFSSL_API int wolfSSL_use_certificate_chain_buffer(WOLFSSL*,
                                               const unsigned char*, long);
    WOLFSSL_API int wolfSSL_UnloadCertsKeys(WOLFSSL*);

    #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
        defined(KEEP_OUR_CERT)
        WOLFSSL_API WOLFSSL_X509* wolfSSL_get_certificate(WOLFSSL* ssl);
        WOLFSSL_API WOLFSSL_X509* wolfSSL_CTX_get0_certificate(WOLFSSL_CTX* ctx);
    #endif
#endif

WOLFSSL_API int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX*);
WOLFSSL_API int wolfSSL_set_group_messages(WOLFSSL*);

WOLFSSL_API int   wolfSSL_DTLS_SetCookieSecret(WOLFSSL*, const byte*, word32);

WOLFSSL_ABI WOLFSSL_API WC_RNG* wolfSSL_GetRNG(WOLFSSL*);

WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX*, int);
WOLFSSL_API int wolfSSL_SetMinVersion(WOLFSSL*, int);
WOLFSSL_API int wolfSSL_GetObjectSize(void);  /* object size based on build */
WOLFSSL_API int wolfSSL_CTX_GetObjectSize(void);
WOLFSSL_API int wolfSSL_METHOD_GetObjectSize(void);
WOLFSSL_API int wolfSSL_GetOutputSize(WOLFSSL*, int);
WOLFSSL_API int wolfSSL_GetMaxOutputSize(WOLFSSL*);
WOLFSSL_API int wolfSSL_GetVersion(const WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SetVersion(WOLFSSL* ssl, int version);

/* moved to asn.c, old names kept for backwards compatibility */
#define wolfSSL_KeyPemToDer    wc_KeyPemToDer
#define wolfSSL_CertPemToDer   wc_CertPemToDer
#define wolfSSL_PemPubKeyToDer wc_PemPubKeyToDer
#define wolfSSL_PubKeyPemToDer wc_PubKeyPemToDer
#define wolfSSL_PemCertToDer   wc_PemCertToDer

/* User Atomic Record Layer CallBacks */
WOLFSSL_API void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX*, CallbackMacEncrypt);
WOLFSSL_API void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

WOLFSSL_API void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX*,
                                                 CallbackDecryptVerify);
WOLFSSL_API void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

WOLFSSL_API void  wolfSSL_CTX_SetEncryptMacCb(WOLFSSL_CTX*, CallbackEncryptMac);
WOLFSSL_API void  wolfSSL_SetEncryptMacCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEncryptMacCtx(WOLFSSL* ssl);

WOLFSSL_API void  wolfSSL_CTX_SetVerifyDecryptCb(WOLFSSL_CTX*,
                                                 CallbackVerifyDecrypt);
WOLFSSL_API void  wolfSSL_SetVerifyDecryptCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetVerifyDecryptCtx(WOLFSSL* ssl);

WOLFSSL_API const unsigned char* wolfSSL_GetMacSecret(WOLFSSL*, int);
WOLFSSL_API const unsigned char* wolfSSL_GetDtlsMacSecret(WOLFSSL*, int, int);
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL*);
WOLFSSL_API const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL*);
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL*);
WOLFSSL_API const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetKeySize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetIVSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetSide(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_IsTLSv1_1(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetBulkCipher(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetCipherBlockSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetAeadMacSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetHmacSize(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetHmacType(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_GetCipherType(WOLFSSL*);
WOLFSSL_API int                  wolfSSL_SetTlsHmacInner(WOLFSSL*, unsigned char*,
                                                       word32, int, int);

/* Public Key Callback support */
#ifdef HAVE_PK_CALLBACKS
#ifdef HAVE_ECC

struct ecc_key;

typedef int (*CallbackEccKeyGen)(WOLFSSL* ssl, struct ecc_key* key,
    unsigned int keySz, int ecc_curve, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEccKeyGenCb(WOLFSSL_CTX*, CallbackEccKeyGen);
WOLFSSL_API void  wolfSSL_SetEccKeyGenCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccKeyGenCtx(WOLFSSL* ssl);

typedef int (*CallbackEccSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_ABI WOLFSSL_API void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX*,
                                                               CallbackEccSign);
WOLFSSL_API void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

typedef int (*CallbackEccVerify)(WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* hash, unsigned int hashSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX*, CallbackEccVerify);
WOLFSSL_API void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

typedef int (*CallbackEccSharedSecret)(WOLFSSL* ssl, struct ecc_key* otherKey,
        unsigned char* pubKeyDer, word32* pubKeySz,
        unsigned char* out, word32* outlen,
        int side, void* ctx); /* side is WOLFSSL_CLIENT_END or WOLFSSL_SERVER_END */
WOLFSSL_API void  wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX*, CallbackEccSharedSecret);
WOLFSSL_API void  wolfSSL_SetEccSharedSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEccSharedSecretCtx(WOLFSSL* ssl);
#endif

#ifndef NO_DH
/* Public DH Key Callback support */
struct DhKey;
typedef int (*CallbackDhAgree)(WOLFSSL* ssl, struct DhKey* key,
        const unsigned char* priv, unsigned int privSz,
        const unsigned char* otherPubKeyDer, unsigned int otherPubKeySz,
        unsigned char* out, word32* outlen,
        void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetDhAgreeCb(WOLFSSL_CTX*, CallbackDhAgree);
WOLFSSL_API void  wolfSSL_SetDhAgreeCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetDhAgreeCtx(WOLFSSL* ssl);
#endif /* !NO_DH */

#ifdef HAVE_ED25519
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
#endif

#ifdef HAVE_CURVE25519
struct curve25519_key;

typedef int (*CallbackX25519KeyGen)(WOLFSSL* ssl, struct curve25519_key* key,
    unsigned int keySz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetX25519KeyGenCb(WOLFSSL_CTX*, CallbackX25519KeyGen);
WOLFSSL_API void  wolfSSL_SetX25519KeyGenCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX25519KeyGenCtx(WOLFSSL* ssl);

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
#endif

#ifdef HAVE_ED448
struct ed448_key;
typedef int (*CallbackEd448Sign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd448SignCb(WOLFSSL_CTX*,
                                               CallbackEd448Sign);
WOLFSSL_API void  wolfSSL_SetEd448SignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd448SignCtx(WOLFSSL* ssl);

typedef int (*CallbackEd448Verify)(WOLFSSL* ssl,
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* msg, unsigned int msgSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetEd448VerifyCb(WOLFSSL_CTX*,
                                                 CallbackEd448Verify);
WOLFSSL_API void  wolfSSL_SetEd448VerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetEd448VerifyCtx(WOLFSSL* ssl);
#endif

#ifdef HAVE_CURVE448
struct curve448_key;

typedef int (*CallbackX448KeyGen)(WOLFSSL* ssl, struct curve448_key* key,
    unsigned int keySz, void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetX448KeyGenCb(WOLFSSL_CTX*, CallbackX448KeyGen);
WOLFSSL_API void  wolfSSL_SetX448KeyGenCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX448KeyGenCtx(WOLFSSL* ssl);

typedef int (*CallbackX448SharedSecret)(WOLFSSL* ssl,
        struct curve448_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx);
        /* side is WOLFSSL_CLIENT_END or WOLFSSL_SERVER_END */
WOLFSSL_API void  wolfSSL_CTX_SetX448SharedSecretCb(WOLFSSL_CTX*,
        CallbackX448SharedSecret);
WOLFSSL_API void  wolfSSL_SetX448SharedSecretCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetX448SharedSecretCtx(WOLFSSL* ssl);
#endif

#ifndef NO_RSA
typedef int (*CallbackRsaSign)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX*, CallbackRsaSign);
WOLFSSL_API void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

typedef int (*CallbackRsaVerify)(WOLFSSL* ssl,
       unsigned char* sig, unsigned int sigSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX*, CallbackRsaVerify);
WOLFSSL_API void  wolfSSL_CTX_SetRsaSignCheckCb(WOLFSSL_CTX*, CallbackRsaVerify);
WOLFSSL_API void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);
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
WOLFSSL_API void  wolfSSL_CTX_SetRsaPssSignCheckCb(WOLFSSL_CTX*,
                                                    CallbackRsaPssVerify);
WOLFSSL_API void  wolfSSL_SetRsaPssVerifyCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaPssVerifyCtx(WOLFSSL* ssl);
#endif

/* RSA Public Encrypt cb */
typedef int (*CallbackRsaEnc)(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX*, CallbackRsaEnc);
WOLFSSL_API void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/* RSA Private Decrypt cb */
typedef int (*CallbackRsaDec)(WOLFSSL* ssl,
       unsigned char* in, unsigned int inSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);
WOLFSSL_API void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX*, CallbackRsaDec);
WOLFSSL_API void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);
WOLFSSL_API void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);
#endif
#endif /* HAVE_PK_CALLBACKS */

#ifndef NO_CERTS
    WOLFSSL_API void wolfSSL_CTX_SetCACb(WOLFSSL_CTX*, CallbackCACache);

    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CTX_GetCertManager(WOLFSSL_CTX*);

    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);
    WOLFSSL_API WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);
    WOLFSSL_API void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER*);
    WOLFSSL_API int wolfSSL_CertManager_up_ref(WOLFSSL_CERT_MANAGER*);

    WOLFSSL_API int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER*, const char* f,
                                                                 const char* d);
    WOLFSSL_API int wolfSSL_CertManagerLoadCABuffer(WOLFSSL_CERT_MANAGER*,
                                  const unsigned char* in, long sz, int format);
    WOLFSSL_API int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);
#ifdef WOLFSSL_TRUST_PEER_CERT
    WOLFSSL_API int wolfSSL_CertManagerUnload_trust_peers(WOLFSSL_CERT_MANAGER* cm);
#endif
    WOLFSSL_API int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER*, const char* f,
                                                                    int format);
    WOLFSSL_API int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* buff, long sz, int format);
    WOLFSSL_API int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER*,
                                                        unsigned char*, int sz);
    WOLFSSL_API int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER*,
                                                                   int options);
    WOLFSSL_API int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER*);
    WOLFSSL_API void wolfSSL_CertManagerSetVerify(WOLFSSL_CERT_MANAGER* cm,
            VerifyCallback vc);
    WOLFSSL_API int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER*,
                                                         const char*, int, int);
    WOLFSSL_API int wolfSSL_CertManagerLoadCRLBuffer(WOLFSSL_CERT_MANAGER*,
                                            const unsigned char*, long sz, int);
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER*,
                                                                  CbMissingCRL);
    WOLFSSL_API int wolfSSL_CertManagerFreeCRL(WOLFSSL_CERT_MANAGER *);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_CertManagerSetCRL_IOCb(WOLFSSL_CERT_MANAGER*,
                                                                       CbCrlIO);
#endif
#if defined(HAVE_OCSP)
    WOLFSSL_API int wolfSSL_CertManagerCheckOCSPResponse(WOLFSSL_CERT_MANAGER *,
        byte *response, int responseSz, WOLFSSL_BUFFER_INFO *responseBuffer,
        CertStatus *status, OcspEntry *entry, OcspRequest *ocspRequest);
#endif
    WOLFSSL_API int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER*,
                                                        unsigned char*, int sz);
    WOLFSSL_API int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER*,
                                                                   int options);
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER*);
    WOLFSSL_API int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER*,
                                                                   const char*);
    WOLFSSL_API int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER*,
                                               CbOCSPIO, CbOCSPRespFree, void*);

    WOLFSSL_API int wolfSSL_CertManagerEnableOCSPStapling(
                                                      WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSPStapling(
                                                      WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerEnableOCSPMustStaple(
                                                      WOLFSSL_CERT_MANAGER* cm);
    WOLFSSL_API int wolfSSL_CertManagerDisableOCSPMustStaple(
                                                      WOLFSSL_CERT_MANAGER* cm);
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
WOLFSSL_API WOLFSSL_STACK* wolfSSL_CertManagerGetCerts(WOLFSSL_CERT_MANAGER* cm);
#endif
    WOLFSSL_API int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);
    WOLFSSL_API int wolfSSL_DisableCRL(WOLFSSL* ssl);
    WOLFSSL_API int wolfSSL_LoadCRL(WOLFSSL*, const char*, int, int);
    WOLFSSL_API int wolfSSL_LoadCRLBuffer(WOLFSSL*,
                                          const unsigned char*, long sz, int);
    WOLFSSL_API int wolfSSL_SetCRL_Cb(WOLFSSL*, CbMissingCRL);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb);
#endif
    WOLFSSL_API int wolfSSL_EnableOCSP(WOLFSSL*, int options);
    WOLFSSL_API int wolfSSL_DisableOCSP(WOLFSSL*);
    WOLFSSL_API int wolfSSL_SetOCSP_OverrideURL(WOLFSSL*, const char*);
    WOLFSSL_API int wolfSSL_SetOCSP_Cb(WOLFSSL*, CbOCSPIO, CbOCSPRespFree, void*);
    WOLFSSL_API int wolfSSL_EnableOCSPStapling(WOLFSSL*);
    WOLFSSL_API int wolfSSL_DisableOCSPStapling(WOLFSSL*);

    WOLFSSL_API int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);
    WOLFSSL_API int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);
    WOLFSSL_API int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX*, const char*, int, int);
    WOLFSSL_API int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX*,
                                            const unsigned char*, long sz, int);
    WOLFSSL_API int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX*, CbMissingCRL);
#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX*, CbCrlIO);
#endif

    WOLFSSL_API int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX*, int options);
    WOLFSSL_API int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX*);
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX*, const char*);
    WOLFSSL_API int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX*,
                                               CbOCSPIO, CbOCSPRespFree, void*);
    WOLFSSL_API int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX*);
    WOLFSSL_API int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX*);
    WOLFSSL_API int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX*);
    WOLFSSL_API int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX*);
#endif /* !NO_CERTS */


#ifdef SINGLE_THREADED
    WOLFSSL_API int wolfSSL_CTX_new_rng(WOLFSSL_CTX*);
#endif

/* end of handshake frees temporary arrays, if user needs for get_keys or
   psk hints, call KeepArrays before handshake and then FreeArrays when done
   if don't want to wait for object free */
WOLFSSL_API void wolfSSL_KeepArrays(WOLFSSL*);
WOLFSSL_API void wolfSSL_FreeArrays(WOLFSSL*);

WOLFSSL_API int wolfSSL_KeepHandshakeResources(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_FreeHandshakeResources(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_CTX_UseClientSuites(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_UseClientSuites(WOLFSSL* ssl);

/* async additions */
#define wolfSSL_UseAsync wolfSSL_SetDevId
#define wolfSSL_CTX_UseAsync wolfSSL_CTX_SetDevId
WOLFSSL_ABI WOLFSSL_API int wolfSSL_SetDevId(WOLFSSL*, int devId);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_SetDevId(WOLFSSL_CTX*, int devId);

/* helpers to get device id and heap */
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_GetDevId(WOLFSSL_CTX*, WOLFSSL*);
WOLFSSL_API void* wolfSSL_CTX_GetHeap(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/* TLS Extensions */

/* Server Name Indication */
#ifdef HAVE_SNI

WOLFSSL_ABI WOLFSSL_API int wolfSSL_UseSNI(WOLFSSL*, unsigned char,
                                                   const void*, unsigned short);
WOLFSSL_ABI WOLFSSL_API int wolfSSL_CTX_UseSNI(WOLFSSL_CTX*, unsigned char,
                                                   const void*, unsigned short);

#ifndef NO_WOLFSSL_SERVER

WOLFSSL_API void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, unsigned char type,
                                                         unsigned char options);
WOLFSSL_API void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx,
                                     unsigned char type, unsigned char options);
WOLFSSL_API int wolfSSL_SNI_GetFromBuffer(
                 const unsigned char* clientHello, unsigned int helloSz,
                 unsigned char type, unsigned char* sni, unsigned int* inOutSz);

#endif /* NO_WOLFSSL_SERVER */

WOLFSSL_API unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type);

WOLFSSL_API unsigned short wolfSSL_SNI_GetRequest(WOLFSSL *ssl,
                                               unsigned char type, void** data);

#endif /* HAVE_SNI */

/* Trusted CA Key Indication - RFC 6066 (Section 6) */
#ifdef HAVE_TRUSTED_CA
WOLFSSL_API int wolfSSL_UseTrustedCA(WOLFSSL* ssl, unsigned char type,
            const unsigned char* certId, unsigned int certIdSz);
#endif /* HAVE_TRUSTED_CA */

/* Application-Layer Protocol Negotiation */
#ifdef HAVE_ALPN
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

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
#ifndef NO_WOLFSSL_CLIENT

WOLFSSL_API int wolfSSL_UseOCSPStapling(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

WOLFSSL_API int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

#endif
#endif

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
#ifndef NO_WOLFSSL_CLIENT

WOLFSSL_API int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

WOLFSSL_API int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

#endif
#endif

#ifdef HAVE_SUPPORTED_CURVES
WOLFSSL_API int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name);
WOLFSSL_API int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           word16 name);
#endif

#ifdef WOLFSSL_TLS13
WOLFSSL_API int wolfSSL_UseKeyShare(WOLFSSL* ssl, word16 group);
WOLFSSL_API int wolfSSL_NoKeyShares(WOLFSSL* ssl);
#endif


/* Secure Renegotiation */
#ifdef HAVE_SECURE_RENEGOTIATION

WOLFSSL_API int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_StartSecureRenegotiation(WOLFSSL* ssl, int resume);
WOLFSSL_API int wolfSSL_Rehandshake(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SecureResume(WOLFSSL* ssl);
WOLFSSL_API long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl);

#endif

/* Session Ticket */
#ifdef HAVE_SESSION_TICKET

#ifndef NO_WOLFSSL_CLIENT
WOLFSSL_API int wolfSSL_UseSessionTicket(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_get_SessionTicket(WOLFSSL*, unsigned char*, word32*);
WOLFSSL_API int wolfSSL_set_SessionTicket(WOLFSSL*, const unsigned char*, word32);
WOLFSSL_API int wolfSSL_set_SessionTicket_cb(WOLFSSL*,
                                                  CallbackSessionTicket, void*);
#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER

WOLFSSL_API int wolfSSL_CTX_NoTicketTLSv12(WOLFSSL_CTX* ctx);
WOLFSSL_API int wolfSSL_NoTicketTLSv12(WOLFSSL* ssl);

WOLFSSL_API int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb);
WOLFSSL_API int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int);
WOLFSSL_API int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void*);
WOLFSSL_API void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx);

#endif /* NO_WOLFSSL_SERVER */

#endif /* HAVE_SESSION_TICKET */

#ifdef HAVE_QSH
/* test if the connection is using a QSH secure connection return 1 if so */
WOLFSSL_API int wolfSSL_isQSH(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_UseSupportedQSH(WOLFSSL* ssl, unsigned short name);
#ifndef NO_WOLFSSL_CLIENT
    /* user control over sending client public key in hello
       when flag = 1 will send keys if flag is 0 or function is not called
       then will not send keys in the hello extension */
    WOLFSSL_API int wolfSSL_UseClientQSHKeys(WOLFSSL* ssl, unsigned char flag);
#endif
#endif /* QSH */

/* TLS Extended Master Secret Extension */
WOLFSSL_API int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx);


#define WOLFSSL_CRL_MONITOR   0x01   /* monitor this dir flag */
#define WOLFSSL_CRL_START_MON 0x02   /* start monitoring flag */


/* notify user the handshake is done */
WOLFSSL_API int wolfSSL_SetHsDoneCb(WOLFSSL*, HandShakeDoneCb, void*);


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
/* wolfSSL connect extension allowing HandShakeCallBack and/or TimeoutCallBack
   for diagnostics */
WOLFSSL_API int wolfSSL_connect_ex(WOLFSSL*, HandShakeCallBack, TimeoutCallBack,
                                 WOLFSSL_TIMEVAL);
WOLFSSL_API int wolfSSL_accept_ex(WOLFSSL*, HandShakeCallBack, TimeoutCallBack,
                                WOLFSSL_TIMEVAL);
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

WOLFSSL_API int wolfSSL_X509_NAME_get_index_by_OBJ(WOLFSSL_X509_NAME *name,
                                                   const WOLFSSL_ASN1_OBJECT *obj,
                                                   int idx);

/* Object functions */
WOLFSSL_API const char* wolfSSL_OBJ_nid2sn(int n);
WOLFSSL_API int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o);
WOLFSSL_API int wolfSSL_OBJ_get_type(const WOLFSSL_ASN1_OBJECT *o);
WOLFSSL_API int wolfSSL_OBJ_sn2nid(const char *sn);

WOLFSSL_API const char* wolfSSL_OBJ_nid2ln(int n);
WOLFSSL_API int wolfSSL_OBJ_ln2nid(const char *ln);
WOLFSSL_API int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a,
            const WOLFSSL_ASN1_OBJECT* b);
WOLFSSL_API int wolfSSL_OBJ_txt2nid(const char *sn);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name);

WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj(int n);
WOLFSSL_LOCAL WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj_ex(int n, WOLFSSL_ASN1_OBJECT *arg_obj);
WOLFSSL_API int wolfSSL_OBJ_obj2txt(char *buf, int buf_len, WOLFSSL_ASN1_OBJECT *a, int no_name);

WOLFSSL_API void wolfSSL_OBJ_cleanup(void);
WOLFSSL_API int wolfSSL_OBJ_create(const char *oid, const char *sn, const char *ln);
#ifdef HAVE_ECC
WOLFSSL_LOCAL int NIDToEccEnum(int n);
#endif
/* end of object functions */

WOLFSSL_API unsigned long wolfSSL_ERR_peek_last_error_line(const char **file, int *line);
WOLFSSL_API long wolfSSL_CTX_ctrl(WOLFSSL_CTX* ctx, int cmd, long opt,void* pt);
WOLFSSL_API long wolfSSL_CTX_callback_ctrl(WOLFSSL_CTX* ctx, int cmd, void (*fp)(void));
WOLFSSL_API long wolfSSL_CTX_clear_extra_chain_certs(WOLFSSL_CTX* ctx);

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
WOLFSSL_API int wolfSSL_X509_NAME_add_entry_by_NID(WOLFSSL_X509_NAME *name, int nid,
                                           int type, const unsigned char *bytes,
                                           int len, int loc, int set);
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY *wolfSSL_X509_NAME_delete_entry(
        WOLFSSL_X509_NAME *name, int loc);
WOLFSSL_API int wolfSSL_X509_NAME_cmp(const WOLFSSL_X509_NAME* x,
            const WOLFSSL_X509_NAME* y);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_NAME_new(void);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_dup(WOLFSSL_X509*);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_NAME_dup(WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_X509_NAME_copy(WOLFSSL_X509_NAME*, WOLFSSL_X509_NAME*);
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

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
WOLFSSL_API int wolfSSL_X509_cmp(const WOLFSSL_X509* a, const WOLFSSL_X509* b);
WOLFSSL_API const WOLFSSL_STACK *wolfSSL_X509_get0_extensions(const WOLFSSL_X509 *x);
WOLFSSL_API const WOLFSSL_STACK *wolfSSL_X509_REQ_get_extensions(const WOLFSSL_X509 *x);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_get_ext(const WOLFSSL_X509* x, int loc);
WOLFSSL_API int wolfSSL_X509_get_ext_by_OBJ(const WOLFSSL_X509 *x,
        const WOLFSSL_ASN1_OBJECT *obj, int lastpos);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_set_ext(WOLFSSL_X509* x, int loc);
WOLFSSL_API int wolfSSL_X509_EXTENSION_get_critical(const WOLFSSL_X509_EXTENSION* ex);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_new(void);
WOLFSSL_API int wolfSSL_sk_X509_EXTENSION_push(WOLFSSL_STACK* sk,
                                       WOLFSSL_X509_EXTENSION* ext);
WOLFSSL_API void wolfSSL_sk_X509_EXTENSION_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_X509_EXTENSION_free(WOLFSSL_X509_EXTENSION* ext_to_free);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_new_x509_ext(void);
#endif

WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_X509_EXTENSION_get_object(WOLFSSL_X509_EXTENSION* ext);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_X509_EXTENSION_get_data(WOLFSSL_X509_EXTENSION* ext);
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
WOLFSSL_API WOLFSSL_STACK* wolfSSL_X509_STORE_GetCerts(WOLFSSL_X509_STORE_CTX* s);
#endif
WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio,
                                               WOLFSSL_X509** x509);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509* wolfSSL_d2i_X509_REQ_bio(WOLFSSL_BIO* bio,
                                               WOLFSSL_X509** x509);
#endif
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);
WOLFSSL_API WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(WOLFSSL_CTX* ctx);
WOLFSSL_API size_t wolfSSL_get_server_random(const WOLFSSL *ssl,
                                             unsigned char *out, size_t outlen);
WOLFSSL_API size_t wolfSSL_get_client_random(const WOLFSSL* ssl,
                                              unsigned char* out, size_t outSz);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
WOLFSSL_API size_t wolfSSL_BIO_wpending(const WOLFSSL_BIO *bio);
WOLFSSL_API int wolfSSL_BIO_supports_pending(const WOLFSSL_BIO *bio);
WOLFSSL_API size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *b);

WOLFSSL_API int wolfSSL_get_server_tmp_key(const WOLFSSL*, WOLFSSL_EVP_PKEY**);

WOLFSSL_API int wolfSSL_CTX_set_min_proto_version(WOLFSSL_CTX*, int);
WOLFSSL_API int wolfSSL_CTX_set_max_proto_version(WOLFSSL_CTX*, int);
WOLFSSL_API int wolfSSL_CTX_get_min_proto_version(WOLFSSL_CTX*);

WOLFSSL_API int wolfSSL_CTX_use_PrivateKey(WOLFSSL_CTX *ctx, WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509(WOLFSSL_BIO *bp, WOLFSSL_X509 **x, pem_password_cb *cb, void *u);
#ifdef WOLFSSL_CERT_REQ
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_REQ(WOLFSSL_BIO *bp, WOLFSSL_X509 **x, pem_password_cb *cb, void *u);
#endif
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_PEM_read_bio_X509_CRL(WOLFSSL_BIO *bp,
        WOLFSSL_X509_CRL **x, pem_password_cb *cb, void *u);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_AUX
        (WOLFSSL_BIO *bp, WOLFSSL_X509 **x, pem_password_cb *cb, void *u);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_INFO)* wolfSSL_PEM_X509_INFO_read_bio(
        WOLFSSL_BIO* bio, WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk,
        pem_password_cb* cb, void* u);
#ifndef NO_FILESYSTEM
WOLFSSL_API WOLFSSL_X509_CRL *wolfSSL_PEM_read_X509_CRL(XFILE fp,
        WOLFSSL_X509_CRL **x, pem_password_cb *cb, void *u);
#endif
WOLFSSL_API int wolfSSL_PEM_get_EVP_CIPHER_INFO(const char* header,
                                                EncryptedInfo* cipher);
WOLFSSL_API int wolfSSL_PEM_do_header(EncryptedInfo* cipher,
                                      unsigned char* data, long* len,
                                      pem_password_cb* callback, void* ctx);
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */

/*lighttp compatibility */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(OPENSSL_EXTRA_X509_SMALL)

WOLFSSL_API WOLFSSL_X509_NAME_ENTRY *wolfSSL_X509_NAME_get_entry(WOLFSSL_X509_NAME *name, int loc);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)|| \
    defined(OPENSSL_EXTRA_X509_SMALL)

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
WOLFSSL_API void wolfSSL_X509_NAME_free(WOLFSSL_X509_NAME* name);
WOLFSSL_API char wolfSSL_CTX_use_certificate(WOLFSSL_CTX*, WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_CTX_add1_chain_cert(WOLFSSL_CTX*, WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_BIO_read_filename(WOLFSSL_BIO *b, const char *name);
/* These are to be merged shortly */
WOLFSSL_API void wolfSSL_set_verify_depth(WOLFSSL *ssl,int depth);
WOLFSSL_API void* wolfSSL_get_app_data( const WOLFSSL *ssl);
WOLFSSL_API int wolfSSL_set_app_data(WOLFSSL *ssl, void *arg);
WOLFSSL_API WOLFSSL_ASN1_OBJECT * wolfSSL_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY *ne);
WOLFSSL_API unsigned char *wolfSSL_SHA1(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA224(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA256(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA384(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API unsigned char *wolfSSL_SHA512(const unsigned char *d, size_t n, unsigned char *md);
WOLFSSL_API int wolfSSL_X509_check_private_key(WOLFSSL_X509*, WOLFSSL_EVP_PKEY*);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME) *wolfSSL_dup_CA_list( WOLF_STACK_OF(WOLFSSL_X509_NAME) *sk );
WOLFSSL_API int wolfSSL_X509_check_ca(WOLFSSL_X509 *x509);

#ifndef NO_FILESYSTEM
WOLFSSL_API long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c);
WOLFSSL_API long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_fp(XFILE fp, int c);
#endif

#endif /* OPENSSL_EXTRA || OPENSSL_ALL || HAVE_LIGHTY || WOLFSSL_MYSQL_COMPATIBLE || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

#endif /* OPENSSL_EXTRA || OPENSSL_ALL */


#if defined(OPENSSL_ALL) \
    || defined(HAVE_STUNNEL) \
    || defined(HAVE_LIGHTY) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) \
    || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA)
#define X509_BUFFER_SZ 8192

WOLFSSL_API WOLFSSL_BIO* wolfSSL_BIO_new_file(const char *filename, const char *mode);
WOLFSSL_API long wolfSSL_CTX_set_tmp_dh(WOLFSSL_CTX*, WOLFSSL_DH*);
WOLFSSL_API WOLFSSL_DH *wolfSSL_PEM_read_bio_DHparams(WOLFSSL_BIO *bp,
    WOLFSSL_DH **x, pem_password_cb *cb, void *u);
WOLFSSL_API WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp,
    WOLFSSL_DSA **x, pem_password_cb *cb, void *u);
WOLFSSL_API int wolfSSL_PEM_write_bio_X509_REQ(WOLFSSL_BIO *bp,WOLFSSL_X509 *x);
WOLFSSL_API int wolfSSL_PEM_write_bio_X509_AUX(WOLFSSL_BIO *bp,WOLFSSL_X509 *x);
WOLFSSL_API int wolfSSL_PEM_write_bio_X509(WOLFSSL_BIO *bp, WOLFSSL_X509 *x);
#endif /* HAVE_STUNNEL || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && defined(WOLFSSL_CERT_GEN) && \
                                                       defined(WOLFSSL_CERT_REQ)
WOLFSSL_API int wolfSSL_i2d_X509_REQ(WOLFSSL_X509* req, unsigned char** out);
WOLFSSL_API WOLFSSL_X509* wolfSSL_X509_REQ_new(void);
WOLFSSL_API void wolfSSL_X509_REQ_free(WOLFSSL_X509* req);
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
WOLFSSL_API int wolfSSL_X509_REQ_get_attr_by_NID(const WOLFSSL_X509 *req,
        int nid, int lastpos);
WOLFSSL_API int wolfSSL_X509_REQ_add1_attr_by_txt(WOLFSSL_X509 *req,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len);
WOLFSSL_API WOLFSSL_X509_ATTRIBUTE *wolfSSL_X509_REQ_get_attr(
        const WOLFSSL_X509 *req, int loc);
WOLFSSL_API WOLFSSL_X509_ATTRIBUTE* wolfSSL_X509_ATTRIBUTE_new(void);
WOLFSSL_API void wolfSSL_X509_ATTRIBUTE_free(WOLFSSL_X509_ATTRIBUTE* attr);
WOLFSSL_API WOLFSSL_ASN1_TYPE *wolfSSL_X509_ATTRIBUTE_get0_type(
        WOLFSSL_X509_ATTRIBUTE *attr, int idx);
WOLFSSL_API WOLFSSL_X509 *wolfSSL_X509_to_X509_REQ(WOLFSSL_X509 *x,
        WOLFSSL_EVP_PKEY *pkey, const WOLFSSL_EVP_MD *md);
#endif


#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

#include <wolfssl/openssl/crypto.h>

WOLFSSL_API int wolfSSL_CRYPTO_set_mem_ex_functions(void *(*m) (size_t, const char *, int),
    void *(*r) (void *, size_t, const char *, int), void (*f) (void *));

WOLFSSL_API void wolfSSL_CRYPTO_cleanup_all_ex_data(void);

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

WOLFSSL_API int wolfSSL_DH_generate_parameters_ex(WOLFSSL_DH*, int, int,
                           void (*callback) (int, int, void *));

WOLFSSL_API void wolfSSL_ERR_load_crypto_strings(void);

WOLFSSL_API unsigned long wolfSSL_ERR_peek_last_error(void);

WOLFSSL_API int wolfSSL_FIPS_mode(void);

WOLFSSL_API int wolfSSL_FIPS_mode_set(int r);

WOLFSSL_API int wolfSSL_RAND_set_rand_method(const void *meth);

WOLFSSL_API int wolfSSL_CIPHER_get_bits(const WOLFSSL_CIPHER *c, int *alg_bits);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_new(void);
WOLFSSL_API int wolfSSL_sk_X509_num(const WOLF_STACK_OF(WOLFSSL_X509) *s);

WOLFSSL_API WOLFSSL_X509_INFO *wolfSSL_X509_INFO_new(void);
WOLFSSL_API void wolfSSL_X509_INFO_free(WOLFSSL_X509_INFO* info);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_INFO_new_null(void);
WOLFSSL_API int wolfSSL_sk_X509_INFO_num(const WOLF_STACK_OF(WOLFSSL_X509_INFO)*);
WOLFSSL_API WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_value(
    const WOLF_STACK_OF(WOLFSSL_X509_INFO)*, int);
WOLFSSL_API int wolfSSL_sk_X509_INFO_push(WOLF_STACK_OF(WOLFSSL_X509_INFO)*,
    WOLFSSL_X509_INFO*);
WOLFSSL_API WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_pop(WOLF_STACK_OF(WOLFSSL_X509_INFO)*);
WOLFSSL_API void wolfSSL_sk_X509_INFO_pop_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)*,
    void (*f) (WOLFSSL_X509_INFO*));
WOLFSSL_API void wolfSSL_sk_X509_INFO_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)*);

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_sk_X509_NAME_new(
    wolf_sk_compare_cb);
WOLFSSL_API int wolfSSL_sk_X509_NAME_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_sk_X509_NAME_find(const WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_sk_X509_NAME_set_cmp_func(
    WOLF_STACK_OF(WOLFSSL_X509_NAME)*, wolf_sk_compare_cb);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_value(const WOLF_STACK_OF(WOLFSSL_X509_NAME)*, int);
WOLFSSL_API int wolfSSL_sk_X509_NAME_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API void wolfSSL_sk_X509_NAME_pop_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    void (*f) (WOLFSSL_X509_NAME*));
WOLFSSL_API void wolfSSL_sk_X509_NAME_free(WOLF_STACK_OF(WOLFSSL_X509_NAME) *);

WOLFSSL_API int wolfSSL_sk_X509_OBJECT_num(const WOLF_STACK_OF(WOLFSSL_X509_OBJECT) *s);

WOLFSSL_API int wolfSSL_X509_NAME_print_ex(WOLFSSL_BIO*,WOLFSSL_X509_NAME*,int,
        unsigned long);
#ifndef NO_FILESYSTEM
WOLFSSL_API int wolfSSL_X509_NAME_print_ex_fp(XFILE,WOLFSSL_X509_NAME*,int,
        unsigned long);
#endif

WOLFSSL_API WOLFSSL_STACK *wolfSSL_sk_CONF_VALUE_new(wolf_sk_compare_cb compFunc);
WOLFSSL_API void wolfSSL_sk_CONF_VALUE_free(struct WOLFSSL_STACK *sk);
WOLFSSL_API int wolfSSL_sk_CONF_VALUE_num(const WOLFSSL_STACK *sk);
WOLFSSL_API WOLFSSL_CONF_VALUE *wolfSSL_sk_CONF_VALUE_value(
        const struct WOLFSSL_STACK *sk, int i);
WOLFSSL_API int wolfSSL_sk_CONF_VALUE_push(WOLF_STACK_OF(WOLFSSL_CONF_VALUE)* sk,
        WOLFSSL_CONF_VALUE* val);
#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API WOLFSSL_ASN1_BIT_STRING* wolfSSL_ASN1_BIT_STRING_new(void);
WOLFSSL_API void wolfSSL_ASN1_BIT_STRING_free(WOLFSSL_ASN1_BIT_STRING*);
WOLFSSL_API WOLFSSL_ASN1_BIT_STRING* wolfSSL_X509_get0_pubkey_bitstr(
                            const WOLFSSL_X509*);
WOLFSSL_API int wolfSSL_ASN1_BIT_STRING_get_bit(
                            const WOLFSSL_ASN1_BIT_STRING*, int);
WOLFSSL_API int wolfSSL_ASN1_BIT_STRING_set_bit(
                            WOLFSSL_ASN1_BIT_STRING*, int, int);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

WOLFSSL_API int        wolfSSL_CTX_add_session(WOLFSSL_CTX*, WOLFSSL_SESSION*);

WOLFSSL_API int  wolfSSL_version(WOLFSSL*);

WOLFSSL_API int wolfSSL_get_state(const WOLFSSL*);

WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_value(WOLF_STACK_OF(WOLFSSL_X509)*, int);

WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_shift(WOLF_STACK_OF(WOLFSSL_X509)*);

WOLFSSL_API void* wolfSSL_sk_X509_OBJECT_value(WOLF_STACK_OF(WOLFSSL_X509_OBJECT)*, int);
#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API void* wolfSSL_SESSION_get_ex_data(const WOLFSSL_SESSION*, int);

WOLFSSL_API int   wolfSSL_SESSION_set_ex_data(WOLFSSL_SESSION*, int, void*);
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

WOLFSSL_API int wolfSSL_SESSION_get_ex_new_index(long,void*,void*,void*,
        CRYPTO_free_func*);

WOLFSSL_API int wolfSSL_X509_NAME_get_sz(WOLFSSL_X509_NAME*);

WOLFSSL_API const unsigned char* wolfSSL_SESSION_get_id(WOLFSSL_SESSION*,
        unsigned int*);

WOLFSSL_API int wolfSSL_SESSION_print(WOLFSSL_BIO*, const WOLFSSL_SESSION*);

WOLFSSL_API int wolfSSL_set_tlsext_host_name(WOLFSSL *, const char *);

WOLFSSL_API const char* wolfSSL_get_servername(WOLFSSL *, unsigned char);

WOLFSSL_API WOLFSSL_CTX* wolfSSL_set_SSL_CTX(WOLFSSL*,WOLFSSL_CTX*);

WOLFSSL_API VerifyCallback wolfSSL_CTX_get_verify_callback(WOLFSSL_CTX*);

WOLFSSL_API VerifyCallback wolfSSL_get_verify_callback(WOLFSSL*);

#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || HAVE_LIGHTY */

#ifdef HAVE_SNI
WOLFSSL_API void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX *,
        CallbackSniRecv);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_servername_callback(WOLFSSL_CTX *,
        CallbackSniRecv);

WOLFSSL_API int  wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX *, void*);
#endif

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
    || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

WOLFSSL_API void wolfSSL_ERR_remove_thread_state(void*);

/* support for deprecated old name */
#define WOLFSSL_ERR_remove_thread_state wolfSSL_ERR_remove_thread_state

#ifndef NO_FILESYSTEM
WOLFSSL_API void wolfSSL_print_all_errors_fp(XFILE fp);
#endif

WOLFSSL_API void wolfSSL_THREADID_set_callback(void (*threadid_func)(void*));

WOLFSSL_API void wolfSSL_THREADID_set_numeric(void* id, unsigned long val);
WOLFSSL_API void wolfSSL_THREADID_current(WOLFSSL_CRYPTO_THREADID* id);
WOLFSSL_API unsigned long wolfSSL_THREADID_hash(
                                    const WOLFSSL_CRYPTO_THREADID* id);

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_X509_STORE_get1_certs(
                               WOLFSSL_X509_STORE_CTX*, WOLFSSL_X509_NAME*);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_OBJECT)*
        wolfSSL_X509_STORE_get0_objects(WOLFSSL_X509_STORE *);
WOLFSSL_API WOLFSSL_X509_OBJECT*
        wolfSSL_sk_X509_OBJECT_delete(WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* sk, int i);
WOLFSSL_API void wolfSSL_X509_OBJECT_free(WOLFSSL_X509_OBJECT *a);
#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY || HAVE_LIGHTY */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
#include <wolfssl/openssl/stack.h>
WOLFSSL_API void wolfSSL_sk_X509_pop_free(WOLF_STACK_OF(WOLFSSL_X509)* sk, void (*f) (WOLFSSL_X509*));
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
WOLFSSL_API int wolfSSL_CTX_set1_curves_list(WOLFSSL_CTX* ctx, const char* names);
WOLFSSL_API int wolfSSL_set1_curves_list(WOLFSSL* ssl, const char* names);
#endif /* OPENSSL_EXTRA && HAVE_ECC */

#if defined(OPENSSL_ALL) || \
    defined(HAVE_STUNNEL) || defined(WOLFSSL_MYSQL_COMPATIBLE) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

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

#ifdef OPENSSL_EXTRA
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
    || defined(OPENSSL_EXTRA)
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

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) \
    || defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_API void *wolfSSL_X509_get_ex_data(WOLFSSL_X509 *x509, int idx);
WOLFSSL_API int wolfSSL_X509_set_ex_data(WOLFSSL_X509 *x509, int idx,
    void *data);
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_CIPHER) *wolfSSL_get_ciphers_compat(const WOLFSSL *ssl);
WOLFSSL_API int wolfSSL_X509_get_ex_new_index(int idx, void *arg, void *a,
    void *b, void *c);
WOLFSSL_API int wolfSSL_X509_NAME_digest(const WOLFSSL_X509_NAME *data,
    const WOLFSSL_EVP_MD *type, unsigned char *md, unsigned int *len);

WOLFSSL_API long wolfSSL_SSL_CTX_get_timeout(const WOLFSSL_CTX *ctx);
WOLFSSL_API long wolfSSL_get_timeout(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_SSL_CTX_set_tmp_ecdh(WOLFSSL_CTX *ctx,
    WOLFSSL_EC_KEY *ecdh);
WOLFSSL_API int wolfSSL_SSL_CTX_remove_session(WOLFSSL_CTX *,
    WOLFSSL_SESSION *c);

WOLFSSL_API WOLFSSL_BIO *wolfSSL_SSL_get_rbio(const WOLFSSL *s);
WOLFSSL_API WOLFSSL_BIO *wolfSSL_SSL_get_wbio(const WOLFSSL *s);
WOLFSSL_API int wolfSSL_SSL_do_handshake(WOLFSSL *s);
WOLFSSL_API int wolfSSL_SSL_in_init(WOLFSSL*);
WOLFSSL_API int wolfSSL_SSL_in_connect_init(WOLFSSL*);

#ifndef NO_SESSION_CACHE
    WOLFSSL_API WOLFSSL_SESSION *wolfSSL_SSL_get0_session(const WOLFSSL *s);
#endif

WOLFSSL_API int wolfSSL_i2a_ASN1_INTEGER(WOLFSSL_BIO *bp,
    const WOLFSSL_ASN1_INTEGER *a);

#ifdef HAVE_SESSION_TICKET
typedef int (*ticketCompatCb)(WOLFSSL *ssl, unsigned char *name, unsigned char *iv,
    WOLFSSL_EVP_CIPHER_CTX *ectx, WOLFSSL_HMAC_CTX *hctx, int enc);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_ticket_key_cb(WOLFSSL_CTX *, ticketCompatCb);
#endif

#if defined(HAVE_OCSP) || defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
WOLFSSL_API int wolfSSL_CTX_get_extra_chain_certs(WOLFSSL_CTX* ctx,
    WOLF_STACK_OF(X509)** chain);
WOLFSSL_API int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx,
    int(*)(WOLFSSL*, void*));

WOLFSSL_API int wolfSSL_X509_STORE_CTX_get1_issuer(WOLFSSL_X509 **issuer,
    WOLFSSL_X509_STORE_CTX *ctx, WOLFSSL_X509 *x);

WOLFSSL_API void wolfSSL_X509_email_free(WOLF_STACK_OF(WOLFSSL_STRING) *sk);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_STRING) *wolfSSL_X509_get1_ocsp(WOLFSSL_X509 *x);

WOLFSSL_API int wolfSSL_X509_check_issued(WOLFSSL_X509 *issuer,
    WOLFSSL_X509 *subject);

WOLFSSL_API WOLF_STACK_OF(WOLFSSL_STRING)* wolfSSL_sk_WOLFSSL_STRING_new(void);
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
     unsigned char *keys, int keylen);
#endif

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

#ifndef NO_ASN
WOLFSSL_API int wolfSSL_X509_check_host(WOLFSSL_X509 *x, const char *chk,
    size_t chklen, unsigned int flags, char **peername);
WOLFSSL_API int wolfSSL_X509_check_ip_asc(WOLFSSL_X509 *x, const char *ipasc,
        unsigned int flags);
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
WOLFSSL_API const unsigned char *SSL_SESSION_get0_id_context(
        const WOLFSSL_SESSION *sess, unsigned int *sid_ctx_length);
WOLFSSL_API size_t wolfSSL_get_finished(const WOLFSSL *ssl, void *buf, size_t count);
WOLFSSL_API size_t wolfSSL_get_peer_finished(const WOLFSSL *ssl, void *buf, size_t count);
#endif

WOLFSSL_API int SSL_SESSION_set1_id(WOLFSSL_SESSION *s, const unsigned char *sid, unsigned int sid_len);
WOLFSSL_API int SSL_SESSION_set1_id_context(WOLFSSL_SESSION *s, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
WOLFSSL_API WOLFSSL_X509_ALGOR* wolfSSL_X509_ALGOR_new(void);
WOLFSSL_API void wolfSSL_X509_ALGOR_free(WOLFSSL_X509_ALGOR *alg);
WOLFSSL_API const WOLFSSL_X509_ALGOR* wolfSSL_X509_get0_tbs_sigalg(const WOLFSSL_X509 *x);
WOLFSSL_API void wolfSSL_X509_ALGOR_get0(const WOLFSSL_ASN1_OBJECT **paobj, int *pptype, const void **ppval, const WOLFSSL_X509_ALGOR *algor);
WOLFSSL_API int wolfSSL_X509_ALGOR_set0(WOLFSSL_X509_ALGOR *algor, WOLFSSL_ASN1_OBJECT *aobj, int ptype, void *pval);
WOLFSSL_API WOLFSSL_ASN1_TYPE* wolfSSL_ASN1_TYPE_new(void);
WOLFSSL_API void wolfSSL_ASN1_TYPE_free(WOLFSSL_ASN1_TYPE* at);
WOLFSSL_API WOLFSSL_X509_PUBKEY *wolfSSL_X509_PUBKEY_new(void);
WOLFSSL_API void wolfSSL_X509_PUBKEY_free(WOLFSSL_X509_PUBKEY *x);
WOLFSSL_API WOLFSSL_X509_PUBKEY *wolfSSL_X509_get_X509_PUBKEY(const WOLFSSL_X509* x509);
WOLFSSL_API int wolfSSL_X509_PUBKEY_get0_param(WOLFSSL_ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, WOLFSSL_X509_ALGOR **pa, WOLFSSL_X509_PUBKEY *pub);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_X509_PUBKEY_get(WOLFSSL_X509_PUBKEY* key);
WOLFSSL_API int wolfSSL_X509_PUBKEY_set(WOLFSSL_X509_PUBKEY **x, WOLFSSL_EVP_PKEY *key);
WOLFSSL_API int i2t_ASN1_OBJECT(char *buf, int buf_len, WOLFSSL_ASN1_OBJECT *a);
WOLFSSL_API WOLFSSL_ASN1_OBJECT *wolfSSL_d2i_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT **a,
                                                         const unsigned char **der,
                                                         long length);
WOLFSSL_API int wolfSSL_i2a_ASN1_OBJECT(WOLFSSL_BIO *bp, WOLFSSL_ASN1_OBJECT *a);
WOLFSSL_API int wolfSSL_i2d_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT *a, unsigned char **pp);
WOLFSSL_API void SSL_CTX_set_tmp_dh_callback(WOLFSSL_CTX *ctx, WOLFSSL_DH *(*dh) (WOLFSSL *ssl, int is_export, int keylength));
WOLFSSL_API WOLF_STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void);
WOLFSSL_API int wolfSSL_X509_STORE_load_locations(WOLFSSL_X509_STORE *str, const char *file, const char *dir);
WOLFSSL_API int wolfSSL_X509_STORE_add_crl(WOLFSSL_X509_STORE *ctx, WOLFSSL_X509_CRL *x);
WOLFSSL_API int wolfSSL_sk_SSL_CIPHER_num(const WOLF_STACK_OF(WOLFSSL_CIPHER)* p);
WOLFSSL_API int wolfSSL_sk_SSL_CIPHER_find(
        WOLF_STACK_OF(WOLFSSL_CIPHER)* sk, const WOLFSSL_CIPHER* toFind);
WOLFSSL_API void wolfSSL_sk_SSL_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);
WOLFSSL_API int wolfSSL_sk_SSL_COMP_zero(WOLFSSL_STACK* st);
WOLFSSL_API int wolfSSL_sk_SSL_COMP_num(WOLF_STACK_OF(WOLFSSL_COMP)* sk);
WOLFSSL_API WOLFSSL_CIPHER* wolfSSL_sk_SSL_CIPHER_value(WOLFSSL_STACK* sk, int i);
WOLFSSL_API void ERR_load_SSL_strings(void);
WOLFSSL_API void wolfSSL_EC_POINT_dump(const char *msg, const WOLFSSL_EC_POINT *p);

WOLFSSL_API const char *wolfSSL_ASN1_tag2str(int tag);
WOLFSSL_API int wolfSSL_ASN1_STRING_print_ex(WOLFSSL_BIO *out, WOLFSSL_ASN1_STRING *str, unsigned long flags);
WOLFSSL_API int wolfSSL_ASN1_STRING_print(WOLFSSL_BIO *out, WOLFSSL_ASN1_STRING *str);
WOLFSSL_API int wolfSSL_ASN1_TIME_get_length(WOLFSSL_ASN1_TIME *t);
WOLFSSL_API unsigned char* wolfSSL_ASN1_TIME_get_data(WOLFSSL_ASN1_TIME *t);
WOLFSSL_API WOLFSSL_ASN1_TIME *wolfSSL_ASN1_TIME_to_generalizedtime(WOLFSSL_ASN1_TIME *t,
                                                                WOLFSSL_ASN1_TIME **out);
WOLFSSL_API int wolfSSL_i2c_ASN1_INTEGER(WOLFSSL_ASN1_INTEGER *a, unsigned char **pp);
WOLFSSL_API int wolfSSL_a2i_ASN1_INTEGER(WOLFSSL_BIO *bio, WOLFSSL_ASN1_INTEGER *asn1,
        char *buf, int size);
WOLFSSL_API int wolfSSL_X509_CA_num(WOLFSSL_X509_STORE *store);
WOLFSSL_API long wolfSSL_X509_get_version(const WOLFSSL_X509 *x);
WOLFSSL_API int wolfSSL_X509_get_signature_nid(const WOLFSSL_X509* x);

WOLFSSL_API int wolfSSL_PEM_write_bio_PKCS8PrivateKey(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY* pkey, const WOLFSSL_EVP_CIPHER* enc, char* passwd,
    int passwdSz, pem_password_cb* cb, void* ctx);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_PKCS8PrivateKey_bio(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY** pkey, pem_password_cb* cb, void* u);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_d2i_AutoPrivateKey(
    WOLFSSL_EVP_PKEY** pkey, const unsigned char** data, long length);


#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef HAVE_PK_CALLBACKS
WOLFSSL_API int wolfSSL_IsPrivatePkSet(WOLFSSL* ssl);
WOLFSSL_API int wolfSSL_CTX_IsPrivatePkSet(WOLFSSL_CTX* ctx);
#endif

#ifdef HAVE_ENCRYPT_THEN_MAC
WOLFSSL_API int wolfSSL_CTX_AllowEncryptThenMac(WOLFSSL_CTX *, int);
WOLFSSL_API int wolfSSL_AllowEncryptThenMac(WOLFSSL *s, int);
#endif

/* This feature is used to set a fixed ephemeral key and is for testing only */
/* Currently allows ECDHE and DHE only */
#ifdef WOLFSSL_STATIC_EPHEMERAL
WOLFSSL_API int wolfSSL_CTX_set_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const char* key, unsigned int keySz, int format);
WOLFSSL_API int wolfSSL_set_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const char* key, unsigned int keySz, int format);
#endif



#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_SSL_H */
