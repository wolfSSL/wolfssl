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



/*  ssl.h defines wolfssl_openssl compatibility layer 
 *
 */


#ifndef WOLFSSL_OPENSSL_H_
#define WOLFSSL_OPENSSL_H_

/* wolfssl_openssl compatibility layer */
#include <wolfssl/ssl.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef _WIN32
    /* wincrypt.h clashes */
    #undef X509_NAME
#endif


typedef WOLFSSL          SSL;
typedef WOLFSSL_SESSION  SSL_SESSION;
typedef WOLFSSL_METHOD   SSL_METHOD;
typedef WOLFSSL_CTX      SSL_CTX;

typedef WOLFSSL_X509       X509;
typedef WOLFSSL_X509_NAME  X509_NAME;
typedef WOLFSSL_X509_CHAIN X509_CHAIN;


/* redeclare guard */
#define WOLFSSL_TYPES_DEFINED


typedef WOLFSSL_EVP_PKEY       EVP_PKEY;
typedef WOLFSSL_RSA            RSA;
typedef WOLFSSL_DSA            DSA;
typedef WOLFSSL_EC_KEY         EC_KEY;
typedef WOLFSSL_EC_GROUP       EC_GROUP;
typedef WOLFSSL_EC_POINT       EC_POINT;
typedef WOLFSSL_ECDSA_SIG	   ECDSA_SIG;
typedef WOLFSSL_BIO            BIO;
typedef WOLFSSL_BIO_METHOD     BIO_METHOD;
typedef WOLFSSL_CIPHER         SSL_CIPHER;
typedef WOLFSSL_X509_LOOKUP    X509_LOOKUP;
typedef WOLFSSL_X509_LOOKUP_METHOD X509_LOOKUP_METHOD;
typedef WOLFSSL_X509_CRL       X509_CRL;
typedef WOLFSSL_X509_EXTENSION X509_EXTENSION;
typedef WOLFSSL_ASN1_TIME      ASN1_TIME;
typedef WOLFSSL_ASN1_INTEGER   ASN1_INTEGER;
typedef WOLFSSL_ASN1_OBJECT    ASN1_OBJECT;
typedef WOLFSSL_ASN1_STRING    ASN1_STRING;
typedef WOLFSSL_dynlock_value  CRYPTO_dynlock_value;

#define ASN1_UTCTIME WOLFSSL_ASN1_TIME

typedef WOLFSSL_MD4_CTX        MD4_CTX;
typedef WOLFSSL_COMP_METHOD    COMP_METHOD;
typedef WOLFSSL_X509_STORE     X509_STORE;
typedef WOLFSSL_X509_REVOKED   X509_REVOKED;
typedef WOLFSSL_X509_OBJECT    X509_OBJECT;
typedef WOLFSSL_X509_STORE_CTX X509_STORE_CTX;

#define SSL_get_cipher_list(ctx,i)          wolfSSL_get_cipher_list((i))
#define SSL_get_cipher_name(ctx)            wolfSSL_get_cipher((ctx))
#define SSL_get_shared_ciphers(ctx,buf,len) \
                                strncpy(buf, "Not Implemented, SSLv2 only", len)

/* @TODO */
#define ERR_print_errors_fp(file)

/* at the moment only returns ok */
#define SSL_get_verify_result(ctx)    X509_V_OK
#define SSL_get_verify_mode           wolfSSL_SSL_get_mode
#define SSL_get_verify_depth          wolfSSL_get_verify_depth
#define SSL_CTX_get_verify_mode       wolfSSL_CTX_get_verify_mode
#define SSL_CTX_get_verify_depth      wolfSSL_CTX_get_verify_depth
#define SSL_get_certificate(ctx)      0 /* used to pass to get_privatekey */

#define SSLv3_server_method wolfSSLv3_server_method
#define SSLv3_client_method wolfSSLv3_client_method
#define TLSv1_server_method wolfTLSv1_server_method
#define TLSv1_client_method wolfTLSv1_client_method
#define TLSv1_1_server_method wolfTLSv1_1_server_method
#define TLSv1_1_client_method wolfTLSv1_1_client_method
#define TLSv1_2_server_method wolfTLSv1_2_server_method
#define TLSv1_2_client_method wolfTLSv1_2_client_method

#ifdef WOLFSSL_DTLS
    #define DTLSv1_client_method wolfDTLSv1_client_method
    #define DTLSv1_server_method wolfDTLSv1_server_method
    #define DTLSv1_2_client_method wolfDTLSv1_2_client_method
    #define DTLSv1_2_server_method wolfDTLSv1_2_server_method
#endif


#ifndef NO_FILESYSTEM
    #define SSL_CTX_use_certificate_file wolfSSL_CTX_use_certificate_file
    #define SSL_CTX_use_PrivateKey_file wolfSSL_CTX_use_PrivateKey_file
    #define SSL_CTX_load_verify_locations wolfSSL_CTX_load_verify_locations
    #define SSL_CTX_use_certificate_chain_file wolfSSL_CTX_use_certificate_chain_file
    #define SSL_CTX_use_RSAPrivateKey_file wolfSSL_CTX_use_RSAPrivateKey_file
    
    #define SSL_use_certificate_file wolfSSL_use_certificate_file
    #define SSL_use_PrivateKey_file wolfSSL_use_PrivateKey_file
    #define SSL_use_certificate_chain_file wolfSSL_use_certificate_chain_file
    #define SSL_use_RSAPrivateKey_file wolfSSL_use_RSAPrivateKey_file
#endif

#define SSL_CTX_new wolfSSL_CTX_new
#define SSL_new     wolfSSL_new
#define SSL_set_fd  wolfSSL_set_fd
#define SSL_get_fd  wolfSSL_get_fd
#define SSL_connect wolfSSL_connect
#define SSL_clear   wolfSSL_clear

#define SSL_write    wolfSSL_write
#define SSL_read     wolfSSL_read
#define SSL_peek     wolfSSL_peek
#define SSL_accept   wolfSSL_accept
#define SSL_CTX_free wolfSSL_CTX_free
#define SSL_free     wolfSSL_free
#define SSL_shutdown wolfSSL_shutdown

#define SSL_CTX_set_quiet_shutdown wolfSSL_CTX_set_quiet_shutdown
#define SSL_set_quiet_shutdown wolfSSL_set_quiet_shutdown
#define SSL_get_error wolfSSL_get_error
#define SSL_set_session wolfSSL_set_session
#define SSL_get_session wolfSSL_get_session
#define SSL_flush_sessions wolfSSL_flush_sessions
/* assume unlimited temporarily */
#define SSL_CTX_get_session_cache_mode(ctx) 0

#define SSL_CTX_set_verify wolfSSL_CTX_set_verify
#define SSL_set_verify wolfSSL_set_verify
#define SSL_pending wolfSSL_pending
#define SSL_load_error_strings wolfSSL_load_error_strings
#define SSL_library_init wolfSSL_library_init
#define SSL_CTX_set_session_cache_mode wolfSSL_CTX_set_session_cache_mode
#define SSL_CTX_set_cipher_list wolfSSL_CTX_set_cipher_list
#define SSL_set_cipher_list     wolfSSL_set_cipher_list

#define ERR_error_string wolfSSL_ERR_error_string
#define ERR_error_string_n wolfSSL_ERR_error_string_n
#define ERR_reason_error_string wolfSSL_ERR_reason_error_string

#define SSL_set_ex_data wolfSSL_set_ex_data
#define SSL_get_shutdown wolfSSL_get_shutdown
#define SSL_set_rfd wolfSSL_set_rfd
#define SSL_set_wfd wolfSSL_set_wfd
#define SSL_set_shutdown wolfSSL_set_shutdown
#define SSL_set_session_id_context wolfSSL_set_session_id_context
#define SSL_set_connect_state wolfSSL_set_connect_state
#define SSL_set_accept_state wolfSSL_set_accept_state
#define SSL_session_reused wolfSSL_session_reused
#define SSL_SESSION_free wolfSSL_SESSION_free
#define SSL_is_init_finished wolfSSL_is_init_finished

#define SSL_get_version wolfSSL_get_version
#define SSL_get_current_cipher wolfSSL_get_current_cipher
#define SSL_get_cipher wolfSSL_get_cipher
#define SSL_CIPHER_description wolfSSL_CIPHER_description
#define SSL_CIPHER_get_name wolfSSL_CIPHER_get_name
#define SSL_get1_session wolfSSL_get1_session

#define SSL_get_keyblock_size wolfSSL_get_keyblock_size
#define SSL_get_keys          wolfSSL_get_keys

#define X509_free wolfSSL_X509_free
#define OPENSSL_free wolfSSL_OPENSSL_free

#define OCSP_parse_url wolfSSL_OCSP_parse_url
#define SSLv23_client_method wolfSSLv23_client_method
#define SSLv2_client_method wolfSSLv2_client_method
#define SSLv2_server_method wolfSSLv2_server_method

#define MD4_Init wolfSSL_MD4_Init
#define MD4_Update  wolfSSL_MD4_Update
#define MD4_Final wolfSSL_MD4_Final

#define BIO_new      wolfSSL_BIO_new
#define BIO_free     wolfSSL_BIO_free
#define BIO_free_all wolfSSL_BIO_free_all
#define BIO_read     wolfSSL_BIO_read
#define BIO_write    wolfSSL_BIO_write
#define BIO_push     wolfSSL_BIO_push
#define BIO_pop      wolfSSL_BIO_pop
#define BIO_flush    wolfSSL_BIO_flush
#define BIO_pending  wolfSSL_BIO_pending

#define BIO_get_mem_data wolfSSL_BIO_get_mem_data
#define BIO_new_mem_buf  wolfSSL_BIO_new_mem_buf

#define BIO_f_buffer              wolfSSL_BIO_f_buffer
#define BIO_set_write_buffer_size wolfSSL_BIO_set_write_buffer_size
#define BIO_f_ssl                 wolfSSL_BIO_f_ssl
#define BIO_new_socket            wolfSSL_BIO_new_socket
#define SSL_set_bio               wolfSSL_set_bio
#define BIO_eof                   wolfSSL_BIO_eof
#define BIO_set_ss                wolfSSL_BIO_set_ss

#define BIO_s_mem     wolfSSL_BIO_s_mem
#define BIO_f_base64  wolfSSL_BIO_f_base64
#define BIO_set_flags wolfSSL_BIO_set_flags

#define OpenSSL_add_all_algorithms wolfSSL_add_all_algorithms
#define SSLeay_add_ssl_algorithms  wolfSSL_add_all_algorithms
#define SSLeay_add_all_algorithms wolfSSL_add_all_algorithms

#define RAND_screen     wolfSSL_RAND_screen
#define RAND_file_name  wolfSSL_RAND_file_name
#define RAND_write_file wolfSSL_RAND_write_file
#define RAND_load_file  wolfSSL_RAND_load_file
#define RAND_egd        wolfSSL_RAND_egd
#define RAND_seed       wolfSSL_RAND_seed
#define RAND_add        wolfSSL_RAND_add

#define COMP_zlib                       wolfSSL_COMP_zlib
#define COMP_rle                        wolfSSL_COMP_rle
#define SSL_COMP_add_compression_method wolfSSL_COMP_add_compression_method

#define SSL_get_ex_new_index wolfSSL_get_ex_new_index

#define CRYPTO_set_id_callback wolfSSL_set_id_callback
#define CRYPTO_set_locking_callback wolfSSL_set_locking_callback
#define CRYPTO_set_dynlock_create_callback wolfSSL_set_dynlock_create_callback
#define CRYPTO_set_dynlock_lock_callback wolfSSL_set_dynlock_lock_callback
#define CRYPTO_set_dynlock_destroy_callback wolfSSL_set_dynlock_destroy_callback
#define CRYPTO_num_locks wolfSSL_num_locks

#define X509_STORE_CTX_get_current_cert wolfSSL_X509_STORE_CTX_get_current_cert
#define X509_STORE_CTX_get_error wolfSSL_X509_STORE_CTX_get_error
#define X509_STORE_CTX_get_error_depth wolfSSL_X509_STORE_CTX_get_error_depth

#define X509_NAME_oneline             wolfSSL_X509_NAME_oneline
#define X509_get_issuer_name          wolfSSL_X509_get_issuer_name
#define X509_get_subject_name         wolfSSL_X509_get_subject_name
#define X509_verify_cert_error_string wolfSSL_X509_verify_cert_error_string

#define X509_LOOKUP_add_dir wolfSSL_X509_LOOKUP_add_dir
#define X509_LOOKUP_load_file wolfSSL_X509_LOOKUP_load_file
#define X509_LOOKUP_hash_dir wolfSSL_X509_LOOKUP_hash_dir
#define X509_LOOKUP_file wolfSSL_X509_LOOKUP_file

#define X509_STORE_add_lookup wolfSSL_X509_STORE_add_lookup
#define X509_STORE_new wolfSSL_X509_STORE_new
#define X509_STORE_get_by_subject wolfSSL_X509_STORE_get_by_subject
#define X509_STORE_CTX_init wolfSSL_X509_STORE_CTX_init
#define X509_STORE_CTX_cleanup wolfSSL_X509_STORE_CTX_cleanup

#define X509_CRL_get_lastUpdate wolfSSL_X509_CRL_get_lastUpdate
#define X509_CRL_get_nextUpdate wolfSSL_X509_CRL_get_nextUpdate

#define X509_get_pubkey           wolfSSL_X509_get_pubkey
#define X509_CRL_verify           wolfSSL_X509_CRL_verify
#define X509_STORE_CTX_set_error  wolfSSL_X509_STORE_CTX_set_error
#define X509_OBJECT_free_contents wolfSSL_X509_OBJECT_free_contents
#define EVP_PKEY_free             wolfSSL_EVP_PKEY_free
#define X509_cmp_current_time     wolfSSL_X509_cmp_current_time
#define sk_X509_REVOKED_num       wolfSSL_sk_X509_REVOKED_num
#define X509_CRL_get_REVOKED      wolfSSL_X509_CRL_get_REVOKED
#define sk_X509_REVOKED_value     wolfSSL_sk_X509_REVOKED_value
#define X509_get_notBefore(cert)  (ASN1_TIME*)wolfSSL_X509_notBefore((cert))
#define X509_get_notAfter(cert)   (ASN1_TIME*)wolfSSL_X509_notAfter((cert))


#define X509_get_serialNumber wolfSSL_X509_get_serialNumber

#define ASN1_TIME_print wolfSSL_ASN1_TIME_print

#define ASN1_INTEGER_cmp wolfSSL_ASN1_INTEGER_cmp
#define ASN1_INTEGER_get wolfSSL_ASN1_INTEGER_get

#define SSL_load_client_CA_file wolfSSL_load_client_CA_file

#define SSL_CTX_set_client_CA_list         wolfSSL_CTX_set_client_CA_list
#define X509_STORE_CTX_get_ex_data         wolfSSL_X509_STORE_CTX_get_ex_data
#define SSL_get_ex_data_X509_STORE_CTX_idx wolfSSL_get_ex_data_X509_STORE_CTX_idx
#define SSL_get_ex_data wolfSSL_get_ex_data

#define SSL_CTX_set_default_passwd_cb_userdata wolfSSL_CTX_set_default_passwd_cb_userdata
#define SSL_CTX_set_default_passwd_cb wolfSSL_CTX_set_default_passwd_cb

#define SSL_CTX_set_timeout(ctx, to) wolfSSL_CTX_set_timeout(ctx, (unsigned int) to)
#define SSL_CTX_set_info_callback wolfSSL_CTX_set_info_callback

#define ERR_peek_error wolfSSL_ERR_peek_error
#define ERR_GET_REASON wolfSSL_ERR_GET_REASON

#define SSL_alert_type_string wolfSSL_alert_type_string
#define SSL_alert_desc_string wolfSSL_alert_desc_string
#define SSL_state_string wolfSSL_state_string

#define RSA_free wolfSSL_RSA_free
#define RSA_generate_key wolfSSL_RSA_generate_key
#define SSL_CTX_set_tmp_rsa_callback wolfSSL_CTX_set_tmp_rsa_callback

#define PEM_def_callback wolfSSL_PEM_def_callback

#define SSL_CTX_sess_accept wolfSSL_CTX_sess_accept
#define SSL_CTX_sess_connect wolfSSL_CTX_sess_connect
#define SSL_CTX_sess_accept_good wolfSSL_CTX_sess_accept_good
#define SSL_CTX_sess_connect_good wolfSSL_CTX_sess_connect_good
#define SSL_CTX_sess_accept_renegotiate wolfSSL_CTX_sess_accept_renegotiate
#define SSL_CTX_sess_connect_renegotiate wolfSSL_CTX_sess_connect_renegotiate
#define SSL_CTX_sess_hits wolfSSL_CTX_sess_hits
#define SSL_CTX_sess_cb_hits wolfSSL_CTX_sess_cb_hits
#define SSL_CTX_sess_cache_full wolfSSL_CTX_sess_cache_full
#define SSL_CTX_sess_misses wolfSSL_CTX_sess_misses
#define SSL_CTX_sess_timeouts wolfSSL_CTX_sess_timeouts
#define SSL_CTX_sess_number wolfSSL_CTX_sess_number
#define SSL_CTX_sess_get_cache_size wolfSSL_CTX_sess_get_cache_size


#define SSL_DEFAULT_CIPHER_LIST WOLFSSL_DEFAULT_CIPHER_LIST
#define RSA_F4 WOLFSSL_RSA_F4

#define SSL_CTX_set_psk_client_callback wolfSSL_CTX_set_psk_client_callback
#define SSL_set_psk_client_callback wolfSSL_set_psk_client_callback

#define SSL_get_psk_identity_hint wolfSSL_get_psk_identity_hint
#define SSL_get_psk_identity wolfSSL_get_psk_identity

#define SSL_CTX_use_psk_identity_hint wolfSSL_CTX_use_psk_identity_hint
#define SSL_use_psk_identity_hint wolfSSL_use_psk_identity_hint

#define SSL_CTX_set_psk_server_callback wolfSSL_CTX_set_psk_server_callback
#define SSL_set_psk_server_callback wolfSSL_set_psk_server_callback

#define ERR_get_error_line_data wolfSSL_ERR_get_error_line_data

#define ERR_get_error wolfSSL_ERR_get_error
#define ERR_clear_error wolfSSL_ERR_clear_error

#define RAND_status wolfSSL_RAND_status
#define RAND_bytes wolfSSL_RAND_bytes
#define SSLv23_server_method wolfSSLv23_server_method
#define SSL_CTX_set_options wolfSSL_CTX_set_options 
#define SSL_CTX_check_private_key wolfSSL_CTX_check_private_key

#define ERR_free_strings wolfSSL_ERR_free_strings
#define ERR_remove_state wolfSSL_ERR_remove_state
#define EVP_cleanup wolfSSL_EVP_cleanup

#define CRYPTO_cleanup_all_ex_data wolfSSL_cleanup_all_ex_data
#define SSL_CTX_set_mode wolfSSL_CTX_set_mode
#define SSL_CTX_get_mode wolfSSL_CTX_get_mode
#define SSL_CTX_set_default_read_ahead wolfSSL_CTX_set_default_read_ahead

#define SSL_CTX_sess_set_cache_size wolfSSL_CTX_sess_set_cache_size
#define SSL_CTX_set_default_verify_paths wolfSSL_CTX_set_default_verify_paths

#define SSL_CTX_set_session_id_context wolfSSL_CTX_set_session_id_context
#define SSL_get_peer_certificate wolfSSL_get_peer_certificate

#define SSL_want_read wolfSSL_want_read
#define SSL_want_write wolfSSL_want_write

#define BIO_prf wolfSSL_BIO_prf
#define ASN1_UTCTIME_pr wolfSSL_ASN1_UTCTIME_pr

#define sk_num wolfSSL_sk_num
#define sk_value wolfSSL_sk_value

#define SSL_CTX_get_ex_data wolfSSL_CTX_get_ex_data
#define SSL_CTX_set_ex_data wolfSSL_CTX_set_ex_data
#define SSL_CTX_sess_set_get_cb wolfSSL_CTX_sess_set_get_cb
#define SSL_CTX_sess_set_new_cb wolfSSL_CTX_sess_set_new_cb
#define SSL_CTX_sess_set_remove_cb wolfSSL_CTX_sess_set_remove_cb

#define i2d_SSL_SESSION wolfSSL_i2d_SSL_SESSION
#define d2i_SSL_SESSION wolfSSL_d2i_SSL_SESSION
#define SSL_SESSION_set_timeout wolfSSL_SSL_SESSION_set_timeout
#define SSL_SESSION_get_timeout wolfSSL_SESSION_get_timeout
#define SSL_SESSION_get_time wolfSSL_SESSION_get_time
#define SSL_CTX_get_ex_new_index wolfSSL_CTX_get_ex_new_index

/* yassl had set the default to be 500 */
#define SSL_get_default_timeout(ctx) 500

/* Lighthttp compatibility */

#ifdef HAVE_LIGHTY                       
typedef WOLFSSL_X509_NAME_ENTRY X509_NAME_ENTRY;

#define SSL_CB_HANDSHAKE_START          0x10
#define X509_NAME_free wolfSSL_X509_NAME_free
#define SSL_CTX_use_certificate wolfSSL_CTX_use_certificate
#define SSL_CTX_use_PrivateKey wolfSSL_CTX_use_PrivateKey
#define BIO_read_filename wolfSSL_BIO_read_filename
#define BIO_s_file wolfSSL_BIO_s_file
#define OBJ_nid2sn wolf_OBJ_nid2sn
#define OBJ_obj2nid wolf_OBJ_obj2nid
#define OBJ_sn2nid wolf_OBJ_sn2nid
#define PEM_read_bio_X509 PEM_read_bio_WOLFSSL_X509
#define SSL_CTX_set_verify_depth wolfSSL_CTX_set_verify_depth
#define SSL_get_app_data wolfSSL_get_app_data
#define SSL_set_app_data wolfSSL_set_app_data
#define X509_NAME_entry_count wolfSSL_X509_NAME_entry_count
#define X509_NAME_ENTRY_get_object wolfSSL_X509_NAME_ENTRY_get_object
#define X509_NAME_get_entry wolfSSL_X509_NAME_get_entry
#define sk_X509_NAME_pop_free  wolfSSL_sk_X509_NAME_pop_free
#define SHA1 wolfSSL_SHA1
#define X509_check_private_key wolfSSL_X509_check_private_key
#define SSL_dup_CA_list wolfSSL_dup_CA_list

#endif

#if defined(HAVE_STUNNEL) || defined(HAVE_LIGHTY)

#define OBJ_nid2ln wolf_OBJ_nid2ln
#define OBJ_txt2nid wolf_OBJ_txt2nid
#define PEM_read_bio_DHparams wolfSSL_PEM_read_bio_DHparams
#define PEM_write_bio_X509 PEM_write_bio_WOLFSSL_X509
#define SSL_CTX_set_tmp_dh wolfSSL_CTX_set_tmp_dh
#define BIO_new_file wolfSSL_BIO_new_file


#endif /* HAVE_STUNNEL || HAVE_LIGHTY */

#ifdef HAVE_STUNNEL
#include <wolfssl/openssl/asn1.h>

/* defined as: (SSL_ST_ACCEPT|SSL_CB_LOOP), which becomes 0x2001*/
#define SSL_CB_ACCEPT_LOOP               0x2001 
#define SSL2_VERSION                     0x0002
#define SSL3_VERSION                     0x0300
#define TLS1_VERSION                     0x0301
#define DTLS1_VERSION                    0xFEFF
#define SSL23_ST_SR_CLNT_HELLO_A        (0x210|0x2000)
#define SSL3_ST_SR_CLNT_HELLO_A         (0x110|0x2000)
#define ASN1_STRFLGS_ESC_MSB             4
#define X509_V_ERR_CERT_REJECTED         28

#define SSL_alert_desc_string_long       wolfSSL_alert_desc_string_long
#define SSL_alert_type_string_long       wolfSSL_alert_type_string_long
#define SSL_CIPHER_get_bits              wolfSSL_CIPHER_get_bits
#define sk_X509_NAME_num                 wolfSSL_sk_X509_NAME_num
#define sk_X509_num                      wolfSSL_sk_X509_num
#define X509_NAME_print_ex               wolfSSL_X509_NAME_print_ex
#define X509_get0_pubkey_bitstr          wolfSSL_X509_get0_pubkey_bitstr
#define SSL_CTX_get_options              wolfSSL_CTX_get_options

#define SSL_CTX_flush_sessions           wolfSSL_flush_sessions
#define SSL_CTX_add_session              wolfSSL_CTX_add_session
#define SSL_get_SSL_CTX                  wolfSSL_get_SSL_CTX
#define SSL_version                      wolfSSL_version
#define SSL_get_state                    wolfSSL_get_state
#define SSL_state_string_long            wolfSSL_state_string_long
#define SSL_get_peer_cert_chain          wolfSSL_get_peer_cert_chain
#define sk_X509_NAME_value               wolfSSL_sk_X509_NAME_value
#define sk_X509_value                    wolfSSL_sk_X509_value
#define SSL_SESSION_get_ex_data          wolfSSL_SESSION_get_ex_data
#define SSL_SESSION_set_ex_data          wolfSSL_SESSION_set_ex_data
#define SSL_SESSION_get_ex_new_index     wolfSSL_SESSION_get_ex_new_index
#define SSL_SESSION_get_id               wolfSSL_SESSION_get_id
#define CRYPTO_dynlock_value             WOLFSSL_dynlock_value
typedef WOLFSSL_ASN1_BIT_STRING    ASN1_BIT_STRING;
#define X509_STORE_get1_certs            wolfSSL_X509_STORE_get1_certs
#define sk_X509_pop_free                 wolfSSL_sk_X509_pop_free

#define SSL_TLSEXT_ERR_OK                    0
#define SSL_TLSEXT_ERR_ALERT_FATAL           alert_fatal
#define SSL_TLSEXT_ERR_NOACK                 alert_warning
#define TLSEXT_NAMETYPE_host_name            WOLFSSL_SNI_HOST_NAME

#define SSL_set_tlsext_host_name wolfSSL_set_tlsext_host_name
#define SSL_get_servername wolfSSL_get_servername
#define SSL_set_SSL_CTX                  wolfSSL_set_SSL_CTX
#define SSL_CTX_get_verify_callback      wolfSSL_CTX_get_verify_callback
#define SSL_CTX_set_tlsext_servername_callback      wolfSSL_CTX_set_servername_callback
#define SSL_CTX_set_tlsext_servername_arg           wolfSSL_CTX_set_servername_arg

#define PSK_MAX_PSK_LEN                      256
#define PSK_MAX_IDENTITY_LEN                 128
#define ERR_remove_thread_state WOLFSSL_ERR_remove_thread_state
#define SSL_CTX_clear_options wolfSSL_CTX_clear_options


#endif /* HAVE_STUNNEL */

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* wolfSSL_openssl_h__ */
