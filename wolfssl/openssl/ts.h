/* ts.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* ts.h - Time-Stamp Protocol (RFC 3161) compatibility layer.
 *
 * Requester side only: create and encode requests, decode responses and
 * verify time-stamp tokens. There is no TS_RESP_CTX - wolfSSL's wc_Tsp API
 * is used to implement a TSA.
 */

#ifndef WOLFSSL_OPENSSL_TS_H_
#define WOLFSSL_OPENSSL_TS_H_

#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/pkcs7.h>
#include <wolfssl/wolfcrypt/pkcs7.h>

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && \
    defined(WOLFSSL_TSP_VERIFIER)

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct WOLFSSL_TS_MSG_IMPRINT WOLFSSL_TS_MSG_IMPRINT;
typedef struct WOLFSSL_TS_REQ         WOLFSSL_TS_REQ;
typedef struct WOLFSSL_TS_ACCURACY    WOLFSSL_TS_ACCURACY;
typedef struct WOLFSSL_TS_STATUS_INFO WOLFSSL_TS_STATUS_INFO;
typedef struct WOLFSSL_TS_TST_INFO    WOLFSSL_TS_TST_INFO;
typedef struct WOLFSSL_TS_RESP        WOLFSSL_TS_RESP;
typedef struct WOLFSSL_TS_VERIFY_CTX  WOLFSSL_TS_VERIFY_CTX;

/* PKIStatus values. RFC 3161, 2.4.2. */
#define WOLFSSL_TS_STATUS_GRANTED                  0
#define WOLFSSL_TS_STATUS_GRANTED_WITH_MODS        1
#define WOLFSSL_TS_STATUS_REJECTION                2
#define WOLFSSL_TS_STATUS_WAITING                  3
#define WOLFSSL_TS_STATUS_REVOCATION_WARNING       4
#define WOLFSSL_TS_STATUS_REVOCATION_NOTIFICATION  5

/* Verification flags. */
#define WOLFSSL_TS_VFY_SIGNATURE  (1u << 0)
#define WOLFSSL_TS_VFY_VERSION    (1u << 1)
#define WOLFSSL_TS_VFY_POLICY     (1u << 2)
#define WOLFSSL_TS_VFY_IMPRINT    (1u << 3)
#define WOLFSSL_TS_VFY_DATA       (1u << 4)
#define WOLFSSL_TS_VFY_NONCE      (1u << 5)
#define WOLFSSL_TS_VFY_SIGNER     (1u << 6)
#define WOLFSSL_TS_VFY_TSA_NAME   (1u << 7) /* needs name - not supported */

#define WOLFSSL_TS_VFY_ALL_IMPRINT  (WOLFSSL_TS_VFY_SIGNATURE | \
                                     WOLFSSL_TS_VFY_VERSION   | \
                                     WOLFSSL_TS_VFY_POLICY    | \
                                     WOLFSSL_TS_VFY_IMPRINT   | \
                                     WOLFSSL_TS_VFY_NONCE     | \
                                     WOLFSSL_TS_VFY_SIGNER    | \
                                     WOLFSSL_TS_VFY_TSA_NAME)

/* TS_RESP_CTX flags - OpenSSL values. */
#define WOLFSSL_TS_TSA_NAME           0x01
#define WOLFSSL_TS_ORDERING           0x02
#define WOLFSSL_TS_ESS_CERT_ID_CHAIN  0x04

/* Responder context for creating time-stamp responses. */
typedef struct WOLFSSL_TS_RESP_CTX WOLFSSL_TS_RESP_CTX;

/* Callback returning a new serial number as an ASN1_INTEGER - the response
 * creation takes ownership of the returned object. */
typedef WOLFSSL_ASN1_INTEGER* (*WOLFSSL_TS_serial_cb)(WOLFSSL_TS_RESP_CTX*,
    void*);
/* Callback filling the time in seconds since the epoch (and optionally
 * microseconds). Returns 1 on success. */
typedef int (*WOLFSSL_TS_time_cb)(WOLFSSL_TS_RESP_CTX*, void*, long* sec,
    long* usec);

/* TS_MSG_IMPRINT */
WOLFSSL_API WOLFSSL_TS_MSG_IMPRINT* wolfSSL_TS_MSG_IMPRINT_new(void);
WOLFSSL_API void wolfSSL_TS_MSG_IMPRINT_free(WOLFSSL_TS_MSG_IMPRINT* a);
WOLFSSL_API int wolfSSL_TS_MSG_IMPRINT_set_algo(WOLFSSL_TS_MSG_IMPRINT* a,
    WOLFSSL_X509_ALGOR* alg);
WOLFSSL_API WOLFSSL_X509_ALGOR* wolfSSL_TS_MSG_IMPRINT_get_algo(
    WOLFSSL_TS_MSG_IMPRINT* a);
WOLFSSL_API int wolfSSL_TS_MSG_IMPRINT_set_msg(WOLFSSL_TS_MSG_IMPRINT* a,
    unsigned char* d, int len);
WOLFSSL_API WOLFSSL_ASN1_STRING* wolfSSL_TS_MSG_IMPRINT_get_msg(
    WOLFSSL_TS_MSG_IMPRINT* a);

/* TS_REQ */
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API WOLFSSL_TS_REQ* wolfSSL_TS_REQ_new(void);
WOLFSSL_API void wolfSSL_TS_REQ_free(WOLFSSL_TS_REQ* a);
WOLFSSL_API int wolfSSL_TS_REQ_set_version(WOLFSSL_TS_REQ* a, long version);
WOLFSSL_API long wolfSSL_TS_REQ_get_version(const WOLFSSL_TS_REQ* a);
WOLFSSL_API int wolfSSL_TS_REQ_set_msg_imprint(WOLFSSL_TS_REQ* a,
    WOLFSSL_TS_MSG_IMPRINT* msgImprint);
WOLFSSL_API WOLFSSL_TS_MSG_IMPRINT* wolfSSL_TS_REQ_get_msg_imprint(
    WOLFSSL_TS_REQ* a);
WOLFSSL_API int wolfSSL_TS_REQ_set_policy_id(WOLFSSL_TS_REQ* a,
    const WOLFSSL_ASN1_OBJECT* policy);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_TS_REQ_get_policy_id(
    WOLFSSL_TS_REQ* a);
WOLFSSL_API int wolfSSL_TS_REQ_set_nonce(WOLFSSL_TS_REQ* a,
    const WOLFSSL_ASN1_INTEGER* nonce);
WOLFSSL_API const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_REQ_get_nonce(
    const WOLFSSL_TS_REQ* a);
WOLFSSL_API int wolfSSL_TS_REQ_set_cert_req(WOLFSSL_TS_REQ* a, int certReq);
WOLFSSL_API int wolfSSL_TS_REQ_get_cert_req(const WOLFSSL_TS_REQ* a);
WOLFSSL_API int wolfSSL_i2d_TS_REQ(const WOLFSSL_TS_REQ* a,
    unsigned char** pp);
WOLFSSL_API WOLFSSL_TS_REQ* wolfSSL_d2i_TS_REQ(WOLFSSL_TS_REQ** a,
    const unsigned char** pp, long length);
#endif /* WOLFSSL_TSP_REQUESTER */

/* TS_STATUS_INFO */
WOLFSSL_API const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_STATUS_INFO_get0_status(
    const WOLFSSL_TS_STATUS_INFO* a);
WOLFSSL_API const WOLFSSL_ASN1_BIT_STRING*
    wolfSSL_TS_STATUS_INFO_get0_failure_info(
    const WOLFSSL_TS_STATUS_INFO* a);
WOLFSSL_API const WOLF_STACK_OF(WOLFSSL_ASN1_STRING)*
    wolfSSL_TS_STATUS_INFO_get0_text(const WOLFSSL_TS_STATUS_INFO* a);

/* TS_ACCURACY */
WOLFSSL_API const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_ACCURACY_get_seconds(
    const WOLFSSL_TS_ACCURACY* a);
WOLFSSL_API const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_ACCURACY_get_millis(
    const WOLFSSL_TS_ACCURACY* a);
WOLFSSL_API const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_ACCURACY_get_micros(
    const WOLFSSL_TS_ACCURACY* a);

/* TS_TST_INFO */
WOLFSSL_API void wolfSSL_TS_TST_INFO_free(WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API WOLFSSL_TS_TST_INFO* wolfSSL_d2i_TS_TST_INFO(
    WOLFSSL_TS_TST_INFO** a, const unsigned char** pp, long length);
WOLFSSL_API int wolfSSL_i2d_TS_TST_INFO(const WOLFSSL_TS_TST_INFO* a,
    unsigned char** pp);
WOLFSSL_API long wolfSSL_TS_TST_INFO_get_version(
    const WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_TS_TST_INFO_get_policy_id(
    WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API WOLFSSL_TS_MSG_IMPRINT* wolfSSL_TS_TST_INFO_get_msg_imprint(
    WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_TST_INFO_get_serial(
    const WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API const WOLFSSL_ASN1_GENERALIZEDTIME* wolfSSL_TS_TST_INFO_get_time(
    const WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API WOLFSSL_TS_ACCURACY* wolfSSL_TS_TST_INFO_get_accuracy(
    WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API int wolfSSL_TS_TST_INFO_get_ordering(
    const WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_TST_INFO_get_nonce(
    const WOLFSSL_TS_TST_INFO* a);
WOLFSSL_API WOLFSSL_GENERAL_NAME* wolfSSL_TS_TST_INFO_get_tsa(
    WOLFSSL_TS_TST_INFO* a);

/* TS_RESP */
WOLFSSL_API void wolfSSL_TS_RESP_free(WOLFSSL_TS_RESP* a);
WOLFSSL_API WOLFSSL_TS_RESP* wolfSSL_d2i_TS_RESP(WOLFSSL_TS_RESP** a,
    const unsigned char** pp, long length);
WOLFSSL_API int wolfSSL_i2d_TS_RESP(const WOLFSSL_TS_RESP* a,
    unsigned char** pp);
WOLFSSL_API WOLFSSL_TS_STATUS_INFO* wolfSSL_TS_RESP_get_status_info(
    WOLFSSL_TS_RESP* a);
WOLFSSL_API WOLFSSL_TS_TST_INFO* wolfSSL_TS_RESP_get_tst_info(
    WOLFSSL_TS_RESP* a);

/* TS_VERIFY_CTX */
WOLFSSL_API WOLFSSL_TS_VERIFY_CTX* wolfSSL_TS_VERIFY_CTX_new(void);
WOLFSSL_API void wolfSSL_TS_VERIFY_CTX_free(WOLFSSL_TS_VERIFY_CTX* ctx);
WOLFSSL_API void wolfSSL_TS_VERIFY_CTX_cleanup(WOLFSSL_TS_VERIFY_CTX* ctx);
WOLFSSL_API int wolfSSL_TS_VERIFY_CTX_set_flags(WOLFSSL_TS_VERIFY_CTX* ctx,
    int flags);
WOLFSSL_API int wolfSSL_TS_VERIFY_CTX_add_flags(WOLFSSL_TS_VERIFY_CTX* ctx,
    int flags);
WOLFSSL_API unsigned char* wolfSSL_TS_VERIFY_CTX_set_imprint(
    WOLFSSL_TS_VERIFY_CTX* ctx, unsigned char* imprint, long len);
WOLFSSL_API WOLFSSL_X509_STORE* wolfSSL_TS_VERIFY_CTX_set_store(
    WOLFSSL_TS_VERIFY_CTX* ctx, WOLFSSL_X509_STORE* store);
WOLFSSL_API WOLFSSL_BIO* wolfSSL_TS_VERIFY_CTX_set_data(
    WOLFSSL_TS_VERIFY_CTX* ctx, WOLFSSL_BIO* b);
#ifdef WOLFSSL_TSP_REQUESTER
WOLFSSL_API WOLFSSL_TS_VERIFY_CTX* wolfSSL_TS_REQ_to_TS_VERIFY_CTX(
    WOLFSSL_TS_REQ* req, WOLFSSL_TS_VERIFY_CTX* ctx);
#endif /* WOLFSSL_TSP_REQUESTER */
WOLFSSL_API int wolfSSL_TS_RESP_verify_response(WOLFSSL_TS_VERIFY_CTX* ctx,
    WOLFSSL_TS_RESP* response);
#ifdef OPENSSL_ALL
WOLFSSL_API int wolfSSL_TS_RESP_verify_token(WOLFSSL_TS_VERIFY_CTX* ctx,
    WOLFSSL_PKCS7* token);
#endif

/* TS_RESP_CTX - responder context for creating time-stamp responses. */
#ifdef WOLFSSL_TSP_RESPONDER
WOLFSSL_API WOLFSSL_TS_RESP_CTX* wolfSSL_TS_RESP_CTX_new(void);
WOLFSSL_API void wolfSSL_TS_RESP_CTX_free(WOLFSSL_TS_RESP_CTX* ctx);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_set_signer_cert(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_X509* signer);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_set_signer_key(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_EVP_PKEY* key);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_set_signer_digest(
    WOLFSSL_TS_RESP_CTX* ctx, const WOLFSSL_EVP_MD* md);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_set_def_policy(WOLFSSL_TS_RESP_CTX* ctx,
    const WOLFSSL_ASN1_OBJECT* policy);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_set_serial_cb(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_TS_serial_cb cb, void* data);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_set_time_cb(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_TS_time_cb cb, void* data);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_set_accuracy(WOLFSSL_TS_RESP_CTX* ctx,
    int secs, int millis, int micros);
WOLFSSL_API int wolfSSL_TS_RESP_CTX_add_flags(WOLFSSL_TS_RESP_CTX* ctx,
    int flags);
WOLFSSL_API WOLFSSL_TS_RESP* wolfSSL_TS_RESP_create_response(
    WOLFSSL_TS_RESP_CTX* ctx, WOLFSSL_BIO* req_bio);
#endif /* WOLFSSL_TSP_RESPONDER */

#ifndef OPENSSL_COEXIST

typedef WOLFSSL_TS_MSG_IMPRINT TS_MSG_IMPRINT;
typedef WOLFSSL_TS_REQ         TS_REQ;
typedef WOLFSSL_TS_ACCURACY    TS_ACCURACY;
typedef WOLFSSL_TS_STATUS_INFO TS_STATUS_INFO;
typedef WOLFSSL_TS_TST_INFO    TS_TST_INFO;
typedef WOLFSSL_TS_RESP        TS_RESP;
typedef WOLFSSL_TS_VERIFY_CTX  TS_VERIFY_CTX;

#define TS_STATUS_GRANTED                 WOLFSSL_TS_STATUS_GRANTED
#define TS_STATUS_GRANTED_WITH_MODS       WOLFSSL_TS_STATUS_GRANTED_WITH_MODS
#define TS_STATUS_REJECTION               WOLFSSL_TS_STATUS_REJECTION
#define TS_STATUS_WAITING                 WOLFSSL_TS_STATUS_WAITING
#define TS_STATUS_REVOCATION_WARNING      WOLFSSL_TS_STATUS_REVOCATION_WARNING
#define TS_STATUS_REVOCATION_NOTIFICATION \
        WOLFSSL_TS_STATUS_REVOCATION_NOTIFICATION

#define TS_VFY_SIGNATURE        WOLFSSL_TS_VFY_SIGNATURE
#define TS_VFY_VERSION          WOLFSSL_TS_VFY_VERSION
#define TS_VFY_POLICY           WOLFSSL_TS_VFY_POLICY
#define TS_VFY_IMPRINT          WOLFSSL_TS_VFY_IMPRINT
#define TS_VFY_DATA             WOLFSSL_TS_VFY_DATA
#define TS_VFY_NONCE            WOLFSSL_TS_VFY_NONCE
#define TS_VFY_SIGNER           WOLFSSL_TS_VFY_SIGNER
#define TS_VFY_TSA_NAME         WOLFSSL_TS_VFY_TSA_NAME
#define TS_VFY_ALL_IMPRINT      WOLFSSL_TS_VFY_ALL_IMPRINT

#define TS_MSG_IMPRINT_new          wolfSSL_TS_MSG_IMPRINT_new
#define TS_MSG_IMPRINT_free         wolfSSL_TS_MSG_IMPRINT_free
#define TS_MSG_IMPRINT_set_algo     wolfSSL_TS_MSG_IMPRINT_set_algo
#define TS_MSG_IMPRINT_get_algo     wolfSSL_TS_MSG_IMPRINT_get_algo
#define TS_MSG_IMPRINT_set_msg      wolfSSL_TS_MSG_IMPRINT_set_msg
#define TS_MSG_IMPRINT_get_msg      wolfSSL_TS_MSG_IMPRINT_get_msg

#ifdef WOLFSSL_TSP_REQUESTER
#define TS_REQ_new                  wolfSSL_TS_REQ_new
#define TS_REQ_free                 wolfSSL_TS_REQ_free
#define TS_REQ_set_version          wolfSSL_TS_REQ_set_version
#define TS_REQ_get_version          wolfSSL_TS_REQ_get_version
#define TS_REQ_set_msg_imprint      wolfSSL_TS_REQ_set_msg_imprint
#define TS_REQ_get_msg_imprint      wolfSSL_TS_REQ_get_msg_imprint
#define TS_REQ_set_policy_id        wolfSSL_TS_REQ_set_policy_id
#define TS_REQ_get_policy_id        wolfSSL_TS_REQ_get_policy_id
#define TS_REQ_set_nonce            wolfSSL_TS_REQ_set_nonce
#define TS_REQ_get_nonce            wolfSSL_TS_REQ_get_nonce
#define TS_REQ_set_cert_req         wolfSSL_TS_REQ_set_cert_req
#define TS_REQ_get_cert_req         wolfSSL_TS_REQ_get_cert_req
#define i2d_TS_REQ                  wolfSSL_i2d_TS_REQ
#define d2i_TS_REQ                  wolfSSL_d2i_TS_REQ
#endif /* WOLFSSL_TSP_REQUESTER */

#define TS_STATUS_INFO_get0_status  wolfSSL_TS_STATUS_INFO_get0_status
#define TS_STATUS_INFO_get0_text    wolfSSL_TS_STATUS_INFO_get0_text
#define sk_ASN1_UTF8STRING_num      wolfSSL_sk_num
#define sk_ASN1_UTF8STRING_value    wolfSSL_sk_value
#define TS_STATUS_INFO_get0_failure_info \
        wolfSSL_TS_STATUS_INFO_get0_failure_info

#define TS_ACCURACY_get_seconds     wolfSSL_TS_ACCURACY_get_seconds
#define TS_ACCURACY_get_millis      wolfSSL_TS_ACCURACY_get_millis
#define TS_ACCURACY_get_micros      wolfSSL_TS_ACCURACY_get_micros

#define TS_TST_INFO_free            wolfSSL_TS_TST_INFO_free
#define d2i_TS_TST_INFO             wolfSSL_d2i_TS_TST_INFO
#define i2d_TS_TST_INFO             wolfSSL_i2d_TS_TST_INFO
#define TS_TST_INFO_get_version     wolfSSL_TS_TST_INFO_get_version
#define TS_TST_INFO_get_policy_id   wolfSSL_TS_TST_INFO_get_policy_id
#define TS_TST_INFO_get_msg_imprint wolfSSL_TS_TST_INFO_get_msg_imprint
#define TS_TST_INFO_get_serial      wolfSSL_TS_TST_INFO_get_serial
#define TS_TST_INFO_get_time        wolfSSL_TS_TST_INFO_get_time
#define TS_TST_INFO_get_accuracy    wolfSSL_TS_TST_INFO_get_accuracy
#define TS_TST_INFO_get_ordering    wolfSSL_TS_TST_INFO_get_ordering
#define TS_TST_INFO_get_nonce       wolfSSL_TS_TST_INFO_get_nonce
#define TS_TST_INFO_get_tsa         wolfSSL_TS_TST_INFO_get_tsa

#define TS_RESP_free                wolfSSL_TS_RESP_free
#define d2i_TS_RESP                 wolfSSL_d2i_TS_RESP
#define i2d_TS_RESP                 wolfSSL_i2d_TS_RESP
#define TS_RESP_get_status_info     wolfSSL_TS_RESP_get_status_info
#define TS_RESP_get_tst_info        wolfSSL_TS_RESP_get_tst_info

#define TS_VERIFY_CTX_new           wolfSSL_TS_VERIFY_CTX_new
#define TS_VERIFY_CTX_free          wolfSSL_TS_VERIFY_CTX_free
#define TS_VERIFY_CTX_cleanup       wolfSSL_TS_VERIFY_CTX_cleanup
#define TS_VERIFY_CTX_set_flags     wolfSSL_TS_VERIFY_CTX_set_flags
#define TS_VERIFY_CTX_add_flags     wolfSSL_TS_VERIFY_CTX_add_flags
#define TS_VERIFY_CTX_set_imprint   wolfSSL_TS_VERIFY_CTX_set_imprint
#define TS_VERIFY_CTX_set_store     wolfSSL_TS_VERIFY_CTX_set_store
#define TS_VERIFY_CTX_set_data      wolfSSL_TS_VERIFY_CTX_set_data
#ifdef WOLFSSL_TSP_REQUESTER
#define TS_REQ_to_TS_VERIFY_CTX     wolfSSL_TS_REQ_to_TS_VERIFY_CTX
#endif
#define TS_RESP_verify_response     wolfSSL_TS_RESP_verify_response
#ifdef OPENSSL_ALL
#define TS_RESP_verify_token        wolfSSL_TS_RESP_verify_token
#endif

#define TS_TST_INFO_get_tsa         wolfSSL_TS_TST_INFO_get_tsa

#ifdef WOLFSSL_TSP_RESPONDER
#define TS_RESP_CTX_new             wolfSSL_TS_RESP_CTX_new
#define TS_RESP_CTX_free            wolfSSL_TS_RESP_CTX_free
#define TS_RESP_CTX_set_signer_cert wolfSSL_TS_RESP_CTX_set_signer_cert
#define TS_RESP_CTX_set_signer_key  wolfSSL_TS_RESP_CTX_set_signer_key
#define TS_RESP_CTX_set_signer_digest wolfSSL_TS_RESP_CTX_set_signer_digest
#define TS_RESP_CTX_set_def_policy  wolfSSL_TS_RESP_CTX_set_def_policy
#define TS_RESP_CTX_set_serial_cb   wolfSSL_TS_RESP_CTX_set_serial_cb
#define TS_RESP_CTX_set_time_cb     wolfSSL_TS_RESP_CTX_set_time_cb
#define TS_RESP_CTX_set_accuracy    wolfSSL_TS_RESP_CTX_set_accuracy
#define TS_RESP_CTX_add_flags       wolfSSL_TS_RESP_CTX_add_flags
#define TS_RESP_create_response     wolfSSL_TS_RESP_create_response
#define TS_RESP_CTX                 WOLFSSL_TS_RESP_CTX
#define TS_TSA_NAME                 WOLFSSL_TS_TSA_NAME
#define TS_ORDERING                 WOLFSSL_TS_ORDERING
#define TS_ESS_CERT_ID_CHAIN        WOLFSSL_TS_ESS_CERT_ID_CHAIN
#endif /* WOLFSSL_TSP_RESPONDER */

#endif /* !OPENSSL_COEXIST */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* OPENSSL_EXTRA && WOLFSSL_TSP && HAVE_PKCS7 */
#endif /* WOLFSSL_OPENSSL_TS_H_ */
