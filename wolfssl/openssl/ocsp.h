/* ocsp.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* ocsp.h for libcurl */

#ifndef WOLFSSL_OCSP_H_
#define WOLFSSL_OCSP_H_

#ifdef HAVE_OCSP
#include <wolfssl/ocsp.h>

#ifndef OPENSSL_COEXIST

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(WOLFSSL_NGINX) ||\
    defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY)
typedef OcspRequest                      OCSP_REQUEST;
typedef OcspResponse                     OCSP_RESPONSE;
typedef WOLFSSL_OCSP_BASICRESP           OCSP_BASICRESP;
typedef WOLFSSL_OCSP_SINGLERESP          OCSP_SINGLERESP;
typedef WOLFSSL_OCSP_CERTID              OCSP_CERTID;
typedef WOLFSSL_OCSP_ONEREQ              OCSP_ONEREQ;
typedef WOLFSSL_OCSP_REQ_CTX             OCSP_REQ_CTX;
#endif

#define OCSP_REVOKED_STATUS_NOSTATUS     (-1)


#define OCSP_RESPONSE_STATUS_SUCCESSFUL  0
#define OCSP_RESPONSE_STATUS_TRYLATER    3

#define V_OCSP_CERTSTATUS_GOOD           0
#define V_OCSP_CERTSTATUS_REVOKED        1
#define V_OCSP_CERTSTATUS_UNKNOWN        2

#define OCSP_resp_find_status     wolfSSL_OCSP_resp_find_status
#define OCSP_cert_status_str      wolfSSL_OCSP_cert_status_str
#define OCSP_check_validity       wolfSSL_OCSP_check_validity

#define OCSP_CERTID_free          wolfSSL_OCSP_CERTID_free
#define OCSP_cert_to_id           wolfSSL_OCSP_cert_to_id

#define OCSP_BASICRESP_free       wolfSSL_OCSP_BASICRESP_free
#define OCSP_basic_verify         wolfSSL_OCSP_basic_verify

#define OCSP_RESPONSE_free        wolfSSL_OCSP_RESPONSE_free
#define d2i_OCSP_RESPONSE_bio     wolfSSL_d2i_OCSP_RESPONSE_bio
#define d2i_OCSP_RESPONSE         wolfSSL_d2i_OCSP_RESPONSE
#define i2d_OCSP_RESPONSE         wolfSSL_i2d_OCSP_RESPONSE
#define OCSP_response_status      wolfSSL_OCSP_response_status
#define OCSP_response_status_str  wolfSSL_OCSP_response_status_str
#define OCSP_response_get1_basic  wolfSSL_OCSP_response_get1_basic
#define OCSP_response_create      wolfSSL_OCSP_response_create

#define OCSP_REQUEST_new          wolfSSL_OCSP_REQUEST_new
#define OCSP_REQUEST_free         wolfSSL_OCSP_REQUEST_free
#define i2d_OCSP_REQUEST          wolfSSL_i2d_OCSP_REQUEST
#define OCSP_request_add0_id      wolfSSL_OCSP_request_add0_id
#define OCSP_request_add1_nonce   wolfSSL_OCSP_request_add1_nonce
#define OCSP_check_nonce          wolfSSL_OCSP_check_nonce
#define OCSP_id_get0_info         wolfSSL_OCSP_id_get0_info
#define OCSP_crl_reason_str       wolfSSL_OCSP_crl_reason_str
#define OCSP_REQUEST_add_ext      wolfSSL_OCSP_REQUEST_add_ext

#define OCSP_CERTID_dup           wolfSSL_OCSP_CERTID_dup

#define i2d_OCSP_REQUEST_bio      wolfSSL_i2d_OCSP_REQUEST_bio

#define i2d_OCSP_CERTID           wolfSSL_i2d_OCSP_CERTID
#define d2i_OCSP_CERTID           wolfSSL_d2i_OCSP_CERTID
#define OCSP_SINGLERESP_get0_id   wolfSSL_OCSP_SINGLERESP_get0_id
#define OCSP_id_cmp               wolfSSL_OCSP_id_cmp
#define OCSP_single_get0_status   wolfSSL_OCSP_single_get0_status
#define OCSP_resp_count           wolfSSL_OCSP_resp_count
#define OCSP_resp_get0            wolfSSL_OCSP_resp_get0

#define OCSP_REQ_CTX_new          wolfSSL_OCSP_REQ_CTX_new
#define OCSP_REQ_CTX_free         wolfSSL_OCSP_REQ_CTX_free
#define OCSP_sendreq_new          wolfSSL_OCSP_sendreq_new
#define OCSP_REQ_CTX_set1_req     wolfSSL_OCSP_REQ_CTX_set1_req
#define OCSP_REQ_CTX_add1_header  wolfSSL_OCSP_REQ_CTX_add1_header
#define OCSP_REQ_CTX_http         wolfSSL_OCSP_REQ_CTX_http
#define OCSP_REQ_CTX_nbio         wolfSSL_OCSP_REQ_CTX_nbio
#define OCSP_sendreq_nbio         wolfSSL_OCSP_sendreq_nbio

#endif /* !OPENSSL_COEXIST */

#endif /* HAVE_OCSP */

#endif /* WOLFSSL_OCSP_H_ */

