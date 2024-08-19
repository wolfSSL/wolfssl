/* error-ssl.h
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



#ifndef WOLFSSL_ERROR_H
#define WOLFSSL_ERROR_H

#include <wolfssl/wolfcrypt/error-crypt.h>   /* pull in wolfCrypt errors */

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES_H
    #include <wolfssl/debug-untrace-error-codes.h>
#endif

#define WOLFSSL_FATAL_ERROR            -1 /* must be -1 for backward compat. */

/* negative counterparts to namesake positive constants in ssl.h */
#define WOLFSSL_ERROR_WANT_READ_E      -2
#define WOLFSSL_ERROR_WANT_WRITE_E     -3
#define WOLFSSL_ERROR_WANT_X509_LOOKUP_E -4
#define WOLFSSL_ERROR_SYSCALL_E        -5
#define WOLFSSL_ERROR_ZERO_RETURN_E    -6
#define WOLFSSL_ERROR_WANT_CONNECT_E   -7
#define WOLFSSL_ERROR_WANT_ACCEPT_E    -8

#define WOLFSSL_FIRST_E             -301
#define INPUT_CASE_ERROR            -301   /* process input state error */
#define PREFIX_ERROR                -302   /* bad index to key rounds  */
#define MEMORY_ERROR                -303   /* out of memory            */
#define VERIFY_FINISHED_ERROR       -304   /* verify problem on finished */
#define VERIFY_MAC_ERROR            -305   /* verify mac problem       */
#define PARSE_ERROR                 -306   /* parse error on header    */
#define UNKNOWN_HANDSHAKE_TYPE      -307   /* weird handshake type     */
#define SOCKET_ERROR_E              -308   /* error state on socket    */
#define SOCKET_NODATA               -309   /* expected data, not there */
#define INCOMPLETE_DATA             -310   /* don't have enough data to
                                              complete task            */
#define UNKNOWN_RECORD_TYPE         -311   /* unknown type in record hdr */
#define DECRYPT_ERROR               -312   /* error during decryption  */
#define FATAL_ERROR                 -313   /* recvd alert fatal error  */
#define ENCRYPT_ERROR               -314   /* error during encryption  */
#define FREAD_ERROR                 -315   /* fread problem            */
#define NO_PEER_KEY                 -316   /* need peer's key          */
#define NO_PRIVATE_KEY              -317   /* need the private key     */
#define RSA_PRIVATE_ERROR           -318   /* error during rsa priv op */
#define NO_DH_PARAMS                -319   /* server missing DH params */
#define BUILD_MSG_ERROR             -320   /* build message failure    */
#define BAD_HELLO                   -321   /* client hello malformed   */
#define DOMAIN_NAME_MISMATCH        -322   /* peer subject name mismatch */
#define WANT_READ                   -323   /* want read, call again    */
#define NOT_READY_ERROR             -324   /* handshake layer not ready */
#define IPADDR_MISMATCH             -325   /* peer ip address mismatch */
#define VERSION_ERROR               -326   /* record layer version error */
#define WANT_WRITE                  -327   /* want write, call again   */
#define BUFFER_ERROR                -328   /* malformed buffer input   */
#define VERIFY_CERT_ERROR           -329   /* verify cert error        */
#define VERIFY_SIGN_ERROR           -330   /* verify sign error        */
#define CLIENT_ID_ERROR             -331   /* psk client identity error  */
#define SERVER_HINT_ERROR           -332   /* psk server hint error  */
#define PSK_KEY_ERROR               -333   /* psk key error  */

#define GETTIME_ERROR               -337   /* gettimeofday failed ??? */
#define GETITIMER_ERROR             -338   /* getitimer failed ??? */
#define SIGACT_ERROR                -339   /* sigaction failed ??? */
#define SETITIMER_ERROR             -340   /* setitimer failed ??? */
#define LENGTH_ERROR                -341   /* record layer length error */
#define PEER_KEY_ERROR              -342   /* can't decode peer key */
#define ZERO_RETURN                 -343   /* peer sent close notify */
#define SIDE_ERROR                  -344   /* wrong client/server type */
#define NO_PEER_CERT                -345   /* peer didn't send key */

#define ECC_CURVETYPE_ERROR         -350   /* Bad ECC Curve Type */
#define ECC_CURVE_ERROR             -351   /* Bad ECC Curve */
#define ECC_PEERKEY_ERROR           -352   /* Bad Peer ECC Key */
#define ECC_MAKEKEY_ERROR           -353   /* Bad Make ECC Key */
#define ECC_EXPORT_ERROR            -354   /* Bad ECC Export Key */
#define ECC_SHARED_ERROR            -355   /* Bad ECC Shared Secret */

#define NOT_CA_ERROR                -357   /* Not a CA cert error */

#define BAD_CERT_MANAGER_ERROR      -359   /* Bad Cert Manager */
#define OCSP_CERT_REVOKED           -360   /* OCSP Certificate revoked */
#define CRL_CERT_REVOKED            -361   /* CRL Certificate revoked */
#define CRL_MISSING                 -362   /* CRL Not loaded */
#define MONITOR_SETUP_E             -363   /* CRL Monitor setup error */
#define THREAD_CREATE_E             -364   /* Thread Create Error */
#define OCSP_NEED_URL               -365   /* OCSP need an URL for lookup */
#define OCSP_CERT_UNKNOWN           -366   /* OCSP responder doesn't know */
#define OCSP_LOOKUP_FAIL            -367   /* OCSP lookup not successful */
#define MAX_CHAIN_ERROR             -368   /* max chain depth exceeded */
#define COOKIE_ERROR                -369   /* dtls cookie error */
#define SEQUENCE_ERROR              -370   /* dtls sequence error */
#define SUITES_ERROR                -371   /* suites pointer error */

#define OUT_OF_ORDER_E              -373   /* out of order message */
#define BAD_KEA_TYPE_E              -374   /* bad KEA type found */
#define SANITY_CIPHER_E             -375   /* sanity check on cipher error */
#define RECV_OVERFLOW_E             -376   /* RXCB returned more than read */
#define GEN_COOKIE_E                -377   /* Generate Cookie Error */
#define NO_PEER_VERIFY              -378   /* Need peer cert verify Error */
#define FWRITE_ERROR                -379   /* fwrite problem */
#define CACHE_MATCH_ERROR           -380   /* Cache hdr match error */
#define UNKNOWN_SNI_HOST_NAME_E     -381   /* Unrecognized host name Error */
#define UNKNOWN_MAX_FRAG_LEN_E      -382   /* Unrecognized max frag len Error */
#define KEYUSE_SIGNATURE_E          -383   /* KeyUse digSignature error */

#define KEYUSE_ENCIPHER_E           -385   /* KeyUse keyEncipher error */
#define EXTKEYUSE_AUTH_E            -386   /* ExtKeyUse server|client_auth */
#define SEND_OOB_READ_E             -387   /* Send Cb out of bounds read */
#define SECURE_RENEGOTIATION_E      -388   /* Invalid Renegotiation Info */
#define SESSION_TICKET_LEN_E        -389   /* Session Ticket too large */
#define SESSION_TICKET_EXPECT_E     -390   /* Session Ticket missing   */
#define SCR_DIFFERENT_CERT_E        -391   /* SCR Different cert error  */
#define SESSION_SECRET_CB_E         -392   /* Session secret Cb fcn failure */
#define NO_CHANGE_CIPHER_E          -393   /* Finished before change cipher */
#define SANITY_MSG_E                -394   /* Sanity check on msg order error */
#define DUPLICATE_MSG_E             -395   /* Duplicate message error */
#define SNI_UNSUPPORTED             -396   /* SSL 3.0 does not support SNI */
#define SOCKET_PEER_CLOSED_E        -397   /* Underlying transport closed */
#define BAD_TICKET_KEY_CB_SZ        -398   /* Bad session ticket key cb size */
#define BAD_TICKET_MSG_SZ           -399   /* Bad session ticket msg size    */
#define BAD_TICKET_ENCRYPT          -400   /* Bad user ticket encrypt        */
#define DH_KEY_SIZE_E               -401   /* DH Key too small */
#define SNI_ABSENT_ERROR            -402   /* No SNI request. */
#define RSA_SIGN_FAULT              -403   /* RSA Sign fault */
#define HANDSHAKE_SIZE_ERROR        -404   /* Handshake message too large */
#define UNKNOWN_ALPN_PROTOCOL_NAME_E -405   /* Unrecognized protocol name Error*/
#define BAD_CERTIFICATE_STATUS_ERROR -406   /* Bad certificate status message */
#define OCSP_INVALID_STATUS         -407   /* Invalid OCSP Status */
#define OCSP_WANT_READ              -408   /* OCSP callback response WOLFSSL_CBIO_ERR_WANT_READ */
#define RSA_KEY_SIZE_E              -409   /* RSA key too small */
#define ECC_KEY_SIZE_E              -410   /* ECC key too small */
#define DTLS_EXPORT_VER_E           -411   /* export version error */
#define INPUT_SIZE_E                -412   /* input size too big error */
#define CTX_INIT_MUTEX_E            -413   /* initialize ctx mutex error */
#define EXT_MASTER_SECRET_NEEDED_E  -414   /* need EMS enabled to resume */
#define DTLS_POOL_SZ_E              -415   /* exceeded DTLS pool size */
#define DECODE_E                    -416   /* decode handshake message error */
#define HTTP_TIMEOUT                -417   /* HTTP timeout for OCSP or CRL req */
#define WRITE_DUP_READ_E            -418   /* Write dup write side can't read */
#define WRITE_DUP_WRITE_E           -419   /* Write dup read side can't write */
#define INVALID_CERT_CTX_E          -420   /* TLS cert ctx not matching */
#define BAD_KEY_SHARE_DATA          -421   /* Key Share data invalid */
#define MISSING_HANDSHAKE_DATA      -422   /* Handshake message missing data */
#define BAD_BINDER                  -423   /* Binder does not match */
#define EXT_NOT_ALLOWED             -424   /* Extension not allowed in msg */
#define INVALID_PARAMETER           -425   /* Security parameter invalid */
#define MCAST_HIGHWATER_CB_E        -426   /* Multicast highwater cb err */
#define ALERT_COUNT_E               -427   /* Alert Count exceeded err */
#define EXT_MISSING                 -428   /* Required extension not found */
#define UNSUPPORTED_EXTENSION       -429   /* TLSX not requested by client */
#define PRF_MISSING                 -430   /* PRF not compiled in */
#define DTLS_RETX_OVER_TX           -431   /* Retransmit DTLS flight over */
#define DH_PARAMS_NOT_FFDHE_E       -432   /* DH params from server not FFDHE */
#define TCA_INVALID_ID_TYPE         -433   /* TLSX TCA ID type invalid */
#define TCA_ABSENT_ERROR            -434   /* TLSX TCA ID no response */
#define TSIP_MAC_DIGSZ_E            -435   /* Invalid MAC size for TSIP */
#define CLIENT_CERT_CB_ERROR        -436   /* Client cert callback error */
#define SSL_SHUTDOWN_ALREADY_DONE_E -437   /* Shutdown called redundantly */
#define TLS13_SECRET_CB_E           -438   /* TLS1.3 secret Cb fcn failure */
#define DTLS_SIZE_ERROR             -439   /* Trying to send too much data */
#define NO_CERT_ERROR               -440   /* TLS1.3 - no cert set error */
#define APP_DATA_READY              -441   /* DTLS1.2 application data ready for read */
#define TOO_MUCH_EARLY_DATA         -442   /* Too much Early data */
#define SOCKET_FILTERED_E           -443   /* Session stopped by network filter */
#define HTTP_RECV_ERR               -444   /* HTTP Receive error */
#define HTTP_HEADER_ERR             -445   /* HTTP Header error */
#define HTTP_PROTO_ERR              -446   /* HTTP Protocol error */
#define HTTP_STATUS_ERR             -447   /* HTTP Status error */
#define HTTP_VERSION_ERR            -448   /* HTTP Version error */
#define HTTP_APPSTR_ERR             -449   /* HTTP Application string error */
#define UNSUPPORTED_PROTO_VERSION   -450   /* bad/unsupported protocol version*/
#define FALCON_KEY_SIZE_E           -451   /* Wrong key size for Falcon. */
#define QUIC_TP_MISSING_E           -452   /* QUIC transport parameter missing */
#define DILITHIUM_KEY_SIZE_E        -453   /* Wrong key size for Dilithium. */
#define DTLS_CID_ERROR              -454   /* Wrong or missing CID */
#define DTLS_TOO_MANY_FRAGMENTS_E   -455   /* Received too many fragments */
#define QUIC_WRONG_ENC_LEVEL        -456   /* QUIC data received on wrong encryption level */

#define DUPLICATE_TLS_EXT_E         -457   /* Duplicate TLS extension in msg. */
/* add strings to wolfSSL_ERR_reason_error_string in internal.c !!!!! */

/* begin negotiation parameter errors */
#define UNSUPPORTED_SUITE           -500   /* unsupported cipher suite */
#define MATCH_SUITE_ERROR           -501   /* can't match cipher suite */
#define COMPRESSION_ERROR           -502   /* compression mismatch */
#define KEY_SHARE_ERROR             -503   /* key share mismatch */
#define POST_HAND_AUTH_ERROR        -504   /* client won't do post-hand auth */
#define HRR_COOKIE_ERROR            -505   /* HRR msg cookie mismatch */
#define UNSUPPORTED_CERTIFICATE     -506    /* unsupported certificate type */
    /* end negotiation parameter errors only 10 for now */

#define WOLFSSL_LAST_E              -506

    /* add strings to wolfSSL_ERR_reason_error_string in internal.c !!!!! */

    /* no error strings go down here, add above negotiation errors !!!! */

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

#if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
    enum {
        MIN_PARAM_ERR = UNSUPPORTED_SUITE,
        MAX_PARAM_ERR = MIN_PARAM_ERR - 10
    };
#endif


WOLFSSL_LOCAL
void SetErrorString(int err, char* buff);

#if defined(WOLFSSL_DEBUG_TRACE_ERROR_CODES) && \
        (defined(BUILDING_WOLFSSL) || \
         defined(WOLFSSL_DEBUG_TRACE_ERROR_CODES_ALWAYS))
    #include <wolfssl/debug-trace-error-codes.h>
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* wolfSSL_ERROR_H */
