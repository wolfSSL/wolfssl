/* test_tls13_features.c
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

/* MC/DC vectors for src/tls13.c's FEATURE-FLAG decisions (ISO 26262 Part 7,
 * Track B): the rows that test ssl->options.* state, extension presence and
 * PSK / ticket / early-data negotiation results.
 *
 * An ssl->options.X operand that is stuck on one row usually means no test
 * ever turns X on -- a fixture gap, not a hard condition. Each test here
 * negotiates a feature combination the tls13 group did not previously
 * negotiate at all, and is paired with the ordinary handshakes that group
 * already runs so that both rows of the independence pair exist in the same
 * unit.test binary.
 *
 * Everything is driven over the tests/utils.c memio transport. The only
 * non-WOLFSSL_API symbol used is BuildTls13Message(), which is declared
 * WOLFSSL_TEST_VIS (exported for tests) and is already used the same way by
 * test_tls13_zero_inner_content_type(), so this file links in a shared build.
 */

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_tls13_features.h>

#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)

/* -------------------------------------------------------------------------
 * Optional client authentication: the server asks for a certificate but does
 * not insist on one, and the client has none configured.
 * ---------------------------------------------------------------------- */

/* wolfSSL_accept_TLSv13() TLS13_ACCEPT_FINISHED_DONE:
 *
 *   if (!resuming && verifyPeer && !verifyPostHandshake &&
 *       !havePeerCert && !failNoCert)
 *       peerAuthGood = 1;
 *
 * needs a server that set WOLFSSL_VERIFY_PEER *without*
 * WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT and a client that answers the
 * CertificateRequest with an empty Certificate. The group's other
 * client-auth handshakes all supply a certificate (havePeerCert = 1), so
 * this decision had never been true.
 *
 * The same handshake leaves the server with
 * msgsReceived.got_certificate = 1 and got_certificate_verify = 0, which is
 * the state test_tls13_feat_post_handshake_unexpected_msg() below needs. */
int test_tls13_feat_optional_client_cert(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Request a client certificate but accept the handshake without one. */
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The client had no certificate to send, so the server saw an empty
     * Certificate message and no CertificateVerify, and still accepted. */
    ExpectIntEQ(ssl_s->msgsReceived.got_certificate, 1);
    ExpectIntEQ(ssl_s->msgsReceived.got_certificate_verify, 0);
    ExpectIntEQ(ssl_s->options.havePeerCert, 0);
    ExpectIntEQ(ssl_s->options.peerAuthGood, 1);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* -------------------------------------------------------------------------
 * A handshake message of a type that is not legal after the handshake.
 * ---------------------------------------------------------------------- */

/* DoTls13HandShakeMsgType():
 *
 *   if (handShakeState == HANDSHAKE_DONE &&
 *       type != session_ticket && type != certificate_request &&
 *       type != certificate && type != key_update && type != finished
 *       && type != request_connection_id && type != new_connection_id)
 *
 * The group already produces every "false" row of this chain: a client
 * receiving a post-handshake NewSessionTicket, a post-handshake auth
 * CertificateRequest / Certificate / Finished, a KeyUpdate, and the DTLS
 * connection-id messages. What no test ever produced is the row where the
 * whole chain is TRUE -- a post-handshake handshake message of some other
 * type -- so none of the eight operands had a pair.
 *
 * CertificateVerify is the type that reaches the check: on a server,
 * SanityCheckTls13MsgReceived() lets it through once the server has sent
 * its Finished, has seen a ClientHello and a Certificate, and has not yet
 * seen a CertificateVerify. Optional client authentication (the test above)
 * leaves exactly that state.
 *
 * The message is built with the client's own application-data keys via
 * BuildTls13Message() and handed to the server with wolfSSL_inject(), so
 * this is a real record on the real connection, not a poke at internals. */
int test_tls13_feat_post_handshake_unexpected_msg(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;
    /* handshake header for a 4-byte CertificateVerify body, plus a body the
     * server never gets as far as parsing */
    byte hsMsg[8] = { certificate_verify, 0x00, 0x00, 0x04,
                      0x08, 0x04, 0x00, 0x00 };
    byte record[128];
    char readBuf[16];
    int recordSz = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&h, 0, sizeof(h));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Optional client auth: server sees an empty Certificate and no
     * CertificateVerify, so a later CertificateVerify is not a duplicate. */
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);
    /* Keep the post-handshake flight to just our injected message. */
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(ssl_s), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_s->options.handShakeState, HANDSHAKE_DONE);
    ExpectIntEQ(ssl_s->msgsReceived.got_certificate, 1);
    ExpectIntEQ(ssl_s->msgsReceived.got_certificate_verify, 0);

    if (EXPECT_SUCCESS()) {
        recordSz = BuildTls13Message(ssl_c, record, (int)sizeof(record), hsMsg,
            (int)sizeof(hsMsg), handshake, 0, 0, 0);
        ExpectIntGT(recordSz, 0);
    }
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_inject(ssl_s, record, recordSz),
            WOLFSSL_SUCCESS);
    }

    /* RFC 8446 Section 4.6: an unexpected handshake message after the
     * handshake is a fatal unexpected_message alert. */
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, (int)sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WC_NO_ERR_TRACE(OUT_OF_ORDER_E));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_s, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_tx.code, unexpected_message);
    ExpectIntEQ(h.last_tx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* -------------------------------------------------------------------------
 * External PSK negotiated in psk_ke mode -- no (EC)DHE, no key_share.
 * ---------------------------------------------------------------------- */

#if !defined(NO_PSK)

static const byte test_tls13_feat_psk[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const char test_tls13_feat_psk_id[] = "feat_psk_client";

static unsigned int test_tls13_feat_psk_client_cb(WOLFSSL* ssl,
    const char* hint, char* identity, unsigned int id_max_len,
    unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    if (id_max_len <= XSTRLEN(test_tls13_feat_psk_id) ||
            key_max_len < sizeof(test_tls13_feat_psk))
        return 0;
    XSTRNCPY(identity, test_tls13_feat_psk_id, id_max_len);
    XMEMCPY(key, test_tls13_feat_psk, sizeof(test_tls13_feat_psk));
    return (unsigned int)sizeof(test_tls13_feat_psk);
}

static unsigned int test_tls13_feat_psk_server_cb(WOLFSSL* ssl,
    const char* id, unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    if (id == NULL || key_max_len < sizeof(test_tls13_feat_psk))
        return 0;
    if (XSTRCMP(id, test_tls13_feat_psk_id) != 0)
        return 0;
    XMEMCPY(key, test_tls13_feat_psk, sizeof(test_tls13_feat_psk));
    return (unsigned int)sizeof(test_tls13_feat_psk);
}

#endif /* !NO_PSK */

/* SetupPskKey() and CheckPreSharedKeys() both branch on whether the peer
 * offered psk_dhe_ke and on whether a key_share entry is present:
 *
 *   if (((modes & (1 << PSK_DHE_KE)) != 0) && !noPskDheKe &&
 *        kse != NULL && kse->derived)              [SetupPskKey]
 *   if (((modes & (1 << PSK_DHE_KE)) != 0 && !noPskDheKe && ext != NULL)
 *        || usingCertWithExternPsk)                [CheckPreSharedKeys]
 *
 * Every PSK handshake in the group runs psk_dhe_ke, so the kse == NULL /
 * ext == NULL rows were unreachable. wolfSSL_no_dhe_psk() on both ends
 * negotiates plain psk_ke: no key_share is offered and preMasterSz is
 * zeroed. The group's existing psk_dhe_ke handshakes are the partner row. */
int test_tls13_feat_psk_ke_no_dhe(void)
{
    EXPECT_DECLS;
#if !defined(NO_PSK) && defined(HAVE_SUPPORTED_CURVES)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char appMsg[] = "psk_ke";
    char readBuf[sizeof(appMsg)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_feat_psk_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_feat_psk_server_cb);

    /* psk_ke only: the ClientHello carries no key_share extension. */
    ExpectIntEQ(wolfSSL_no_dhe_psk(ssl_c), 0);
    ExpectIntEQ(wolfSSL_no_dhe_psk(ssl_s), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_c->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_s->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_c->options.noPskDheKe, 1);
    ExpectIntEQ(ssl_s->options.noPskDheKe, 1);

    ExpectIntEQ(wolfSSL_write(ssl_c, appMsg, (int)XSTRLEN(appMsg)),
        (int)XSTRLEN(appMsg));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, (int)sizeof(readBuf)),
        (int)XSTRLEN(appMsg));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* The rejecting partner of the vector above, for the
 *
 *   else if (onlyPskDheKe || (failNoPSK && !resumption))
 *
 * arms of CheckPreSharedKeys() and SetupPskKey(): a server that insists on
 * forward secrecy (wolfSSL_only_dhe_psk) facing a client that offers
 * psk_ke only. onlyPskDheKe had never been set on a live handshake -- the
 * group only exercised it through the argument-validation API test. */
int test_tls13_feat_psk_only_dhe_rejects_psk_ke(void)
{
    EXPECT_DECLS;
#if !defined(NO_PSK) && defined(HAVE_SUPPORTED_CURVES)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_feat_psk_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_feat_psk_server_cb);

    ExpectIntEQ(wolfSSL_no_dhe_psk(ssl_c), 0);
    ExpectIntEQ(wolfSSL_only_dhe_psk(ssl_s), 0);

    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(PSK_KEY_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* wolfSSL_accept_TLSv13() TLS13_ACCEPT_FINISHED_DONE:
 *
 *   if (!noTicketTls13 && ctx->ticketEncCb != NULL)
 *       SendTls13NewSessionTicket(ssl);
 *
 * HAVE_SESSION_TICKET installs a default ticket encryption callback, so
 * ticketEncCb is non-NULL on every handshake the group runs and operand 1
 * had no false row. Clearing the callback keeps tickets enabled
 * (noTicketTls13 stays 0, so operand 0 is still true) but leaves the server
 * with no way to protect one, and it silently sends none. The group's
 * ordinary ticketed handshakes are the partner row. */
int test_tls13_feat_no_ticket_enc_cb(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Tickets stay enabled; there is just no callback to encrypt one. */
    ExpectIntEQ(wolfSSL_CTX_set_TicketEncCb(ctx_s, NULL), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_s->options.noTicketTls13, 0);
    ExpectNull(ctx_s->ticketEncCb);
    ExpectIntEQ(ssl_c->msgsReceived.got_session_ticket, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* -------------------------------------------------------------------------
 * A PSK ClientHello that offers psk_dhe_ke but carries no key_share entry.
 * ---------------------------------------------------------------------- */

/* CheckPreSharedKeys():
 *
 *   if (((modes & (1 << PSK_DHE_KE)) != 0 && !noPskDheKe && ext != NULL)
 *        || usingCertWithExternPsk)
 *
 * and SetupPskKey():
 *
 *   if (((modes & (1 << PSK_DHE_KE)) != 0) && !noPskDheKe &&
 *        kse != NULL && kse->derived)
 *
 * both need a client that advertises psk_dhe_ke with an EMPTY key_share
 * list. wolfSSL_NoKeyShares() produces exactly that (it is how the group
 * forces a HelloRetryRequest), but until now it was only ever combined with
 * cert_with_extern_psk, which takes the other arm of the || and hides the
 * ext == NULL row. Here it is combined with a plain external PSK, so the
 * left conjunct is false while usingCertWithExternPsk is also false and the
 * decision comes out false -- the partner of
 * test_tls13_cert_with_extern_psk_requires_key_share(). */
int test_tls13_feat_psk_ke_empty_key_share(void)
{
    EXPECT_DECLS;
#if !defined(NO_PSK) && defined(HAVE_SUPPORTED_CURVES)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_feat_psk_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_feat_psk_server_cb);

    /* psk_dhe_ke is still offered; the key_share list is empty. */
    ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

    /* CH1 has no key share, so the server answers with a HelloRetryRequest
     * and the PSK is only bound on CH2. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    ExpectIntEQ(ssl_c->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_s->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_s->msgsReceived.got_client_hello, 2);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* CheckPreSharedKeys(), on the branch taken when the ClientHello has no
 * pre_shared_key extension at all:
 *
 *   if (ssl->options.havePSK && ssl->options.failNoPSK)
 *       return PSK_MISSING_ERROR;
 *
 * havePSK is only set by installing an external-PSK callback, and every
 * handshake in the group that installs one also sends a PSK, so operand 1
 * was only ever evaluated with failNoPSK set (the
 * test_tls13_fail_if_no_psk_* family). This is the same server -- external
 * PSK callback installed, so havePSK is true -- but with failNoPSK left off
 * and a client that offers no PSK, so the server falls back to certificate
 * authentication instead of refusing. */
int test_tls13_feat_optional_psk_falls_back_to_cert(void)
{
    EXPECT_DECLS;
#if !defined(NO_PSK) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Server accepts an external PSK but does not require one. The client
     * has no PSK callback, so its ClientHello carries no pre_shared_key. */
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_feat_psk_server_cb);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_s->options.havePSK, 1);
    ExpectIntEQ(ssl_s->options.failNoPSK, 0);
    ExpectIntEQ(ssl_s->options.pskNegotiated, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* -------------------------------------------------------------------------
 * Post-handshake client authentication, run to completion, with the
 * status_request extension held on the CTX.
 * ---------------------------------------------------------------------- */

/* Guard must match test_tls13_feat_pha_ctx_status_request() below exactly: these
 * are its only callers, and a narrower guard leaves them defined-but-unused
 * under -Werror=unused-function. */
#if defined(WOLFSSL_POST_HANDSHAKE_AUTH) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(HAVE_OCSP) && \
    defined(KEEP_PEER_CERT) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
static int test_tls13_feat_ocsp_io_cb(void* ioCtx, const char* url, int urlSz,
    unsigned char* req, int reqSz, unsigned char** resp)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)req;
    (void)reqSz;
    *resp = NULL;
    return 0;
}

static void test_tls13_feat_ocsp_free_cb(void* ioCtx, unsigned char* resp)
{
    (void)ioCtx;
    (void)resp;
}
#endif

/* SetupOcspResp():
 *
 *   if (extension == NULL && side == WOLFSSL_CLIENT_END &&
 *       handShakeDone &&
 *       TLSX_Find(ssl->ctx->extensions, TLSX_STATUS_REQUEST) != NULL)
 *
 * is the post-handshake-auth path where the client has to rebuild the
 * status_request extension it offered in its ClientHello, because that
 * extension no longer lives on ssl->extensions. The group's existing PHA
 * stapling test offers status_request with wolfSSL_UseOCSPStapling() on the
 * *SSL*, so ssl->ctx->extensions is empty, the last operand is false and
 * the decision was never true -- leaving all four operands unpaired.
 *
 * This test offers it with wolfSSL_CTX_UseOCSPStapling() instead, so the
 * extension is on the CTX and the rebuild actually happens, and then runs
 * the post-handshake authentication all the way to the server accepting the
 * client certificate. */
int test_tls13_feat_pha_ctx_status_request(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_POST_HANDSHAKE_AUTH) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(HAVE_OCSP) && \
    defined(KEEP_PEER_CERT) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_X509* peer = NULL;
    const char msg[] = "ping";
    char buf[8];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* --- Client CTX ------------------------------------------------ */
    ExpectNotNull(ctx_c = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c, caCertFile, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx_c, cliCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_c, cliKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(ctx_c), 0);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx_c), WOLFSSL_SUCCESS);
    /* The whole point of this vector: status_request is offered from the
     * CTX, so ssl->ctx->extensions holds it and the post-handshake rebuild
     * in SetupOcspResp() finds it. */
    ExpectIntEQ(wolfSSL_CTX_UseOCSPStapling(ctx_c, WOLFSSL_CSR_OCSP, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_SetIORecv(ctx_c, test_memio_read_cb);
    wolfSSL_SetIOSend(ctx_c, test_memio_write_cb);

    /* --- Server CTX ------------------------------------------------ */
    ExpectNotNull(ctx_s = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, caCertFile, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s,
        "./certs/client-ca.pem", 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx_s, test_tls13_feat_ocsp_io_cb,
        test_tls13_feat_ocsp_free_cb, NULL), WOLFSSL_SUCCESS);
    wolfSSL_CTX_set_verify(ctx_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_SetIORecv(ctx_s, test_memio_read_cb);
    wolfSSL_SetIOSend(ctx_s, test_memio_write_cb);

    /* --- SSL objects ----------------------------------------------- */
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectNull(wolfSSL_get_peer_certificate(ssl_s));

    /* Trigger post-handshake authentication. */
    if (EXPECT_SUCCESS()) {
        wolfSSL_set_verify(ssl_s,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ExpectIntEQ(wolfSSL_request_certificate(ssl_s), WOLFSSL_SUCCESS);
    }

    ExpectIntEQ(wolfSSL_write(ssl_s, msg, (int)sizeof(msg) - 1),
        (int)sizeof(msg) - 1);
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf) - 1),
        (int)sizeof(msg) - 1);

    /* The client's reply carries Certificate (with the rebuilt staple),
     * CertificateVerify and Finished ahead of the application data. */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)sizeof(msg) - 1),
        (int)sizeof(msg) - 1);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf) - 1),
        (int)sizeof(msg) - 1);

    ExpectNotNull(peer = wolfSSL_get_peer_certificate(ssl_s));
    wolfSSL_X509_free(peer);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* -------------------------------------------------------------------------
 * A server that answers an external PSK with psk_ke, so the client's own
 * key share is never used.
 * ---------------------------------------------------------------------- */

/* SetupPskKey() runs on the CLIENT while it processes the ServerHello:
 *
 *   if (((modes & (1 << PSK_DHE_KE)) != 0) && !noPskDheKe &&
 *        kse != NULL && kse->derived)
 *   else if (onlyPskDheKe || (failNoPSK && !psk->resumption))
 *
 * Reaching the kse rows needs a client that offered psk_dhe_ke (so the
 * first two operands are true) whose key share was nevertheless not used.
 * Every PSK handshake in the group had both ends agree on psk_dhe_ke, so
 * kse was always a derived entry. Here only the SERVER is restricted to
 * psk_ke (wolfSSL_no_dhe_psk on the server), which is a configuration the
 * group never built: the client still offers psk_dhe_ke and a key share,
 * the server confirms psk_ke, and the client's key share stays underived.
 *
 * `variant` selects what the client offered:
 *   0 - a real key share (kse != NULL, kse->derived == 0)
 *   1 - an empty key_share list via wolfSSL_NoKeyShares (kse == NULL) */
static int test_tls13_feat_psk_ke_server_side(int variant)
{
    EXPECT_DECLS;
#if !defined(NO_PSK) && defined(HAVE_SUPPORTED_CURVES)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_feat_psk_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_feat_psk_server_cb);

    /* Only the server refuses (EC)DHE with a PSK. */
    ExpectIntEQ(wolfSSL_no_dhe_psk(ssl_s), 0);
    if (variant == 1)
        ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_c->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_s->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_s->options.noPskDheKe, 1);
    /* The client offered psk_dhe_ke; only the server said no. */
    ExpectIntEQ(ssl_c->options.onlyPskDheKe, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#else
    (void)variant;
#endif
    return EXPECT_RESULT();
}

int test_tls13_feat_psk_ke_server_key_share_unused(void)
{
    return test_tls13_feat_psk_ke_server_side(0);
}

int test_tls13_feat_psk_ke_server_no_key_share(void)
{
    return test_tls13_feat_psk_ke_server_side(1);
}

/* The same else-if, one operand further along:
 *
 *   else if (onlyPskDheKe || (failNoPSK && !psk->resumption))
 *
 * test_tls13_fail_if_no_psk_client_requires_dhe() supplies the row where a
 * client with a mandatory EXTERNAL PSK refuses a psk_ke ServerHello
 * (failNoPSK true, !psk->resumption true, decision true). Its partner --
 * failNoPSK still true but the PSK being a session-ticket RESUMPTION, which
 * RFC 8446 exempts -- never existed, because no test combined
 * wolfSSL_require_psk() on the client with a resumed session. */
int test_tls13_feat_psk_ke_client_require_psk_resumption(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_PSK) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    WOLFSSL_SESSION* sess = NULL;
    struct test_memio_ctx test_ctx;
    byte readBuf[16];

    /* First connection: mint a session ticket. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Drain the post-handshake NewSessionTicket. */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    /* Second connection: resume with psk_ke while the CLIENT insists on a
     * PSK. The resumption exemption means this must succeed. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_require_psk(ssl_c);
    ExpectIntEQ(wolfSSL_no_dhe_psk(ssl_c), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    ExpectIntEQ(ssl_c->options.resuming, 1);
    ExpectIntEQ(ssl_s->options.resuming, 1);
    ExpectIntEQ(ssl_c->options.failNoPSK, 1);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* -------------------------------------------------------------------------
 * A TLS 1.3 HelloRetryRequest carrying a stateless cookie, accepted.
 * ---------------------------------------------------------------------- */

/* The tail of DoTls13ClientHello() is one block guarded by
 * ssl->options.sendCookie, and inside it three decisions branch on
 * ssl->options.cookieGood:
 *
 *   if (cookieGood && acceptState == TLS13_ACCEPT_FIRST_REPLY_DONE)
 *   if (cookieGood && serverState == SERVER_HELLO_RETRY_REQUEST_COMPLETE)
 *   if (!cookieGood && serverState != SERVER_HELLO_RETRY_REQUEST_COMPLETE)
 *
 * wolfSSL_send_hrr_cookie() had only ever been called by the argument-check
 * test and by test_tls13_hrr_bad_cookie(), which corrupts the cookie so
 * cookieGood never becomes 1. No test in the group had ever completed a
 * TLS 1.3 handshake through an accepted cookie, so all six operands sat on
 * one row. This drives both ClientHellos: CH1 with no key share (cookieGood
 * still 0, the server emits the HelloRetryRequest and the cookie) and CH2
 * echoing that cookie back (cookieGood 1). */
static int test_tls13_feat_hrr_cookie_round(int emptyKeyShare)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SEND_HRR_COOKIE) && defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Stateless HelloRetryRequest: the server puts a cookie in the HRR and
     * validates the echo in CH2. NULL/0 lets it generate its own secret. */
    ExpectIntEQ(wolfSSL_send_hrr_cookie(ssl_s, NULL, 0), WOLFSSL_SUCCESS);
    /* emptyKeyShare == 1: CH1 carries an empty key_share list, so the server
     * is already committed to a HelloRetryRequest by the time the cookie
     * block runs (serverState == SERVER_HELLO_RETRY_REQUEST_COMPLETE).
     * emptyKeyShare == 0: CH1 carries a usable key share, so serverState is
     * still NULL_STATE there and it is the cookie alone that forces the
     * retry -- that is the only way :8188's decision comes out true. */
    if (emptyKeyShare)
        ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    ExpectIntEQ(ssl_s->options.sendCookie, 1);
    ExpectIntEQ(ssl_s->options.cookieGood, 1);
    ExpectIntEQ(ssl_s->msgsReceived.got_client_hello, 2);
    ExpectIntEQ(ssl_c->msgsReceived.got_hello_retry_request, 1);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#else
    (void)emptyKeyShare;
#endif
    return EXPECT_RESULT();
}

int test_tls13_feat_hrr_cookie_handshake(void)
{
    return test_tls13_feat_hrr_cookie_round(1);
}

int test_tls13_feat_hrr_cookie_forces_retry(void)
{
    return test_tls13_feat_hrr_cookie_round(0);
}

/* -------------------------------------------------------------------------
 * Encrypted ClientHello: the feature-flag operands next to the ECH pointers.
 * ---------------------------------------------------------------------- */

#if defined(HAVE_ECH) && defined(HAVE_SNI) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)

/* An ECH handshake that also does client authentication and delivers a
 * session ticket, so the ECH guards in DoTls13CertificateRequest() and
 * DoTls13NewSessionTicket() -- which the group's ECH tests never reach,
 * because they neither request a certificate nor read the post-handshake
 * ticket -- are evaluated too.
 *
 * Every one of those guards has the shape
 *
 *   if (ssl->echConfigs != NULL && !ssl->options.disableECH && <third>)
 *
 * and `echEnabled == 0` supplies the row the group never had: the ECH
 * configuration is present (operand 0 true) but ECH is switched off at
 * run time, so operand 1 is false. wolfSSL_SetEchEnable() had never been
 * called from the tls13 group at all. `echEnabled == 1` is the partner row
 * on the same code path. */
static int test_tls13_feat_ech_round(int echEnabled)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    static const char pubName[] = "ech-public-name.com";
    static const char privName[] = "ech-private-name.com";
    byte configs[512];
    word32 configsLen = (word32)sizeof(configs);
    byte readBuf[16];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);

    /* Client authentication, so the server sends a CertificateRequest. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, NULL),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);

    ExpectIntEQ(wolfSSL_CTX_GenerateEchConfig(ctx_s, pubName, 0, 0, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_GetEchConfigs(ctx_s, configs, &configsLen),
        WOLFSSL_SUCCESS);
    /* wolfSSL_SetEchEnable(ssl, 0) frees any ECHConfig already installed, so
     * the switch has to be thrown BEFORE the configs are handed over for the
     * (echConfigs != NULL && disableECH) state to exist at all. That is the
     * state every `echConfigs != NULL && !disableECH && ...` guard in
     * src/tls13.c needs in order to evaluate its second operand false. */
    if (!echEnabled)
        wolfSSL_SetEchEnable(ssl_c, 0);
    ExpectIntEQ(wolfSSL_SetEchConfigs(ssl_c, configs, configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME, privName,
        (word16)XSTRLEN(privName)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_s, WOLFSSL_SNI_HOST_NAME, privName,
        (word16)XSTRLEN(privName)), WOLFSSL_SUCCESS);

    ExpectNotNull(ssl_c->echConfigs);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    ExpectIntEQ(ssl_c->options.disableECH, echEnabled ? 0 : 1);
    ExpectIntEQ(wolfSSL_GetEchStatus(ssl_c), echEnabled ?
        WOLFSSL_ECH_STATUS_ACCEPTED : WOLFSSL_ECH_STATUS_NOT_OFFERED);
    ExpectIntEQ(ssl_c->msgsReceived.got_certificate_request, 1);
    ExpectIntEQ(ssl_s->options.havePeerCert, 1);

    /* Drain the post-handshake NewSessionTicket so DoTls13NewSessionTicket()
     * runs with the ECH state still attached. A build can enable ECH without
     * session tickets (--enable-ech alone leaves "Session Ticket: no"), and
     * then the server sends nothing after the handshake: the read still
     * reports WANT_READ, but there is no ticket to have received. */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
#ifdef HAVE_SESSION_TICKET
    ExpectIntEQ(ssl_c->msgsReceived.got_session_ticket, 1);
#endif

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif /* HAVE_ECH && HAVE_SNI && certs */

int test_tls13_feat_ech_full_handshake(void)
{
#if defined(HAVE_ECH) && defined(HAVE_SNI) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    return test_tls13_feat_ech_round(1);
#else
    return TEST_SKIPPED;
#endif
}

int test_tls13_feat_ech_disabled_client(void)
{
#if defined(HAVE_ECH) && defined(HAVE_SNI) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    return test_tls13_feat_ech_round(0);
#else
    return TEST_SKIPPED;
#endif
}

/* The server side of the same switch:
 *
 *   DoTls13ClientHello():  if (ssl->ctx->echConfigs != NULL &&
 *                              !ssl->options.disableECH)
 *   SendTls13ServerHello(): the same pair
 *
 * The server holds an ECHConfig (operand 0 true) but has ECH switched off,
 * so it never opens the client's outer ClientHello and answers against the
 * public name. RFC 9849 6.1.7 then makes the client abort with
 * ECH_REQUIRED_E once it sees the retry configs. The group's existing
 * ECH-rejection vector corrupts the config's public key instead, which
 * leaves disableECH false on both ends. */
int test_tls13_feat_ech_disabled_server(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECH) && defined(HAVE_SNI) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    static const char pubName[] = "ech-public-name.com";
    static const char privName[] = "ech-private-name.com";
    byte configs[512];
    word32 configsLen = (word32)sizeof(configs);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);

    /* Client authentication as well, so the ECH-rejected client still runs
     * DoTls13CertificateRequest() -- whose ECH guard sends a blank
     * Certificate per RFC 9849 6.1.7 and is only ever true on this path. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, NULL),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER, NULL);

    ExpectIntEQ(wolfSSL_CTX_GenerateEchConfig(ctx_s, pubName, 0, 0, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_GetEchConfigs(ctx_s, configs, &configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SetEchConfigs(ssl_c, configs, configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME, privName,
        (word16)XSTRLEN(privName)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_s, WOLFSSL_SNI_HOST_NAME, pubName,
        (word16)XSTRLEN(pubName)), WOLFSSL_SUCCESS);

    /* Server keeps its ECHConfig but refuses to use it. */
    wolfSSL_SetEchEnable(ssl_s, 0);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(ECH_REQUIRED_E));
    ExpectIntEQ(ssl_s->options.disableECH, 1);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* CheckPreSharedKeys():
 *
 *   if (((modes & (1 << PSK_DHE_KE)) != 0 && !noPskDheKe && ext != NULL)
 *        || usingCertWithExternPsk)
 *
 * Operand 3 is only ever *evaluated* when the left conjunct is false, and
 * every cert_with_extern_psk handshake the group runs has it true (the
 * client offers psk_dhe_ke, the server does not set noPskDheKe and a
 * key_share is present), so the || short-circuits before reaching it.
 * A server that refuses (EC)DHE with a PSK makes the second conjunct false
 * and leaves RFC 9973's own arm to carry the decision. */
int test_tls13_feat_cert_with_extern_psk_psk_ke_server(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && !defined(NO_PSK) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_feat_psk_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_feat_psk_server_cb);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_c, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_s, 1), WOLFSSL_SUCCESS);
    /* The server refuses psk_dhe_ke, so the left conjunct of the decision
     * is false; RFC 9973's own arm then carries it and the handshake still
     * completes with an (EC)DHE key share, as RFC 9973 Section 3 requires. */
    ExpectIntEQ(wolfSSL_no_dhe_psk(ssl_s), 0);

    /* DoTls13ClientHello() clears options.noPskDheKe again once RFC 9973's
     * arm has taken the decision, so only the negotiated result is asserted
     * here. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    ExpectIntEQ(ssl_s->options.certWithExternPsk, 1);
    ExpectIntEQ(ssl_c->options.certWithExternPsk, 1);
    ExpectIntEQ(ssl_c->options.pskNegotiated, 1);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* DoTls13ServerHello(), inside the branch taken when the server chose a PSK:
 *
 *   if (ssl->echConfigs != NULL && !ssl->options.disableECH &&
 *       !ssl->options.echAccepted)
 *       return INVALID_PARAMETER;   ("ECH rejected but server negotiated PSK")
 *
 * needs the two features together -- an ECH client whose ECH was rejected AND
 * a server that answers with a pre_shared_key. The group ran ECH handshakes
 * and PSK handshakes but never one of each, so this decision had never been
 * true and none of its three operands paired. Here the server holds an
 * ECHConfig but has ECH switched off, so it answers the outer ClientHello and
 * negotiates the external PSK; the client must refuse rather than resume
 * against an unauthenticated outer handshake. */
static int test_tls13_feat_ech_psk_round(int mode)
{
    EXPECT_DECLS;
#if defined(HAVE_ECH) && defined(HAVE_SNI) && !defined(NO_PSK) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    static const char pubName[] = "ech-public-name.com";
    static const char privName[] = "ech-private-name.com";
    byte configs[512];
    word32 configsLen = (word32)sizeof(configs);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_feat_psk_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_feat_psk_server_cb);

    ExpectIntEQ(wolfSSL_CTX_GenerateEchConfig(ctx_s, pubName, 0, 0, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_GetEchConfigs(ctx_s, configs, &configsLen),
        WOLFSSL_SUCCESS);
    /* mode 1 disables ECH on the client before the configs are installed, so
     * echConfigs stays non-NULL while disableECH is set; mode 2 leaves the
     * client's ECH on and switches the server's off. (An ECH handshake that
     * is ACCEPTED and also negotiates a PSK is not a case wolfSSL supports --
     * it fails with INVALID_PARAMETER at this very guard -- so the operand
     * that would need it is left open rather than asserted here.) */
    if (mode == 1)
        wolfSSL_SetEchEnable(ssl_c, 0);
    ExpectIntEQ(wolfSSL_SetEchConfigs(ssl_c, configs, configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_c, WOLFSSL_SNI_HOST_NAME, privName,
        (word16)XSTRLEN(privName)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSNI(ssl_s, WOLFSSL_SNI_HOST_NAME,
        mode == 2 ? pubName : privName,
        (word16)XSTRLEN(mode == 2 ? pubName : privName)), WOLFSSL_SUCCESS);

    /* mode 2: server has the ECHConfig but refuses to use it, so ECH is
     * rejected and the decision above comes out true. */
    if (mode == 2)
        wolfSSL_SetEchEnable(ssl_s, 0);

    if (mode == 2) {
        ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
        ExpectIntEQ(ssl_c->options.echAccepted, 0);
    }
    else {
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
        ExpectIntEQ(ssl_c->options.pskNegotiated, 1);
        ExpectIntEQ(ssl_c->options.echAccepted, mode == 0 ? 1 : 0);
        ExpectIntEQ(ssl_c->options.disableECH, mode == 1 ? 1 : 0);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#else
    (void)mode;
#endif
    return EXPECT_RESULT();
}

int test_tls13_feat_ech_psk_disabled_client(void)
{
    return test_tls13_feat_ech_psk_round(1);
}

int test_tls13_feat_ech_rejected_with_psk(void)
{
    return test_tls13_feat_ech_psk_round(2);
}

#else /* !WOLFSSL_TLS13 || !HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES */

int test_tls13_feat_optional_client_cert(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_post_handshake_unexpected_msg(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_psk_ke_no_dhe(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_psk_only_dhe_rejects_psk_ke(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_no_ticket_enc_cb(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_psk_ke_empty_key_share(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_optional_psk_falls_back_to_cert(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_pha_ctx_status_request(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_psk_ke_server_key_share_unused(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_psk_ke_server_no_key_share(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_psk_ke_client_require_psk_resumption(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_hrr_cookie_handshake(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_hrr_cookie_forces_retry(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_cert_with_extern_psk_psk_ke_server(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_ech_full_handshake(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_ech_disabled_client(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_ech_disabled_server(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_ech_rejected_with_psk(void)
{
    return TEST_SKIPPED;
}
int test_tls13_feat_ech_psk_disabled_client(void)
{
    return TEST_SKIPPED;
}

#endif
