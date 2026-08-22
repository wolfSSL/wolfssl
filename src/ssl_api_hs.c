/* ssl_api_hs.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_SSL_API_HS_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_hs.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY

#ifndef NO_TLS
/* Perform the handshake, calling connect or accept as appropriate.
 *
 * The side must already have been established, either by the method used to
 * create the object or with wolfSSL_set_connect_state() or
 * wolfSSL_set_accept_state().
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  WOLFSSL_FATAL_ERROR when ssl is NULL, no side has been established
 *          or the handshake fails.
 * @return  Any other error passed through from wolfSSL_connect() or
 *          wolfSSL_accept(), such as the raw error from their ReinitSSL()
 *          step.
 */
int wolfSSL_negotiate(WOLFSSL* ssl)
{
    int err = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    WOLFSSL_ENTER("wolfSSL_negotiate");

    /* err starts as a failure, which is what a NULL object and an object with
     * no side established both report. */
    if (ssl != NULL) {
        #ifndef NO_WOLFSSL_SERVER
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            #ifdef WOLFSSL_TLS13
            if (IsAtLeastTLSv1_3(ssl->version)) {
                err = wolfSSL_accept_TLSv13(ssl);
            }
            else
            #endif
            {
                err = wolfSSL_accept(ssl);
            }
        }
        #endif

        #ifndef NO_WOLFSSL_CLIENT
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            #ifdef WOLFSSL_TLS13
            if (IsAtLeastTLSv1_3(ssl->version)) {
                err = wolfSSL_connect_TLSv13(ssl);
            }
            else
            #endif
            {
                err = wolfSSL_connect(ssl);
            }
        }
        #endif
    }

    WOLFSSL_LEAVE("wolfSSL_negotiate", err);

    return err;
}
#endif /* !NO_TLS */

#if !defined(NO_TLS) && !(defined(WOLFSSL_NO_TLS12) && \
      defined(NO_OLD_TLS) && defined(WOLFSSL_TLS13)) && \
      (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER))

#ifndef NO_WOLFSSL_CLIENT
/* Send any buffered output and retry a pending alert, for the client.
 *
 * Called once on entry to wolfSSL_connect(), before the state machine runs,
 * so that a message left unsent by a previous call is flushed before the next
 * one is built. The steps inside fall through to each other without coming
 * back here.
 *
 * Whether the state may be advanced is decided before the send, which is what
 * the client did before these two flushes were split out of their callers.
 * The server decides after; see wolfssl_accept_flush().
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  0 when there was nothing to send or everything was sent.
 * @return  WOLFSSL_FATAL_ERROR when sending fails. ssl->error holds the reason.
 */
static int wolfssl_connect_flush(WOLFSSL* ssl)
{
    int ret = 0;
    byte advanceState;

    /* fragOffset is non-zero when sending fragments. On the last fragment,
     * fragOffset is zero again, and the state can be advanced. */
    advanceState = (byte)((ssl->fragOffset == 0) &&
        ((ssl->options.connectState == CONNECT_BEGIN) ||
         (ssl->options.connectState == HELLO_AGAIN) ||
         ((ssl->options.connectState >= FIRST_REPLY_DONE) &&
          (ssl->options.connectState <= FIRST_REPLY_FOURTH))));

    #ifdef WOLFSSL_DTLS13
    /* A DTLS 1.3 ACK or retransmit is not a step of the handshake, so
     * finishing one does not move the state on. */
    if ((ssl->options.dtls) && (IsAtLeastTLSv1_3(ssl->version))) {
        advanceState = (byte)((advanceState) &&
            (!ssl->dtls13SendingAckOrRtx));
    }
    #endif /* WOLFSSL_DTLS13 */

    if ((ssl->buffers.outputBuffer.length > 0)
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* do not send buffered or advance state if last error was an
            async pending operation */
        && (ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E))
    #endif
    ) {
        ret = SendBuffered(ssl);
        if (ret == 0) {
            if ((ssl->fragOffset == 0) && (!ssl->options.buildingMsg)) {
                if (advanceState) {
                    ssl->options.connectState++;
                    WOLFSSL_MSG("connect state: Advanced from last buffered "
                                "fragment send");
                    #ifdef WOLFSSL_ASYNC_IO
                    /* Cleanup async */
                    FreeAsyncCtx(ssl, 0);
                    #endif
                }
            }
            else {
                WOLFSSL_MSG("connect state: Not advanced, more fragments to "
                            "send");
            }
            #ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls) {
                ssl->dtls13SendingAckOrRtx = 0;
            }
            #endif /* WOLFSSL_DTLS13 */
        }
        else {
            ssl->error = ret;
            WOLFSSL_ERROR(ssl->error);
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        ret = RetrySendAlert(ssl);
        if (ret != 0) {
            ssl->error = ret;
            WOLFSSL_ERROR(ssl->error);
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    return ret;
}
#endif /* !NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER
/* Send any buffered output and retry a pending alert, for the server.
 *
 * Called once on entry to wolfSSL_accept(), before the state machine runs, so
 * that a message left unsent by a previous call is flushed before the next
 * one is built. The steps inside fall through to each other without coming
 * back here.
 *
 * Whether the state may be advanced is decided after the send, which is what
 * the server did before these two flushes were split out of their callers.
 * The client decides before; see wolfssl_connect_flush().
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  0 when there was nothing to send or everything was sent.
 * @return  WOLFSSL_FATAL_ERROR when sending fails. ssl->error holds the reason.
 */
static int wolfssl_accept_flush(WOLFSSL* ssl)
{
    int ret = 0;

    if ((ssl->buffers.outputBuffer.length > 0)
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* do not send buffered or advance state if last error was an
            async pending operation */
        && (ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E))
    #endif
    ) {
        ret = SendBuffered(ssl);
        if (ret == 0) {
            /* fragOffset is non-zero when sending fragments. On the last
             * fragment, fragOffset is zero again, and the state can be
             * advanced. */
            if ((ssl->fragOffset == 0) && (!ssl->options.buildingMsg)) {
                /* The accept states listed here are the ones reached after a
                 * message has been sent, so they are the ones that may be
                 * advanced. */
                if ((ssl->options.acceptState == ACCEPT_FIRST_REPLY_DONE) ||
                    (ssl->options.acceptState == SERVER_HELLO_SENT) ||
                    (ssl->options.acceptState == CERT_SENT) ||
                    (ssl->options.acceptState == CERT_STATUS_SENT) ||
                    (ssl->options.acceptState == KEY_EXCHANGE_SENT) ||
                    (ssl->options.acceptState == CERT_REQ_SENT) ||
                    (ssl->options.acceptState == ACCEPT_SECOND_REPLY_DONE) ||
                    (ssl->options.acceptState == TICKET_SENT) ||
                    (ssl->options.acceptState == CHANGE_CIPHER_SENT)) {
                    ssl->options.acceptState++;
                    WOLFSSL_MSG("accept state: Advanced from last buffered "
                                "fragment send");
                    #ifdef WOLFSSL_ASYNC_IO
                    /* Cleanup async */
                    FreeAsyncCtx(ssl, 0);
                    #endif
                }
            }
            else {
                WOLFSSL_MSG("accept state: Not advanced, more fragments to "
                            "send");
            }
            #ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls) {
                ssl->dtls13SendingAckOrRtx = 0;
            }
            #endif /* WOLFSSL_DTLS13 */
        }
        else {
            ssl->error = ret;
            WOLFSSL_ERROR(ssl->error);
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        ret = RetrySendAlert(ssl);
        if (ret != 0) {
            ssl->error = ret;
            WOLFSSL_ERROR(ssl->error);
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    return ret;
}
#endif /* !NO_WOLFSSL_SERVER */

/* Only reached from the server's accept, and from the client's connect when
 * a pre-TLS-1.3 version is built, so it is guarded more tightly than the
 * flush above. */
#if !defined(NO_WOLFSSL_SERVER) || \
    (!defined(NO_WOLFSSL_CLIENT) && \
     (!defined(WOLFSSL_NO_TLS12) || !defined(NO_OLD_TLS)))
/* Finish the handshake.
 *
 * Notifies the application, releases the memory used only during the handshake
 * and discards any asynchronous state.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  0 when the handshake is finished.
 * @return  WOLFSSL_FATAL_ERROR when the handshake done callback asks to stop.
 *          ssl->error holds the value the callback returned.
 */
static int wolfssl_handshake_done(WOLFSSL* ssl)
{
    int ret = 0;

    #ifndef NO_HANDSHAKE_DONE_CB
    if (ssl->hsDoneCb != NULL) {
        int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
        if (cbret < 0) {
            ssl->error = cbret;
            WOLFSSL_MSG("HandShake Done Cb don't continue error");
            /* The caller reports the failure, so don't trace it here too. */
            ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
        }
    }
    #endif /* NO_HANDSHAKE_DONE_CB */

    if (ret == 0) {
        if (!ssl->options.dtls) {
            if (!ssl->options.keepResources) {
                FreeHandshakeResources(ssl);
            }
        }
        #ifdef WOLFSSL_DTLS
        else {
            ssl->options.dtlsHsRetain = 1;
        }
        #endif /* WOLFSSL_DTLS */

        #if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_SECURE_RENEGOTIATION)
        /* This may be necessary in async so that we don't try to
         * renegotiate again */
        if ((ssl->secure_renegotiation != NULL) &&
                (ssl->secure_renegotiation->startScr)) {
            ssl->secure_renegotiation->startScr = 0;
        }
        #endif /* WOLFSSL_ASYNC_CRYPT && HAVE_SECURE_RENEGOTIATION */
        #if defined(WOLFSSL_ASYNC_IO) && !defined(WOLFSSL_ASYNC_CRYPT)
        /* Free the remaining async context if not using it for crypto */
        FreeAsyncCtx(ssl, 1);
        #endif
    }

    return ret;
}
#endif /* !NO_WOLFSSL_SERVER || (!NO_WOLFSSL_CLIENT &&
        * (!WOLFSSL_NO_TLS12 || !NO_OLD_TLS)) */
#endif /* !NO_TLS && !(WOLFSSL_NO_TLS12 && NO_OLD_TLS && WOLFSSL_TLS13) &&
        * (!NO_WOLFSSL_CLIENT || !NO_WOLFSSL_SERVER) */

/* client only parts */
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)

/* Perform the client side of the handshake.
 *
 * Drives the handshake state machine, resuming from wherever the previous call
 * stopped. When non-blocking I/O is in use, the call returns before the
 * handshake completes and must be called again.
 *
 * Please see the note at the top of README if you get an error from connect.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  WOLFSSL_FATAL_ERROR when the object is not a client, a message
 *          cannot be sent or received, or the peer reports an error. Call
 *          wolfSSL_get_error() to determine whether the operation should be
 *          retried.
 * @return  The error from ReinitSSL(), unchanged, when the object cannot be
 *          prepared for a handshake. This is a raw error code rather than
 *          WOLFSSL_FATAL_ERROR, and ssl->error is not set with it.
 *
 * Unlike the rest of this file, the handshake state machine below
 * returns from each step rather than using a single exit. Each step
 * must stop the handshake where it failed, and several of the steps
 * return from inside a receive loop, where a break would only leave
 * the loop.
 */
WOLFSSL_ABI
int wolfSSL_connect(WOLFSSL* ssl)
{
    #if !(defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
      defined(WOLFSSL_TLS13))
    int neededState;
    #endif
    int ret = 0;

    (void)ret;

    #ifdef HAVE_ERRNO_H
    errno = 0;
    #endif

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    #if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EITHER_SIDE)
    if (ssl->options.side == WOLFSSL_NEITHER_END) {
        ssl->error = InitSSL_Side(ssl, WOLFSSL_CLIENT_END);
        if (ssl->error != WOLFSSL_SUCCESS) {
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        ssl->error = 0; /* expected to be zero here */
    }

    #ifdef OPENSSL_EXTRA
    if (ssl->CBIS != NULL) {
        ssl->CBIS(ssl, WOLFSSL_ST_CONNECT, WOLFSSL_SUCCESS);
        ssl->cbmode = WOLFSSL_CB_WRITE;
    }
    #endif
    #endif /* OPENSSL_EXTRA || WOLFSSL_EITHER_SIDE */

    #if defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
        defined(WOLFSSL_TLS13)
    return wolfSSL_connect_TLSv13(ssl);
    #else
    #ifdef WOLFSSL_TLS13
    if (ssl->options.tls1_3) {
        WOLFSSL_MSG("TLS 1.3");
        return wolfSSL_connect_TLSv13(ssl);
    }
    #endif

    WOLFSSL_MSG("TLS 1.2 or lower");
    WOLFSSL_ENTER("wolfSSL_connect");

    /* make sure this wolfSSL object has arrays and rng setup. Protects
     * case where the WOLFSSL object is reused via wolfSSL_clear() */
    if ((ret = ReinitSSL(ssl, ssl->ctx, 0)) != 0) {
        return ret;
    }

    #ifdef WOLFSSL_WOLFSENTRY_HOOKS
    if ((ssl->ConnectFilter != NULL) &&
        (ssl->options.connectState == CONNECT_BEGIN)) {
        wolfSSL_netfilter_decision_t res;
        if ((ssl->ConnectFilter(ssl, ssl->ConnectFilter_arg, &res) ==
             WOLFSSL_SUCCESS) &&
            (res == WOLFSSL_NETFILTER_REJECT)) {
            ssl->error = SOCKET_FILTERED_E;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
    }
    #endif /* WOLFSSL_WOLFSENTRY_HOOKS */

    if (ssl->options.side != WOLFSSL_CLIENT_END) {
        ssl->error = SIDE_ERROR;
        WOLFSSL_ERROR(ssl->error);
        return WOLFSSL_FATAL_ERROR;
    }

    #ifdef WOLFSSL_DTLS
    if (ssl->version.major == DTLS_MAJOR) {
        ssl->options.dtls   = 1;
        ssl->options.tls    = 1;
        ssl->options.tls1_1 = 1;
        ssl->options.dtlsStateful = 1;
    }
    #endif

    ret = wolfssl_connect_flush(ssl);
    if (ret != 0) {
        return ret;
    }

    switch (ssl->options.connectState) {

    case CONNECT_BEGIN :
        /* always send client hello first */
        if ((ssl->error = SendClientHello(ssl)) != 0) {
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        ssl->options.connectState = CLIENT_HELLO_SENT;
        WOLFSSL_MSG("connect state: CLIENT_HELLO_SENT");
        FALL_THROUGH;

    case CLIENT_HELLO_SENT :
        neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                              SERVER_HELLODONE_COMPLETE;
        #ifdef WOLFSSL_DTLS
        /* In DTLS, when resuming, we can go straight to FINISHED,
         * or do a cookie exchange and then skip to FINISHED, assume
         * we need the cookie exchange first. */
        if (IsDtlsNotSctpMode(ssl)) {
            neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
        }
        #endif
        /* get response */
        WOLFSSL_MSG("Server state up to needed state.");
        while (ssl->options.serverState < neededState) {
            WOLFSSL_MSG("Progressing server state...");
            #ifdef WOLFSSL_TLS13
            if (ssl->options.tls1_3) {
                return wolfSSL_connect_TLSv13(ssl);
            }
            #endif
            WOLFSSL_MSG("ProcessReply...");
            if ((ssl->error = ProcessReply(ssl)) < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            /* if resumption failed, reset needed state */
            else if (neededState == SERVER_FINISHED_COMPLETE) {
                if (!ssl->options.resuming) {
                    #ifdef WOLFSSL_DTLS
                    if (IsDtlsNotSctpMode(ssl)) {
                        neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
                    }
                    else
                    #endif
                        neededState = SERVER_HELLODONE_COMPLETE;
                }
            }
            WOLFSSL_MSG("ProcessReply done.");

            #ifdef WOLFSSL_DTLS13
            if ((ssl->options.dtls) && (IsAtLeastTLSv1_3(ssl->version))
                && (ssl->dtls13Rtx.sendAcks == 1)
                && (ssl->options.seenUnifiedHdr)) {
                /* we aren't negotiated the version yet, so we aren't sure
                 * the other end can speak v1.3. On the other side we have
                 * received a unified records, assuming that the
                 * ServerHello got lost, we will send an empty ACK. In case
                 * the server is a DTLS with version less than 1.3, it
                 * should just ignore the message */
                ssl->dtls13Rtx.sendAcks = 0;
                if ((ssl->error = SendDtls13Ack(ssl)) < 0) {
                    if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE)) {
                        ssl->dtls13SendingAckOrRtx = 1;
                    }
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
            #endif /* WOLFSSL_DTLS13 */
        }

        ssl->options.connectState = HELLO_AGAIN;
        WOLFSSL_MSG("connect state: HELLO_AGAIN");
        FALL_THROUGH;

    case HELLO_AGAIN :

        #ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            return wolfSSL_connect_TLSv13(ssl);
        }
        #endif

        #ifdef WOLFSSL_DTLS
        if (ssl->options.serverState ==
                SERVER_HELLOVERIFYREQUEST_COMPLETE) {
            if (IsDtlsNotSctpMode(ssl)) {
                /* re-init hashes, exclude first hello and verify request */
                if ((ssl->error = InitHandshakeHashes(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                if ((ssl->error = SendClientHello(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
        }
        #endif

        ssl->options.connectState = HELLO_AGAIN_REPLY;
        WOLFSSL_MSG("connect state: HELLO_AGAIN_REPLY");
        FALL_THROUGH;

    case HELLO_AGAIN_REPLY :
        #ifdef WOLFSSL_DTLS
        if (IsDtlsNotSctpMode(ssl)) {
            neededState = ssl->options.resuming ?
                SERVER_FINISHED_COMPLETE : SERVER_HELLODONE_COMPLETE;

            /* get response */
            while (ssl->options.serverState < neededState) {
                if ((ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                /* if resumption failed, reset needed state */
                if (neededState == SERVER_FINISHED_COMPLETE) {
                    if (!ssl->options.resuming) {
                        neededState = SERVER_HELLODONE_COMPLETE;
                    }
                }
            }
        }
        #endif

        ssl->options.connectState = FIRST_REPLY_DONE;
        WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");
        FALL_THROUGH;

    case FIRST_REPLY_DONE :
        if (ssl->options.certOnly) {
            return WOLFSSL_SUCCESS;
        }
        #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
        #ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            return wolfSSL_connect_TLSv13(ssl);
        }
        #endif
        if (ssl->options.sendVerify) {
            if ((ssl->error = SendCertificate(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: certificate");
        }

        #endif
        ssl->options.connectState = FIRST_REPLY_FIRST;
        WOLFSSL_MSG("connect state: FIRST_REPLY_FIRST");
        FALL_THROUGH;

    case FIRST_REPLY_FIRST :
        #ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            return wolfSSL_connect_TLSv13(ssl);
        }
        #endif
        if (!ssl->options.resuming) {
            if ((ssl->error = SendClientKeyExchange(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                #ifdef WOLFSSL_EXTRA_ALERTS
                if ((ssl->error == WC_NO_ERR_TRACE(NO_PEER_KEY)) ||
                    (ssl->error == WC_NO_ERR_TRACE(PSK_KEY_ERROR))) {
                    SendAlert(ssl, alert_fatal, handshake_failure);
                }
                #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: client key exchange");
        }

        ssl->options.connectState = FIRST_REPLY_SECOND;
        WOLFSSL_MSG("connect state: FIRST_REPLY_SECOND");
        FALL_THROUGH;

        #if !defined(WOLFSSL_NO_TLS12) || !defined(NO_OLD_TLS)
    case FIRST_REPLY_SECOND :
        /* CLIENT: Fail-safe for Server Authentication. */
        if (!ssl->options.peerAuthGood) {
            WOLFSSL_MSG("Server authentication did not happen");
            ssl->error = NO_PEER_VERIFY;
            return WOLFSSL_FATAL_ERROR;
        }

        #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
        if (ssl->options.sendVerify) {
            if ((ssl->error = SendCertificateVerify(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: certificate verify");
        }
        #endif /* !NO_CERTS && !WOLFSSL_NO_CLIENT_AUTH */
        ssl->options.connectState = FIRST_REPLY_THIRD;
        WOLFSSL_MSG("connect state: FIRST_REPLY_THIRD");
        FALL_THROUGH;

    case FIRST_REPLY_THIRD :
        if ((ssl->error = SendChangeCipher(ssl)) != 0) {
            wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        WOLFSSL_MSG("sent: change cipher spec");
        ssl->options.connectState = FIRST_REPLY_FOURTH;
        WOLFSSL_MSG("connect state: FIRST_REPLY_FOURTH");
        FALL_THROUGH;

    case FIRST_REPLY_FOURTH :
        if ((ssl->error = SendFinished(ssl)) != 0) {
            wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        WOLFSSL_MSG("sent: finished");
        ssl->options.connectState = FINISHED_DONE;
        WOLFSSL_MSG("connect state: FINISHED_DONE");
        FALL_THROUGH;

        #ifdef WOLFSSL_DTLS13
    case WAIT_FINISHED_ACK:
        ssl->options.connectState = FINISHED_DONE;
        FALL_THROUGH;
        #endif /* WOLFSSL_DTLS13 */

    case FINISHED_DONE :
        /* get response */
        while (ssl->options.serverState < SERVER_FINISHED_COMPLETE) {
            if ((ssl->error = ProcessReply(ssl)) < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }

        ssl->options.connectState = SECOND_REPLY_DONE;
        WOLFSSL_MSG("connect state: SECOND_REPLY_DONE");
        FALL_THROUGH;

    case SECOND_REPLY_DONE:
        if (wolfssl_handshake_done(ssl) != 0) {
            return WOLFSSL_FATAL_ERROR;
        }

        ssl->error = 0; /* clear the error */

        WOLFSSL_LEAVE("wolfSSL_connect", WOLFSSL_SUCCESS);
        return WOLFSSL_SUCCESS;
        #endif /* !WOLFSSL_NO_TLS12 || !NO_OLD_TLS */

    default:
        WOLFSSL_MSG("Unknown connect state ERROR");
        return WOLFSSL_FATAL_ERROR; /* unknown connect state */
    }
    #endif /* !WOLFSSL_NO_TLS12 || !NO_OLD_TLS || !WOLFSSL_TLS13 */
}


/* Perform enough of the handshake to get the peer's certificate chain.
 *
 * The handshake stops once the server's certificate has been processed, so no
 * secure connection is established.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the certificate chain was received.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 * @return  WOLFSSL_FATAL_ERROR when the handshake fails.
 */
int wolfSSL_connect_cert(WOLFSSL* ssl)
{
    int ret;

    if (ssl == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        ssl->options.certOnly = 1;
        ret = wolfSSL_connect(ssl);
        ssl->options.certOnly = 0;
    }

    return ret;
}
#endif /* !NO_WOLFSSL_CLIENT && !NO_TLS */
/* end client only parts */

/* server only parts */
#if !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)

/* Only called from the TLS 1.2 and earlier accept path, so it is guarded to
 * match: a TLS 1.3-only build returns before reaching it. */
#if !(defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
      defined(WOLFSSL_TLS13))
/* Check the server has the credentials needed to perform a handshake.
 *
 * A certificate and private key are required unless an anonymous or PSK cipher
 * suite may be chosen, the object is multicast, a certificate setup callback
 * will supply them, or the private key is held externally.
 *
 * Checked on every call in case wolfSSL_set_accept_state() was used after the
 * object was initialized.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  0 when the credentials can be used.
 * @return  WOLFSSL_FATAL_ERROR when the certificate or private key is missing.
 */
static int wolfssl_accept_check_creds(WOLFSSL* ssl)
{
    int ret = 0;
    #ifndef NO_CERTS
    word16 havePSK = 0;
    word16 haveAnon = 0;
    word16 haveMcast = 0;

    #ifndef NO_PSK
    havePSK = ssl->options.havePSK;
    #endif

    #ifdef HAVE_ANON
    haveAnon = ssl->options.useAnon;
    #endif

    #ifdef WOLFSSL_MULTICAST
    haveMcast = ssl->options.haveMcast;
    #endif

    if ((!havePSK) && (!haveAnon) && (!haveMcast)) {
        #ifdef WOLFSSL_CERT_SETUP_CB
        if (ssl->ctx->certSetupCb != NULL) {
            WOLFSSL_MSG("CertSetupCb set. server cert and "
                        "key not checked");
        }
        else
        #endif
        {
            if ((ssl->buffers.certificate == NULL) ||
                    (ssl->buffers.certificate->buffer == NULL)) {
                WOLFSSL_MSG("accept error: server cert required");
                ssl->error = NO_PRIVATE_KEY;
                WOLFSSL_ERROR(ssl->error);
                ret = WOLFSSL_FATAL_ERROR;
            }
            else if ((ssl->buffers.key == NULL) ||
                    (ssl->buffers.key->buffer == NULL)) {
                /* allow no private key if using existing key */
                #ifdef WOLF_PRIVATE_KEY_ID
                if ((ssl->devId != INVALID_DEVID)
                #ifdef HAVE_PK_CALLBACKS
                    || (wolfSSL_CTX_IsPrivatePkSet(ssl->ctx))
                #endif
                ) {
                    WOLFSSL_MSG("Allowing no server private key "
                                "(external)");
                }
                else
                #endif
                {
                    WOLFSSL_MSG("accept error: server key required");
                    ssl->error = NO_PRIVATE_KEY;
                    WOLFSSL_ERROR(ssl->error);
                    ret = WOLFSSL_FATAL_ERROR;
                }
            }
        }
    }
    #else
    (void)ssl;
    #endif /* !NO_CERTS */

    return ret;
}
#endif /* !(WOLFSSL_NO_TLS12 && NO_OLD_TLS && WOLFSSL_TLS13) */

/* Accept a connection from a client.
 *
 * Performs the server side of the handshake, resuming from where it last
 * stopped when non-blocking. Dispatches to the TLS 1.3 or DTLS handshake
 * when negotiated.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  WOLFSSL_FATAL_ERROR when ssl is NULL or the handshake fails.
 *          Call wolfSSL_get_error() for the reason. WOLFSSL_ERROR_WANT_READ
 *          and WOLFSSL_ERROR_WANT_WRITE mean call again.
 * @return  The error from ReinitSSL(), unchanged, when the object cannot be
 *          prepared for a handshake. This is a raw error code rather than
 *          WOLFSSL_FATAL_ERROR, and ssl->error is not set with it.
 *
 * Unlike the rest of this file, the handshake state machine below
 * returns from each step rather than using a single exit. Each step
 * must stop the handshake where it failed, and several of the steps
 * return from inside a receive loop, where a break would only leave
 * the loop.
 */
WOLFSSL_ABI
int wolfSSL_accept(WOLFSSL* ssl)
{
    int ret = 0;

    (void)ret;

    if (ssl == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    #if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EITHER_SIDE)
    if (ssl->options.side == WOLFSSL_NEITHER_END) {
        WOLFSSL_MSG("Setting WOLFSSL_SSL to be server side");
        ssl->error = InitSSL_Side(ssl, WOLFSSL_SERVER_END);
        if (ssl->error != WOLFSSL_SUCCESS) {
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        ssl->error = 0; /* expected to be zero here */
    }
    #endif /* OPENSSL_EXTRA || WOLFSSL_EITHER_SIDE */

    #if defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
        defined(WOLFSSL_TLS13)
    return wolfSSL_accept_TLSv13(ssl);
    #else
    #ifdef WOLFSSL_TLS13
    if (ssl->options.tls1_3) {
        return wolfSSL_accept_TLSv13(ssl);
    }
    #endif
    WOLFSSL_ENTER("wolfSSL_accept");

    /* make sure this wolfSSL object has arrays and rng setup. Protects
     * case where the WOLFSSL object is reused via wolfSSL_clear() */
    if ((ret = ReinitSSL(ssl, ssl->ctx, 0)) != 0) {
        return ret;
    }

    #ifdef WOLFSSL_WOLFSENTRY_HOOKS
    if ((ssl->AcceptFilter != NULL) &&
        ((ssl->options.acceptState == ACCEPT_BEGIN)
    #ifdef HAVE_SECURE_RENEGOTIATION
         || (ssl->options.acceptState == ACCEPT_BEGIN_RENEG)
    #endif
            ))
    {
        wolfSSL_netfilter_decision_t res;
        if ((ssl->AcceptFilter(ssl, ssl->AcceptFilter_arg, &res) ==
             WOLFSSL_SUCCESS) &&
            (res == WOLFSSL_NETFILTER_REJECT)) {
            ssl->error = SOCKET_FILTERED_E;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
    }
    #endif /* WOLFSSL_WOLFSENTRY_HOOKS */

    #ifdef HAVE_ERRNO_H
    errno = 0;
    #endif

    if (ssl->options.side != WOLFSSL_SERVER_END) {
        ssl->error = SIDE_ERROR;
        WOLFSSL_ERROR(ssl->error);
        return WOLFSSL_FATAL_ERROR;
    }

    ret = wolfssl_accept_check_creds(ssl);
    if (ret != 0) {
        return ret;
    }

    #ifdef WOLFSSL_DTLS
    if (ssl->version.major == DTLS_MAJOR) {
        ssl->options.dtls   = 1;
        ssl->options.tls    = 1;
        ssl->options.tls1_1 = 1;
        if ((!IsDtlsNotSctpMode(ssl)) || (IsSCR(ssl))) {
            ssl->options.dtlsStateful = 1;
        }
    }
    #endif

    ret = wolfssl_accept_flush(ssl);
    if (ret != 0) {
        return ret;
    }

    switch (ssl->options.acceptState) {

    case ACCEPT_BEGIN :
        #ifdef HAVE_SECURE_RENEGOTIATION
    case ACCEPT_BEGIN_RENEG:
        #endif
        /* get response */
        while (ssl->options.clientState < CLIENT_HELLO_COMPLETE) {
            if ((ssl->error = ProcessReply(ssl)) < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
        #ifdef WOLFSSL_TLS13
        ssl->options.acceptState = ACCEPT_CLIENT_HELLO_DONE;
        WOLFSSL_MSG("accept state ACCEPT_CLIENT_HELLO_DONE");
        FALL_THROUGH;

    case ACCEPT_CLIENT_HELLO_DONE :
        if (ssl->options.tls1_3) {
            return wolfSSL_accept_TLSv13(ssl);
        }
        #endif

        ssl->options.acceptState = ACCEPT_FIRST_REPLY_DONE;
        WOLFSSL_MSG("accept state ACCEPT_FIRST_REPLY_DONE");
        FALL_THROUGH;

    case ACCEPT_FIRST_REPLY_DONE :
        if (ssl->options.returnOnGoodCh) {
            /* Higher level in stack wants us to return. Simulate a
             * WANT_WRITE to accomplish this. */
            ssl->error = WANT_WRITE;
            return WOLFSSL_FATAL_ERROR;
        }
        if ((ssl->error = SendServerHello(ssl)) != 0) {
            wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        ssl->options.acceptState = SERVER_HELLO_SENT;
        WOLFSSL_MSG("accept state SERVER_HELLO_SENT");
        FALL_THROUGH;

    case SERVER_HELLO_SENT :
        #ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            return wolfSSL_accept_TLSv13(ssl);
        }
        #endif
        #ifndef NO_CERTS
        if (!ssl->options.resuming) {
            if ((ssl->error = SendCertificate(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
        #endif
        ssl->options.acceptState = CERT_SENT;
        WOLFSSL_MSG("accept state CERT_SENT");
        FALL_THROUGH;

    case CERT_SENT :
        #ifndef NO_CERTS
        if (!ssl->options.resuming) {
            if ((ssl->error = SendCertificateStatus(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
        #endif
        ssl->options.acceptState = CERT_STATUS_SENT;
        WOLFSSL_MSG("accept state CERT_STATUS_SENT");
        FALL_THROUGH;

    case CERT_STATUS_SENT :
        #ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            return wolfSSL_accept_TLSv13(ssl);
        }
        #endif
        if (!ssl->options.resuming) {
            if ((ssl->error = SendServerKeyExchange(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
        ssl->options.acceptState = KEY_EXCHANGE_SENT;
        WOLFSSL_MSG("accept state KEY_EXCHANGE_SENT");
        FALL_THROUGH;

    case KEY_EXCHANGE_SENT :
        #ifndef NO_CERTS
        if (!ssl->options.resuming) {
            if (ssl->options.verifyPeer) {
                if ((ssl->error = SendCertificateRequest(ssl)) != 0) {
                    wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
            else {
                /* SERVER: Peer auth good if not verifying client. */
                ssl->options.peerAuthGood = 1;
            }
        }
        #endif
        ssl->options.acceptState = CERT_REQ_SENT;
        WOLFSSL_MSG("accept state CERT_REQ_SENT");
        FALL_THROUGH;

    case CERT_REQ_SENT :
        if (!ssl->options.resuming) {
            if ((ssl->error = SendServerHelloDone(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
        ssl->options.acceptState = SERVER_HELLO_DONE;
        WOLFSSL_MSG("accept state SERVER_HELLO_DONE");
        FALL_THROUGH;

    case SERVER_HELLO_DONE :
        if (!ssl->options.resuming) {
            while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE) {
                if ((ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
        }
        ssl->options.acceptState = ACCEPT_SECOND_REPLY_DONE;
        WOLFSSL_MSG("accept state  ACCEPT_SECOND_REPLY_DONE");
        FALL_THROUGH;

    case ACCEPT_SECOND_REPLY_DONE :
        #ifndef NO_CERTS
        /* SERVER: When not resuming and verifying peer but no certificate
         * received and not failing when not received then peer auth good.
         */
        if ((!ssl->options.resuming) && (ssl->options.verifyPeer) &&
                (!ssl->options.havePeerCert) &&
                (!ssl->options.failNoCert)) {
            ssl->options.peerAuthGood = 1;
        }
        #endif /* !NO_CERTS  */
        #ifdef WOLFSSL_NO_CLIENT_AUTH
        if (!ssl->options.resuming) {
            ssl->options.peerAuthGood = 1;
        }
        #endif

        #ifdef HAVE_SESSION_TICKET
        if ((ssl->options.createTicket) &&
                (!ssl->options.noTicketTls12)) {
            if ((ssl->error = SendTicket(ssl)) != 0) {
                wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
                WOLFSSL_MSG("Thought we need ticket but failed");
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
        #endif /* HAVE_SESSION_TICKET */
        ssl->options.acceptState = TICKET_SENT;
        WOLFSSL_MSG("accept state  TICKET_SENT");
        FALL_THROUGH;

    case TICKET_SENT:
        /* SERVER: Fail-safe for CLient Authentication. */
        if (!ssl->options.peerAuthGood) {
            WOLFSSL_MSG("Client authentication did not happen");
            return WOLFSSL_FATAL_ERROR;
        }

        if ((ssl->error = SendChangeCipher(ssl)) != 0) {
            wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        ssl->options.acceptState = CHANGE_CIPHER_SENT;
        WOLFSSL_MSG("accept state  CHANGE_CIPHER_SENT");
        FALL_THROUGH;

    case CHANGE_CIPHER_SENT :
        if ((ssl->error = SendFinished(ssl)) != 0) {
            wolfssl_local_MaybeCheckAlertOnErr(ssl, ssl->error);
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }

        ssl->options.acceptState = ACCEPT_FINISHED_DONE;
        WOLFSSL_MSG("accept state ACCEPT_FINISHED_DONE");
        FALL_THROUGH;

    case ACCEPT_FINISHED_DONE :
        if (ssl->options.resuming) {
            while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE) {
                if ((ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
        }
        ssl->options.acceptState = ACCEPT_THIRD_REPLY_DONE;
        WOLFSSL_MSG("accept state ACCEPT_THIRD_REPLY_DONE");
        FALL_THROUGH;

    case ACCEPT_THIRD_REPLY_DONE :
        if (wolfssl_handshake_done(ssl) != 0) {
            return WOLFSSL_FATAL_ERROR;
        }

        #if defined(WOLFSSL_SESSION_EXPORT) && defined(WOLFSSL_DTLS)
        if (ssl->dtls_export) {
            if ((ssl->error = wolfSSL_send_session(ssl)) != 0) {
                WOLFSSL_MSG("Export DTLS session error");
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
        #endif
        ssl->error = 0; /* clear the error */

        WOLFSSL_LEAVE("wolfSSL_accept", WOLFSSL_SUCCESS);
        return WOLFSSL_SUCCESS;

    default:
        WOLFSSL_MSG("Unknown accept state ERROR");
        return WOLFSSL_FATAL_ERROR;
    }
    #endif /* !WOLFSSL_NO_TLS12 */
}

#endif /* !NO_WOLFSSL_SERVER && !NO_TLS */
/* end server only parts */

#ifndef NO_HANDSHAKE_DONE_CB

/* Set the callback to call when the handshake completes.
 *
 * @param [in, out] ssl       SSL/TLS object.
 * @param [in]      cb        Callback to call. NULL to clear.
 * @param [in]      user_ctx  Context to pass to the callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_SetHsDoneCb");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ssl->hsDoneCb  = cb;
        ssl->hsDoneCtx = user_ctx;
    }

    return ret;
}

#endif /* NO_HANDSHAKE_DONE_CB */

#ifdef WOLFSSL_CALLBACKS

typedef struct itimerval Itimerval;

/* don't keep calling simple functions while setting up timer and signals
   if no inlining these are the next best */

#define SubtractTimes(a, b, c)                  \
    do {                                        \
        (c).tv_sec  = (a).tv_sec - (b).tv_sec;  \
        (c).tv_usec = (a).tv_usec - (b).tv_usec;\
        if ((c).tv_usec < 0) {                  \
            (c).tv_sec--;                       \
            (c).tv_usec += 1000000;             \
        }                                       \
    } while (0)

#define CmpTimes(a, b, cmp)                     \
    (((a).tv_sec  ==  (b).tv_sec) ?             \
        ((a).tv_usec cmp (b).tv_usec) :         \
        ((a).tv_sec  cmp (b).tv_sec))           \


/* Signal handler that does nothing.
 *
 * Installed for SIGALRM so that the timer interrupts a blocking call rather
 * than terminating the process.
 *
 * @param [in] signo  Signal number. Unused.
 */
static void myHandler(int signo)
{
    (void)signo;
    return;
}


/* Replace any running timer with one that expires after the timeout.
 *
 * When a timer is already running and would expire first, the timeout is
 * shortened to match it so the existing timer is not delayed.
 *
 * @param [in, out] timeout     Maximum time to take. Shortened when a timer
 *                              already running would expire sooner.
 * @param [out]     oldTimeout  Timer that was running, to be restored later.
 * @param [out]     timerWasOn  Set to 1 when a timer was already running, 0
 *                              when not.
 * @param [out]     oact        Signal handler that was replaced.
 * @return  0 on success.
 * @return  SETITIMER_ERROR when the timer cannot be read or set.
 * @return  SIGACT_ERROR when the signal handler cannot be installed.
 */
static int wolfssl_ex_wrapper_set_timer(WOLFSSL_TIMEVAL* timeout,
    Itimerval* oldTimeout, int* timerWasOn, struct sigaction* oact)
{
    int ret = 0;
    Itimerval myTimeout;
    struct sigaction act;

    *timerWasOn = 0;

    /* use setitimer to simulate getitimer, init 0 myTimeout */
    myTimeout.it_interval.tv_sec  = 0;
    myTimeout.it_interval.tv_usec = 0;
    myTimeout.it_value.tv_sec     = 0;
    myTimeout.it_value.tv_usec    = 0;
    if (setitimer(ITIMER_REAL, &myTimeout, oldTimeout) < 0) {
        ret = SETITIMER_ERROR;
    }

    if (ret == 0) {
        if ((oldTimeout->it_value.tv_sec) ||
                (oldTimeout->it_value.tv_usec)) {
            *timerWasOn = 1;

            /* is old timer going to expire before ours */
            if (CmpTimes(oldTimeout->it_value, *timeout, <)) {
                timeout->tv_sec  = oldTimeout->it_value.tv_sec;
                timeout->tv_usec = oldTimeout->it_value.tv_usec;
            }
        }
        myTimeout.it_value.tv_sec  = timeout->tv_sec;
        myTimeout.it_value.tv_usec = timeout->tv_usec;

        /* set up signal handler, don't restart socket send/recv */
        act.sa_handler = myHandler;
        sigemptyset(&act.sa_mask);
        act.sa_flags = 0;
        #ifdef SA_INTERRUPT
        act.sa_flags |= SA_INTERRUPT;
        #endif
        if (sigaction(SIGALRM, &act, oact) < 0) {
            ret = SIGACT_ERROR;
        }
    }

    if (ret == 0) {
        if (setitimer(ITIMER_REAL, &myTimeout, 0) < 0) {
            ret = SETITIMER_ERROR;
        }
    }

    return ret;
}

/* Restore the timer and signal handler that were replaced.
 *
 * A restored timer is adjusted for the time that has since elapsed.
 *
 * @param [in]      startTime   When the handshake started.
 * @param [in]      endTime     When the handshake finished. Only read when
 *                              oldTimerOn is set.
 * @param [in, out] oldTimeout  Timer to restore.
 * @param [in]      oldTimerOn  Whether a timer was already running.
 * @param [in]      oact        Signal handler to restore.
 * @return  0 on success.
 * @return  SIGACT_ERROR when the signal handler cannot be restored.
 * @return  SETITIMER_ERROR when the timer cannot be restored.
 */
static int wolfssl_ex_wrapper_reset_timer(const WOLFSSL_TIMEVAL* startTime,
    const WOLFSSL_TIMEVAL* endTime, Itimerval* oldTimeout, int oldTimerOn,
    struct sigaction* oact)
{
    int ret = 0;
    WOLFSSL_TIMEVAL totalTime;

    if (oldTimerOn) {
        SubtractTimes(*endTime, *startTime, totalTime);
        /* adjust old timer for elapsed time */
        if (CmpTimes(totalTime, oldTimeout->it_value, <)) {
            SubtractTimes(oldTimeout->it_value, totalTime,
                          oldTimeout->it_value);
        }
        else {
            /* reset value to interval, may be off */
            oldTimeout->it_value.tv_sec = oldTimeout->it_interval.tv_sec;
            oldTimeout->it_value.tv_usec = oldTimeout->it_interval.tv_usec;
        }
    /* keep iter the same whether there or not */
    }

    /* restore old handler */
    if (sigaction(SIGALRM, oact, 0) < 0) {
        ret = SIGACT_ERROR;    /* more pressing error, stomp */
    }
    else {
        /* use old settings which may turn off (expired or not there) */
        if (setitimer(ITIMER_REAL, oldTimeout, 0) < 0) {
            ret = SETITIMER_ERROR;
        }
    }

    return ret;
}

/* Perform a handshake with monitoring callbacks and a timeout.
 *
 * An interval timer is used to abort the handshake when it takes longer
 * than the timeout. Any existing timer is restored afterwards.
 *
 * @param [in, out] ssl      SSL/TLS object.
 * @param [in]      hsCb     Handshake information callback. May be NULL.
 * @param [in]      toCb     Timeout callback. May be NULL.
 * @param [in]      timeout  Maximum time to take. Zero for no timeout.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  WOLFSSL_FATAL_ERROR when ssl is NULL, the timeout value is bad,
 *          setting the timer fails or the handshake fails.
 */
static int wolfSSL_ex_wrapper(WOLFSSL* ssl, HandShakeCallBack hsCb,
                             TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout)
{
    int       ret        = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    int       oldTimerOn = 0;   /* was timer already on */
    WOLFSSL_TIMEVAL startTime;
    /* Only filled in, and only read, when a timer was already running. Zeroed
     * so the helper is never handed uninitialized storage. */
    WOLFSSL_TIMEVAL endTime;
    Itimerval oldTimeout; /* if old timer adjust from total time to reset */
    struct sigaction oact;

#define ERR_OUT(x) \
    do { ssl->hsInfoOn = 0; ssl->toInfoOn = 0; return x; } while (0)

    XMEMSET(&endTime, 0, sizeof(endTime));

    if (hsCb) {
        ssl->hsInfoOn = 1;
        InitHandShakeInfo(&ssl->handShakeInfo, ssl);
    }
    if (toCb) {
        /* Kept out of ret so the fatal default survives to the dispatch
         * below, which leaves ret alone when no side has been established. */
        int sret;

        ssl->toInfoOn = 1;
        InitTimeoutInfo(&ssl->timeoutInfo);

        if (gettimeofday(&startTime, 0) < 0) {
            ERR_OUT(GETTIME_ERROR);
        }

        sret = wolfssl_ex_wrapper_set_timer(&timeout, &oldTimeout,
            &oldTimerOn, &oact);
        if (sret != 0) {
            ERR_OUT(sret);
        }
    }

    /* do main work */
    #ifndef NO_WOLFSSL_CLIENT
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ret = wolfSSL_connect(ssl);
    }
    #endif
    #ifndef NO_WOLFSSL_SERVER
    if (ssl->options.side == WOLFSSL_SERVER_END) {
        ret = wolfSSL_accept(ssl);
    }
    #endif

    /* do callbacks */
    if (toCb) {
        int tret;

        if (oldTimerOn) {
            if (gettimeofday(&endTime, 0) < 0) {
                ERR_OUT(SYSLIB_FAILED_E);
            }
        }

        tret = wolfssl_ex_wrapper_reset_timer(&startTime, &endTime,
            &oldTimeout, oldTimerOn, &oact);
        if (tret != 0) {
            ret = tret;    /* more pressing error, stomp */
        }

        /* if we had a timeout call callback */
        if (ssl->timeoutInfo.timeoutName[0]) {
            ssl->timeoutInfo.timeoutValue.tv_sec  = timeout.tv_sec;
            ssl->timeoutInfo.timeoutValue.tv_usec = timeout.tv_usec;
            (toCb)(&ssl->timeoutInfo);
        }
        ssl->toInfoOn = 0;
    }

    /* clean up buffers allocated by AddPacketInfo */
    FreeTimeoutInfo(&ssl->timeoutInfo, ssl->heap);

    if (hsCb) {
        FinishHandShakeInfo(&ssl->handShakeInfo);
        (hsCb)(&ssl->handShakeInfo);
        ssl->hsInfoOn = 0;
    }
    return ret;
}


#ifndef NO_WOLFSSL_CLIENT

/* Connect to a server with monitoring callbacks and a timeout.
 *
 * @param [in, out] ssl      SSL/TLS object.
 * @param [in]      hsCb     Handshake information callback. May be NULL.
 * @param [in]      toCb     Timeout callback. May be NULL.
 * @param [in]      timeout  Maximum time to take. Zero for no timeout.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  WOLFSSL_FATAL_ERROR when the handshake fails or times out.
 */
int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                      TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout)
{
    WOLFSSL_ENTER("wolfSSL_connect_ex");
    return wolfSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
}

#endif


#ifndef NO_WOLFSSL_SERVER

/* Accept a connection from a client with monitoring callbacks and a
 * timeout.
 *
 * @param [in, out] ssl      SSL/TLS object.
 * @param [in]      hsCb     Handshake information callback. May be NULL.
 * @param [in]      toCb     Timeout callback. May be NULL.
 * @param [in]      timeout  Maximum time to take. Zero for no timeout.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  WOLFSSL_FATAL_ERROR when the handshake fails or times out.
 */
int wolfSSL_accept_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                     TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout)
{
    WOLFSSL_ENTER("wolfSSL_accept_ex");
    return wolfSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
}

#endif

/* Local to this file, which is compiled into ssl.c, so do not leave them
 * defined for the files included after it. */
#undef ERR_OUT
#undef SubtractTimes
#undef CmpTimes

#endif /* WOLFSSL_CALLBACKS */


#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EXTRA) || \
    defined(WOLFSSL_WPAS_SMALL)

/* Set the SSL/TLS object to be a server.
 *
 * Resets the handshake state and cipher suites. Must be called before the
 * handshake starts.
 *
 * @param [in, out] ssl  SSL/TLS object.
 */
void wolfSSL_set_accept_state(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_set_accept_state");

    if (ssl == NULL) {
        return;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        #ifdef HAVE_ECC
        WC_DECLARE_VAR(key, ecc_key, 1, 0);
        word32 idx = 0;

        #ifdef WOLFSSL_SMALL_STACK
        key = (ecc_key*)XMALLOC(sizeof(ecc_key), ssl->heap,
                                DYNAMIC_TYPE_ECC);
        if (key == NULL) {
            WOLFSSL_MSG("Error allocating memory for ecc_key");
        }
        #endif
        if ((ssl->options.haveStaticECC) && (ssl->buffers.key != NULL)) {
            if (wc_ecc_init(key) >= 0) {
                DerBuffer* privKey = ssl->buffers.key;
                #ifdef WOLFSSL_BLIND_PRIVATE_KEY
                DerBuffer* unblinded = NULL;

                /* Only a key that has a mask is masked. Without one - after
                 * wolfSSL_use_PrivateKey_Id(), for example - the buffer is
                 * stored as-is and is used directly, so that this build
                 * behaves the same as one without key blinding. */
                if (ssl->buffers.keyMask != NULL) {
                    /* The stored key is masked, so work on a plain copy. */
                    unblinded = wolfssl_priv_der_unblind(ssl->buffers.key,
                        ssl->buffers.keyMask);
                    privKey = unblinded;
                }
                #endif

                if (privKey == NULL) {
                    /* Only an allocation failure gets here, and that says
                     * nothing about the key. Leave the capabilities as they
                     * are rather than withdraw them, which is also what a
                     * failure to allocate the ecc_key above does - that skips
                     * the check entirely. */
                    WOLFSSL_MSG("Unable to unmask private key");
                }
                /* Not an EC key, so withdraw the ECC capabilities. */
                else if (wc_EccPrivateKeyDecode(privKey->buffer, &idx, key,
                        privKey->length) != 0) {
                    ssl->options.haveECDSAsig = 0;
                    ssl->options.haveECC = 0;
                    ssl->options.haveStaticECC = 0;
                }

                #ifdef WOLFSSL_BLIND_PRIVATE_KEY
                /* Only the plain copy is disposed of - the stored key is
                 * not ours to free. */
                wolfssl_priv_der_unblind_free(unblinded);
                #endif
                wc_ecc_free(key);
            }
        }
        WC_FREE_VAR_EX(key, ssl->heap, DYNAMIC_TYPE_ECC);
        #endif

        #ifndef NO_DH
        if ((!ssl->options.haveDH) && (ssl->ctx->haveDH)) {
            /* Nothing to return the failure through, so leave the object
             * without DH rather than claim parameters it does not have. */
            if (CopySSL_CTX_DhParams(ssl, ssl->ctx) == 0) {
                ssl->options.haveDH = 1;
            }
            else {
                WOLFSSL_MSG("Unable to copy DH parameters from context");
            }
        }
        #endif
    }

    if (InitSSL_Side(ssl, WOLFSSL_SERVER_END) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error initializing server side");
    }
}

#endif /* OPENSSL_EXTRA || WOLFSSL_EXTRA || WOLFSSL_WPAS_SMALL */

/* Determine whether the handshake has completed.
 *
 * Works for both TLS and DTLS.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when the handshake has completed.
 * @return  0 when the handshake has not completed or ssl is NULL.
 */
int wolfSSL_is_init_finished(const WOLFSSL* ssl)
{
    int ret = 0;

    if (ssl != NULL) {
        #if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_CLIENT)
        if ((ssl->options.side == WOLFSSL_CLIENT_END) && (ssl->options.dtls)
                && (IsAtLeastTLSv1_3(ssl->version))) {
            ret = (ssl->options.serverState == SERVER_FINISHED_ACKED);
        }
        else
        #endif /* WOLFSSL_DTLS13 && !NO_WOLFSSL_CLIENT */
        {
            /* Can't use ssl->options.connectState and ssl->options.acceptState
             * because they differ in meaning for TLS <=1.2 and 1.3 */
            if (ssl->options.handShakeState == HANDSHAKE_DONE) {
                ret = 1;
            }
        }
    }

    return ret;
}

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Set the SSL/TLS object to be a client.
 *
 * Resets the handshake state and cipher suites. Must be called before the
 * handshake starts.
 *
 * @param [in, out] ssl  SSL/TLS object.
 */
void wolfSSL_set_connect_state(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_set_connect_state");
    if (ssl == NULL) {
        WOLFSSL_MSG("WOLFSSL struct pointer passed in was null");
        return;
    }

    #ifndef NO_DH
    /* client creates its own DH parameters on handshake */
    if ((ssl->buffers.serverDH_P.buffer != NULL) &&
            (ssl->buffers.weOwnDH)) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
            DYNAMIC_TYPE_PUBLIC_KEY);
    }
    ssl->buffers.serverDH_P.buffer = NULL;
    if ((ssl->buffers.serverDH_G.buffer != NULL) &&
            (ssl->buffers.weOwnDH)) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
            DYNAMIC_TYPE_PUBLIC_KEY);
    }
    ssl->buffers.serverDH_G.buffer = NULL;
    #endif

    if (InitSSL_Side(ssl, WOLFSSL_CLIENT_END) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error initializing client side");
    }
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA

#define STATE_STRINGS_PROTO(s) \
    {                          \
        {"SSLv3 " s,           \
         "SSLv3 " s,           \
         "SSLv3 " s},          \
        {"TLSv1 " s,           \
         "TLSv1 " s,           \
         "TLSv1 " s},          \
        {"TLSv1_1 " s,         \
         "TLSv1_1 " s,         \
         "TLSv1_1 " s},        \
        {"TLSv1_2 " s,         \
         "TLSv1_2 " s,         \
         "TLSv1_2 " s},        \
        {"TLSv1_3 " s,         \
         "TLSv1_3 " s,         \
         "TLSv1_3 " s},        \
        {"DTLSv1 " s,          \
         "DTLSv1 " s,          \
         "DTLSv1 " s},         \
        {"DTLSv1_2 " s,        \
         "DTLSv1_2 " s,        \
         "DTLSv1_2 " s},       \
        {"DTLSv1_3 " s,        \
         "DTLSv1_3 " s,        \
         "DTLSv1_3 " s},       \
    }

#define STATE_STRINGS_PROTO_RW(s) \
    {                             \
        {"SSLv3 read " s,         \
         "SSLv3 write " s,        \
         "SSLv3 " s},             \
        {"TLSv1 read " s,         \
         "TLSv1 write " s,        \
         "TLSv1 " s},             \
        {"TLSv1_1 read " s,       \
         "TLSv1_1 write " s,      \
         "TLSv1_1 " s},           \
        {"TLSv1_2 read " s,       \
         "TLSv1_2 write " s,      \
         "TLSv1_2 " s},           \
        {"TLSv1_3 read " s,       \
         "TLSv1_3 write " s,      \
         "TLSv1_3 " s},           \
        {"DTLSv1 read " s,        \
         "DTLSv1 write " s,       \
         "DTLSv1 " s},            \
        {"DTLSv1_2 read " s,      \
         "DTLSv1_2 write " s,     \
         "DTLSv1_2 " s},          \
        {"DTLSv1_3 read " s,      \
         "DTLSv1_3 write " s,     \
         "DTLSv1_3 " s},          \
    }

/* Indices into OUTPUT_STR in wolfSSL_state_string_long().
 *
 * These are shared by that function and its helpers below, so they cannot be
 * local to any one of them. This file is compiled as part of ssl.c, which
 * makes them visible to every other file included into it, hence the
 * WOLFSSL_SS_ ("state string") prefix on the enumerators, whose names would
 * otherwise be far too generic to sit in that namespace. The enum tags
 * follow the naming of those in wolfssl/ssl.h.
 */
enum StateStringProtocol {
    WOLFSSL_SS_SSL_V3 = 0,
    WOLFSSL_SS_TLS_V1,
    WOLFSSL_SS_TLS_V1_1,
    WOLFSSL_SS_TLS_V1_2,
    WOLFSSL_SS_TLS_V1_3,
    WOLFSSL_SS_DTLS_V1,
    WOLFSSL_SS_DTLS_V1_2,
    WOLFSSL_SS_DTLS_V1_3,
    /* Number of protocols above - the second dimension of OUTPUT_STR in
     * wolfSSL_state_string_long(). Keep last of the indices. */
    WOLFSSL_SS_PROTO_CNT,
    WOLFSSL_SS_UNKNOWN = 100
};

enum StateStringIoMode {
    WOLFSSL_SS_READ = 0,
    WOLFSSL_SS_WRITE,
    WOLFSSL_SS_NEITHER,
    /* Number of modes above - the third dimension of OUTPUT_STR. */
    WOLFSSL_SS_IO_CNT
};

enum StateStringState {
    WOLFSSL_SS_NULL_STATE = 0,
    WOLFSSL_SS_SERVER_HELLOREQUEST,
    WOLFSSL_SS_SERVER_HELLOVERIFY,
    WOLFSSL_SS_SERVER_HELLORETRYREQUEST,
    WOLFSSL_SS_SERVER_HELLO,
    WOLFSSL_SS_SERVER_CERTIFICATESTATUS,
    WOLFSSL_SS_SERVER_ENCRYPTEDEXTENSIONS,
    WOLFSSL_SS_SERVER_SESSIONTICKET,
    WOLFSSL_SS_SERVER_CERTREQUEST,
    WOLFSSL_SS_SERVER_CERT,
    WOLFSSL_SS_SERVER_KEYEXCHANGE,
    WOLFSSL_SS_SERVER_HELLODONE,
    WOLFSSL_SS_SERVER_CHANGECIPHERSPEC,
    WOLFSSL_SS_SERVER_FINISHED,
    WOLFSSL_SS_SERVER_KEYUPDATE,
    WOLFSSL_SS_CLIENT_HELLO,
    WOLFSSL_SS_CLIENT_KEYEXCHANGE,
    WOLFSSL_SS_CLIENT_CERT,
    WOLFSSL_SS_CLIENT_CHANGECIPHERSPEC,
    WOLFSSL_SS_CLIENT_CERTVERIFY,
    WOLFSSL_SS_CLIENT_ENDOFEARLYDATA,
    WOLFSSL_SS_CLIENT_FINISHED,
    WOLFSSL_SS_CLIENT_KEYUPDATE,
    WOLFSSL_SS_HANDSHAKE_DONE,
    /* Number of states above - the first dimension of OUTPUT_STR. Each state
     * indexes a row of that table, so the two must stay the same size. */
    WOLFSSL_SS_STATE_CNT
};

/* Determine which direction the last handshake message travelled.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SS_READ when the last message was read.
 * @return  WOLFSSL_SS_WRITE when the last message was written.
 * @return  WOLFSSL_SS_NEITHER when no message has been read or written.
 */
static int wolfssl_state_string_io_mode(const WOLFSSL* ssl)
{
    int cbmode = WOLFSSL_SS_NEITHER;

    if (ssl->cbmode == WOLFSSL_CB_MODE_WRITE) {
        cbmode = WOLFSSL_SS_WRITE;
    }
    else if (ssl->cbmode == WOLFSSL_CB_MODE_READ) {
        cbmode = WOLFSSL_SS_READ;
    }

    return cbmode;
}

/* Determine the protocol version in use.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Index of the protocol version in the state string table.
 * @return  WOLFSSL_SS_UNKNOWN when the version is not recognized.
 */
static int wolfssl_state_string_protocol(const WOLFSSL* ssl)
{
    int protocol = WOLFSSL_SS_UNKNOWN;

    switch (ssl->version.major) {
    case SSLv3_MAJOR:
        switch (ssl->version.minor) {
        case SSLv3_MINOR:
            protocol = WOLFSSL_SS_SSL_V3;
            break;
        case TLSv1_MINOR:
            protocol = WOLFSSL_SS_TLS_V1;
            break;
        case TLSv1_1_MINOR:
            protocol = WOLFSSL_SS_TLS_V1_1;
            break;
        case TLSv1_2_MINOR:
            protocol = WOLFSSL_SS_TLS_V1_2;
            break;
        case TLSv1_3_MINOR:
            protocol = WOLFSSL_SS_TLS_V1_3;
            break;
        default:
            protocol = WOLFSSL_SS_UNKNOWN;
        }
        break;
    case DTLS_MAJOR:
        switch (ssl->version.minor) {
        case DTLS_MINOR:
            protocol = WOLFSSL_SS_DTLS_V1;
            break;
        case DTLSv1_2_MINOR:
            protocol = WOLFSSL_SS_DTLS_V1_2;
            break;
        case DTLSv1_3_MINOR:
            protocol = WOLFSSL_SS_DTLS_V1_3;
            break;
        default:
            protocol = WOLFSSL_SS_UNKNOWN;
        }
        break;
    default:
        protocol = WOLFSSL_SS_UNKNOWN;
    }

    return protocol;
}

/* Map the type of the last message read to a state string table index.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Index of the message in the state string table.
 * @return  WOLFSSL_SS_NULL_STATE when the message type is not recognized.
 */
static int wolfssl_state_string_recv_state(const WOLFSSL* ssl)
{
    int state = ssl->cbtype;

    switch (state) {
    case hello_request:
        state = WOLFSSL_SS_SERVER_HELLOREQUEST;
        break;
    case client_hello:
        state = WOLFSSL_SS_CLIENT_HELLO;
        break;
    case server_hello:
        state = WOLFSSL_SS_SERVER_HELLO;
        break;
    case hello_verify_request:
        state = WOLFSSL_SS_SERVER_HELLOVERIFY;
        break;
    case session_ticket:
        state = WOLFSSL_SS_SERVER_SESSIONTICKET;
        break;
    case end_of_early_data:
        state = WOLFSSL_SS_CLIENT_ENDOFEARLYDATA;
        break;
    case hello_retry_request:
        state = WOLFSSL_SS_SERVER_HELLORETRYREQUEST;
        break;
    case encrypted_extensions:
        state = WOLFSSL_SS_SERVER_ENCRYPTEDEXTENSIONS;
        break;
    case certificate:
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            state = WOLFSSL_SS_CLIENT_CERT;
        }
        else if (ssl->options.side == WOLFSSL_CLIENT_END) {
            state = WOLFSSL_SS_SERVER_CERT;
        }
        else {
            WOLFSSL_MSG("Unknown State");
            state = WOLFSSL_SS_NULL_STATE;
        }
        break;
    case server_key_exchange:
        state = WOLFSSL_SS_SERVER_KEYEXCHANGE;
        break;
    case certificate_request:
        state = WOLFSSL_SS_SERVER_CERTREQUEST;
        break;
    case server_hello_done:
        state = WOLFSSL_SS_SERVER_HELLODONE;
        break;
    case certificate_verify:
        state = WOLFSSL_SS_CLIENT_CERTVERIFY;
        break;
    case client_key_exchange:
        state = WOLFSSL_SS_CLIENT_KEYEXCHANGE;
        break;
    case finished:
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            state = WOLFSSL_SS_CLIENT_FINISHED;
        }
        else if (ssl->options.side == WOLFSSL_CLIENT_END) {
            state = WOLFSSL_SS_SERVER_FINISHED;
        }
        else {
            WOLFSSL_MSG("Unknown State");
            state = WOLFSSL_SS_NULL_STATE;
        }
        break;
    case certificate_status:
        state = WOLFSSL_SS_SERVER_CERTIFICATESTATUS;
        break;
    case key_update:
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            state = WOLFSSL_SS_CLIENT_KEYUPDATE;
        }
        else if (ssl->options.side == WOLFSSL_CLIENT_END) {
            state = WOLFSSL_SS_SERVER_KEYUPDATE;
        }
        else {
            WOLFSSL_MSG("Unknown State");
            state = WOLFSSL_SS_NULL_STATE;
        }
        break;
    case change_cipher_hs:
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            state = WOLFSSL_SS_CLIENT_CHANGECIPHERSPEC;
        }
        else if (ssl->options.side == WOLFSSL_CLIENT_END) {
            state = WOLFSSL_SS_SERVER_CHANGECIPHERSPEC;
        }
        else {
            WOLFSSL_MSG("Unknown State");
            state = WOLFSSL_SS_NULL_STATE;
        }
        break;
    default:
        WOLFSSL_MSG("Unknown State");
        state = WOLFSSL_SS_NULL_STATE;
    }

    return state;
}

/* Map the handshake state reached while sending to a state string table index.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Index of the message in the state string table.
 * @return  WOLFSSL_SS_NULL_STATE when the state is not recognized.
 */
static int wolfssl_state_string_send_state(const WOLFSSL* ssl)
{
    int state;

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        state = ssl->options.serverState;
    }
    else {
        state = ssl->options.clientState;
    }

    switch (state) {
    case SERVER_HELLOVERIFYREQUEST_COMPLETE:
        state = WOLFSSL_SS_SERVER_HELLOVERIFY;
        break;
    case SERVER_HELLO_RETRY_REQUEST_COMPLETE:
        state = WOLFSSL_SS_SERVER_HELLORETRYREQUEST;
        break;
    case SERVER_HELLO_COMPLETE:
        state = WOLFSSL_SS_SERVER_HELLO;
        break;
    case SERVER_ENCRYPTED_EXTENSIONS_COMPLETE:
        state = WOLFSSL_SS_SERVER_ENCRYPTEDEXTENSIONS;
        break;
    case SERVER_CERT_COMPLETE:
        state = WOLFSSL_SS_SERVER_CERT;
        break;
    case SERVER_KEYEXCHANGE_COMPLETE:
        state = WOLFSSL_SS_SERVER_KEYEXCHANGE;
        break;
    case SERVER_HELLODONE_COMPLETE:
        state = WOLFSSL_SS_SERVER_HELLODONE;
        break;
    case SERVER_CHANGECIPHERSPEC_COMPLETE:
        state = WOLFSSL_SS_SERVER_CHANGECIPHERSPEC;
        break;
    case SERVER_FINISHED_COMPLETE:
        state = WOLFSSL_SS_SERVER_FINISHED;
        break;
    case CLIENT_HELLO_RETRY:
    case CLIENT_HELLO_COMPLETE:
        state = WOLFSSL_SS_CLIENT_HELLO;
        break;
    case CLIENT_KEYEXCHANGE_COMPLETE:
        state = WOLFSSL_SS_CLIENT_KEYEXCHANGE;
        break;
    case CLIENT_CHANGECIPHERSPEC_COMPLETE:
        state = WOLFSSL_SS_CLIENT_CHANGECIPHERSPEC;
        break;
    case CLIENT_FINISHED_COMPLETE:
        state = WOLFSSL_SS_CLIENT_FINISHED;
        break;
    case HANDSHAKE_DONE:
        state = WOLFSSL_SS_HANDSHAKE_DONE;
        break;
    default:
        WOLFSSL_MSG("Unknown State");
        state = WOLFSSL_SS_NULL_STATE;
    }

    return state;
}

/* Get a human readable description of the current handshake state.
 *
 * The description names the protocol version, whether the last message was
 * read or written, and the message itself.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  A human readable string describing the state.
 * @return  An empty string when the protocol version is not one this can
 *          name, so the result is always safe to print.
 * @return  NULL when ssl is NULL. That is the only case that returns NULL.
 */
const char* wolfSSL_state_string_long(const WOLFSSL* ssl)
{
    static const char* OUTPUT_STR[24][8][3] = {
        STATE_STRINGS_PROTO("Initialization"),
        STATE_STRINGS_PROTO_RW("Server Hello Request"),
        STATE_STRINGS_PROTO_RW("Server Hello Verify Request"),
        STATE_STRINGS_PROTO_RW("Server Hello Retry Request"),
        STATE_STRINGS_PROTO_RW("Server Hello"),
        STATE_STRINGS_PROTO_RW("Server Certificate Status"),
        STATE_STRINGS_PROTO_RW("Server Encrypted Extensions"),
        STATE_STRINGS_PROTO_RW("Server Session Ticket"),
        STATE_STRINGS_PROTO_RW("Server Certificate Request"),
        STATE_STRINGS_PROTO_RW("Server Cert"),
        STATE_STRINGS_PROTO_RW("Server Key Exchange"),
        STATE_STRINGS_PROTO_RW("Server Hello Done"),
        STATE_STRINGS_PROTO_RW("Server Change CipherSpec"),
        STATE_STRINGS_PROTO_RW("Server Finished"),
        STATE_STRINGS_PROTO_RW("server Key Update"),
        STATE_STRINGS_PROTO_RW("Client Hello"),
        STATE_STRINGS_PROTO_RW("Client Key Exchange"),
        STATE_STRINGS_PROTO_RW("Client Cert"),
        STATE_STRINGS_PROTO_RW("Client Change CipherSpec"),
        STATE_STRINGS_PROTO_RW("Client Certificate Verify"),
        STATE_STRINGS_PROTO_RW("Client End Of Early Data"),
        STATE_STRINGS_PROTO_RW("Client Finished"),
        STATE_STRINGS_PROTO_RW("Client Key Update"),
        STATE_STRINGS_PROTO("Handshake Done"),
    };
    int protocol;
    int cbmode;
    int state;
    const char* ret = NULL;

    /* The three indices below come from enumerations declared at the top of
     * this file, well away from the table they index. Adding an entry to one
     * of them without adding the matching entry here is a build error rather
     * than a read off the end of the table. */
    wc_static_assert(XELEM_CNT(OUTPUT_STR) == WOLFSSL_SS_STATE_CNT);
    wc_static_assert(XELEM_CNT(OUTPUT_STR[0]) == WOLFSSL_SS_PROTO_CNT);
    wc_static_assert(XELEM_CNT(OUTPUT_STR[0][0]) == WOLFSSL_SS_IO_CNT);

    WOLFSSL_ENTER("wolfSSL_state_string_long");

    if (ssl == NULL) {
        WOLFSSL_MSG("Null argument passed in");
    }
    else {
        cbmode = wolfssl_state_string_io_mode(ssl);
        protocol = wolfssl_state_string_protocol(ssl);

        if (ssl->cbmode == WOLFSSL_CB_MODE_READ) {
            state = wolfssl_state_string_recv_state(ssl);
        }
        else {
            state = wolfssl_state_string_send_state(ssl);
        }

        if (protocol == WOLFSSL_SS_UNKNOWN) {
            WOLFSSL_MSG("Unknown protocol");
            ret = "";
        }
        else {
            ret = OUTPUT_STR[state][protocol][cbmode];
        }
    }

    return ret;
}

/* Only used by the table above, and this file is compiled into ssl.c,
 * so do not leave them defined for the files included after it. */
#undef STATE_STRINGS_PROTO
#undef STATE_STRINGS_PROTO_RW
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

#ifndef NO_TLS
/* Perform the handshake.
 *
 * Calls the connect or accept for the side of the object.
 *
 * @param [in, out] s  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  WOLFSSL_FATAL_ERROR when the side is not set or the handshake
 *          fails.
 */
int wolfSSL_SSL_do_handshake_internal(WOLFSSL *s)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SSL_do_handshake_internal");

    if (s == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    else if (s->options.side == WOLFSSL_CLIENT_END) {
        #ifndef NO_WOLFSSL_CLIENT
        ret = wolfSSL_connect(s);
        #else
        WOLFSSL_MSG("Client not compiled in");
        ret = WOLFSSL_FAILURE;
        #endif
    }
    else {
        #ifndef NO_WOLFSSL_SERVER
        ret = wolfSSL_accept(s);
        #else
        WOLFSSL_MSG("Server not compiled in");
        ret = WOLFSSL_FAILURE;
        #endif
    }

    return ret;
}

/* Perform the handshake.
 *
 * @param [in, out] s  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the handshake completes.
 * @return  WOLFSSL_FATAL_ERROR when the handshake fails. Call
 *          wolfSSL_get_error() for the reason.
 */
int wolfSSL_SSL_do_handshake(WOLFSSL *s)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SSL_do_handshake");

    #ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(s)) {
        ret = wolfSSL_quic_do_handshake(s);
    }
    else
    #endif
    {
        ret = wolfSSL_SSL_do_handshake_internal(s);
    }

    return ret;
}
#endif /* !NO_TLS */

/* Determine whether the handshake has not completed.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when the handshake has not completed.
 * @return  0 when the handshake has completed.
 */
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
int wolfSSL_SSL_in_init(const WOLFSSL *ssl)
#else
int wolfSSL_SSL_in_init(WOLFSSL *ssl)
#endif
{
    WOLFSSL_ENTER("wolfSSL_SSL_in_init");

    return !wolfSSL_is_init_finished(ssl);
}

/* Determine whether the handshake has not started.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when the handshake has not started.
 * @return  0 when the handshake has started or ssl is NULL.
 */
int wolfSSL_SSL_in_before(const WOLFSSL *ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SSL_in_before");

    if (ssl != NULL) {
        ret = (ssl->options.handShakeState == NULL_STATE);
    }
    else {
        ret = WOLFSSL_FAILURE;
    }

    return ret;
}

/* Determine whether the handshake is in progress.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when the handshake has started but not completed.
 * @return  0 otherwise or when ssl is NULL.
 */
int wolfSSL_SSL_in_connect_init(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SSL_in_connect_init");

    if (ssl != NULL) {
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            ret = (ssl->options.connectState > CONNECT_BEGIN) &&
                  (ssl->options.connectState < SECOND_REPLY_DONE);
        }
        else {
            ret = (ssl->options.acceptState > ACCEPT_BEGIN) &&
                  (ssl->options.acceptState < ACCEPT_THIRD_REPLY_DONE);
        }
    }
    else {
        ret = WOLFSSL_FAILURE;
    }

    return ret;
}

#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */


#ifndef NO_CERTS
#ifdef  HAVE_PK_CALLBACKS

/* Set the premaster secret generation callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void  wolfSSL_CTX_SetGenPreMasterCb(WOLFSSL_CTX* ctx, CallbackGenPreMaster cb)
{
    if (ctx != NULL) {
        ctx->GenPreMasterCb = cb;
    }
}
/* Set the context to pass to the premaster secret generation callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void  wolfSSL_SetGenPreMasterCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->GenPreMasterCtx = ctx;
    }
}
/* Get the context passed to the premaster secret generation callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetGenPreMasterCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->GenPreMasterCtx;
    }

    return ret;
}

/* Set the master secret generation callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void  wolfSSL_CTX_SetGenMasterSecretCb(WOLFSSL_CTX* ctx,
    CallbackGenMasterSecret cb)
{
    if (ctx != NULL) {
        ctx->GenMasterCb = cb;
    }
}
/* Set the context to pass to the master secret generation callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void  wolfSSL_SetGenMasterSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->GenMasterCtx = ctx;
    }
}
/* Get the context passed to the master secret generation callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetGenMasterSecretCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->GenMasterCtx;
    }

    return ret;
}

/* Set the extended master secret generation callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void  wolfSSL_CTX_SetGenExtMasterSecretCb(WOLFSSL_CTX* ctx,
    CallbackGenExtMasterSecret cb)
{
    if (ctx != NULL) {
        ctx->GenExtMasterCb = cb;
    }
}
/* Set the context to pass to the extended master secret generation callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void  wolfSSL_SetGenExtMasterSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->GenExtMasterCtx = ctx;
    }
}
/* Get the context passed to the extended master secret generation callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetGenExtMasterSecretCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->GenExtMasterCtx;
    }

    return ret;
}


/* Set the session key generation callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void  wolfSSL_CTX_SetGenSessionKeyCb(WOLFSSL_CTX* ctx, CallbackGenSessionKey cb)
{
    if (ctx != NULL) {
        ctx->GenSessionKeyCb = cb;
    }
}
/* Set the context to pass to the session key generation callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void  wolfSSL_SetGenSessionKeyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->GenSessionKeyCtx = ctx;
    }
}
/* Get the context passed to the session key generation callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetGenSessionKeyCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->GenSessionKeyCtx;
    }

    return ret;
}

/* Set the encryption key setting callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void  wolfSSL_CTX_SetEncryptKeysCb(WOLFSSL_CTX* ctx, CallbackEncryptKeys cb)
{
    if (ctx != NULL) {
        ctx->EncryptKeysCb = cb;
    }
}
/* Set the context to pass to the encryption key setting callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void  wolfSSL_SetEncryptKeysCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->EncryptKeysCtx = ctx;
    }
}
/* Get the context passed to the encryption key setting callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetEncryptKeysCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->EncryptKeysCtx;
    }

    return ret;
}

/* Set the TLS Finished message building callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void  wolfSSL_CTX_SetTlsFinishedCb(WOLFSSL_CTX* ctx, CallbackTlsFinished cb)
{
    if (ctx != NULL) {
        ctx->TlsFinishedCb = cb;
    }
}
/* Set the context to pass to the TLS Finished message building callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void  wolfSSL_SetTlsFinishedCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->TlsFinishedCtx = ctx;
    }
}
/* Get the context passed to the TLS Finished message building callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetTlsFinishedCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->TlsFinishedCtx;
    }

    return ret;
}
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
/* Set the MAC verification callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void  wolfSSL_CTX_SetVerifyMacCb(WOLFSSL_CTX* ctx, CallbackVerifyMac cb)
{
    if (ctx != NULL) {
        ctx->VerifyMacCb = cb;
    }
}

/* Set the context to pass to the MAC verification callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void  wolfSSL_SetVerifyMacCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->VerifyMacCtx = ctx;
    }
}
/* Get the context passed to the MAC verification callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetVerifyMacCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->VerifyMacCtx;
    }

    return ret;
}
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */

/* Set the HKDF expand label callback.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void wolfSSL_CTX_SetHKDFExpandLabelCb(WOLFSSL_CTX* ctx,
                                      CallbackHKDFExpandLabel cb)
{
    if (ctx != NULL) {
        ctx->HKDFExpandLabelCb = cb;
    }
}
#ifdef WOLFSSL_PUBLIC_ASN
/* Set the callback to call to process the peer's certificate.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void wolfSSL_CTX_SetProcessPeerCertCb(WOLFSSL_CTX* ctx,
                                        CallbackProcessPeerCert cb)
{
    if (ctx != NULL) {
        ctx->ProcessPeerCertCb = cb;
    }
}
#endif /* WOLFSSL_PUBLIC_ASN */
/* Set the callback to call to process the server's signature and key
 * exchange.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void wolfSSL_CTX_SetProcessServerSigKexCb(WOLFSSL_CTX* ctx,
                                       CallbackProcessServerSigKex cb)
{
    if (ctx != NULL) {
        ctx->ProcessServerSigKexCb = cb;
    }
}
/* Set the callback to call to encrypt and decrypt TLS records.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void wolfSSL_CTX_SetPerformTlsRecordProcessingCb(WOLFSSL_CTX* ctx,
                                          CallbackPerformTlsRecordProcessing cb)
{
    if (ctx != NULL) {
        ctx->PerformTlsRecordProcessingCb = cb;
    }
}
#endif /* HAVE_PK_CALLBACKS */
#endif /* NO_CERTS */

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_HKDF)

/* Set the callback to call to perform the HKDF extract operation.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void wolfSSL_CTX_SetHKDFExtractCb(WOLFSSL_CTX* ctx, CallbackHKDFExtract cb)
{
    if (ctx != NULL) {
        ctx->HkdfExtractCb = cb;
    }
}

/* Set the context to pass to the HKDF extract callback.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  Context to pass to the callback.
 */
void wolfSSL_SetHKDFExtractCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl != NULL) {
        ssl->HkdfExtractCtx = ctx;
    }
}

/* Get the context passed to the HKDF extract callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Context on success.
 * @return  NULL when ssl is NULL.
 */
void* wolfSSL_GetHKDFExtractCtx(WOLFSSL* ssl)
{
    void* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->HkdfExtractCtx;
    }

    return ret;
}
#endif /* HAVE_PK_CALLBACKS && HAVE_HKDF */

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_SSL_API_HS_INCLUDED */
