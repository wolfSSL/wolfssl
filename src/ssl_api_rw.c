/* ssl_api_rw.c
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

#if !defined(WOLFSSL_SSL_API_RW_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_rw.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY

#ifndef NO_TLS

#if defined(HAVE_WRITE_DUP) && defined(WOLFSSL_TLS13)
/* Take over the TLS 1.3 work delegated by the read side.
 *
 * The read side of a write duplicate cannot send, so it records what needs to
 * be sent in the write duplicate object. Move that state across to the SSL
 * object of the write side.
 *
 * Must be called with ssl->dupWrite->dupMutex held.
 *
 * @param [in, out] ssl  SSL/TLS object of the write side.
 * @return  0 on success.
 * @return  Negative on error.
 */
static int wolfssl_write_dup_take_tls13_work(WOLFSSL* ssl)
{
    int ret = 0;

    if (IsAtLeastTLSv1_3(ssl->version)) {
        /* TLS 1.3: if the read side received a KeyUpdate(update_requested)
         * it cannot respond; send the response from here. */
        ssl->keys.keyUpdateRespond |= ssl->dupWrite->keyUpdateRespond;
        ssl->dupWrite->keyUpdateRespond = 0;
        #ifdef WOLFSSL_POST_HANDSHAKE_AUTH
        ssl->postHandshakeAuthPending |=
                ssl->dupWrite->postHandshakeAuthPending;
        ssl->dupWrite->postHandshakeAuthPending = 0;
        if (ssl->postHandshakeAuthPending) {
            /* Take ownership of the delegated auth state. */
            CertReqCtx** tail = &ssl->dupWrite->postHandshakeCertReqCtx;
            while (*tail != NULL) {
                tail = &(*tail)->next;
            }
            *tail = ssl->certReqCtx;
            ssl->certReqCtx = ssl->dupWrite->postHandshakeCertReqCtx;
            ssl->dupWrite->postHandshakeCertReqCtx = NULL;
            FreeHandshakeHashes(ssl);
            ssl->hsHashes = ssl->dupWrite->postHandshakeHashState;
            ssl->dupWrite->postHandshakeHashState = NULL;
            ssl->options.sendVerify = ssl->dupWrite->postHandshakeSendVerify;
            ssl->options.sigAlgo = ssl->dupWrite->postHandshakeSigAlgo;
            ssl->options.hashAlgo = ssl->dupWrite->postHandshakeHashAlgo;
            #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG)
            ssl->options.peerSha1CertOk =
                (ssl->dupWrite->postHandshakeSha1CertOk != 0) ? 1 : 0;
            #endif
        }
        #endif /* WOLFSSL_POST_HANDSHAKE_AUTH */
        #ifdef WOLFSSL_DTLS13
        if (ssl->options.dtls) {
            /* Schedule key update to be sent. */
            if (ssl->keys.keyUpdateRespond) {
                ssl->dtls13DoKeyUpdate = 1;
            }

            /* Copy over ACKs */
            ssl->dtls13Rtx.sendAcks |= ssl->dupWrite->sendAcks;
            if (ssl->dupWrite->sendAcks) {
                /* Insert each record number so the
                 * ACK message is properly ordered. */
                struct Dtls13RecordNumber* rn;
                for (rn = ssl->dupWrite->sendAckList; rn != NULL;
                     rn = rn->next) {
                    ret = Dtls13RtxAddAck(ssl, rn->epoch, rn->seq);
                    if (ret != 0) {
                        break;
                    }
                }
                /* Clear only on success so no ACKs get dropped */
                if (ret == 0) {
                    rn = ssl->dupWrite->sendAckList;
                    ssl->dupWrite->sendAckList = NULL;
                    ssl->dupWrite->sendAcks = 0;
                    while (rn != NULL) {
                        struct Dtls13RecordNumber* next = rn->next;
                        XFREE(rn, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
                        rn = next;
                    }
                }
            }

            /* Remove KeyUpdate record from RTX list. */
            if (ssl->dupWrite->keyUpdateAcked) {
                Dtls13RtxRemoveRecord(ssl, ssl->dupWrite->keyUpdateEpoch,
                        ssl->dupWrite->keyUpdateSeq);
            }
            /* Store if KeyUpdate was ACKed. */
            ssl->dtls13KeyUpdateAcked |= ssl->dupWrite->keyUpdateAcked;
            ssl->dupWrite->keyUpdateAcked = 0;
        }
        #endif /* WOLFSSL_DTLS13 */
    }

    return ret;
}

/* Perform the TLS 1.3 work delegated by the read side.
 *
 * Must be called after ssl->dupWrite->dupMutex has been released, as the work
 * performed here sends records.
 *
 * @param [in, out] ssl  SSL/TLS object of the write side.
 * @return  0 on success.
 * @return  BAD_MUTEX_E when the write duplicate could not be locked. Returned
 *          as-is by the caller, so ssl->error is not set for it.
 * @return  WOLFSSL_FATAL_ERROR on error. Call wolfSSL_get_error() for the
 *          reason.
 */
static int wolfssl_write_dup_do_tls13_work(WOLFSSL* ssl)
{
    int ret = 0;

    if (IsAtLeastTLSv1_3(ssl->version)) {
        #ifdef WOLFSSL_POST_HANDSHAKE_AUTH
        /* Read side received a CertificateRequest but couldn't write;
         * send Certificate+CertificateVerify+Finished from the write
         * side. */
        if (ssl->postHandshakeAuthPending) {
            /* reset handshake states */
            ssl->postHandshakeAuthPending = 0;
            ssl->options.clientState = CLIENT_HELLO_COMPLETE;
            ssl->options.connectState = FIRST_REPLY_DONE;
            ssl->options.handShakeState = CLIENT_HELLO_COMPLETE;
            ssl->options.processReply = 0; /* doProcessInit */
            if (wolfSSL_connect_TLSv13(ssl) != WOLFSSL_SUCCESS) {
                if ((ssl->error != WC_NO_ERR_TRACE(WANT_WRITE)) &&
                        (ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E))) {
                    WOLFSSL_MSG("Post-handshake auth send failed");
                    ssl->error = POST_HAND_AUTH_ERROR;
                }
                ret = WOLFSSL_FATAL_ERROR;
            }
            /* PHA response fully sent: publish the write side's updated
             * transcript to the read side for the next PHA round. */
            else if ((ssl->hsHashes != NULL) && (ssl->dupWrite != NULL)) {
                if (wc_LockMutex(&ssl->dupWrite->dupMutex) != 0) {
                    ret = BAD_MUTEX_E;
                }
                else {
                    int syncRet = InitHandshakeHashesAndCopy(ssl,
                        ssl->hsHashes,
                        &ssl->dupWrite->postHandshakeSyncedHashState);
                    if (syncRet != 0) {
                        /* On failure the copy may have left a partially
                         * initialized transcript. The read side only checks
                         * for non-NULL before consuming it, so drop it here to
                         * avoid hashing onto a corrupt transcript, and surface
                         * the error to the caller. */
                        Free_HS_Hashes(
                            ssl->dupWrite->postHandshakeSyncedHashState,
                            ssl->heap);
                        ssl->dupWrite->postHandshakeSyncedHashState = NULL;
                    }
                    wc_UnLockMutex(&ssl->dupWrite->dupMutex);
                    if (syncRet != 0) {
                        ssl->error = syncRet;
                        ret = WOLFSSL_FATAL_ERROR;
                    }
                }
            }
        }
        #endif /* WOLFSSL_POST_HANDSHAKE_AUTH */

        if (ret == 0) {
            #ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls) {
                if (ssl->dtls13KeyUpdateAcked) {
                    ret = DoDtls13KeyUpdateAck(ssl);
                }
                ssl->dtls13KeyUpdateAcked = 0;
                if (ret == 0) {
                    ret = Dtls13DoScheduledWork(ssl);
                }
            }
            else
            #endif /* WOLFSSL_DTLS13 */
            {
                /* keyUpdateRespond is cleared in SendTls13KeyUpdate. */
                if (ssl->keys.keyUpdateRespond) {
                    /* RFC 9846 Section 4.7.3: a sender that would exceed the
                     * key update limit "MUST NOT send its own KeyUpdate ...
                     * and SHOULD instead ignore the 'update_requested' flag".
                     * The read side delegated this response without seeing the
                     * cap - it never sends KeyUpdates, so its count is not the
                     * one that matters - so the check belongs here, on the
                     * side that actually sends and owns the counter. */
                    if (Tls13KeyUpdateLimitReached(ssl)) {
                        WOLFSSL_MSG("Key update limit reached; ignoring "
                                    "delegated update_requested");
                        ssl->keys.keyUpdateRespond = 0;
                    }
                    else {
                        ret = Tls13UpdateKeys(ssl);
                    }
                }
            }

            if (ret != 0) {
                ssl->error = ret;
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
    }

    return ret;
}
#endif /* HAVE_WRITE_DUP && WOLFSSL_TLS13 */

#ifdef HAVE_WRITE_DUP
/* Settle the write duplicate state before application data is sent.
 *
 * Takes over the work the read side delegated and surfaces any error it
 * recorded. Both are held under ssl->dupWrite->dupMutex, so they are collected
 * with the lock held and acted on once it has been released.
 *
 * @param [in, out] ssl  SSL/TLS object of the write side.
 * @return  0 when the write may proceed.
 * @return  BAD_MUTEX_E when the write duplicate could not be locked.
 * @return  WOLFSSL_FATAL_ERROR on error. Call wolfSSL_get_error() for the
 *          reason.
 */
static int wolfssl_write_dup_prepare(WOLFSSL* ssl)
{
    int ret = 0;

    /* Lock ssl->dupWrite to gather what needs to be done. */
    if (wc_LockMutex(&ssl->dupWrite->dupMutex) != 0) {
        ret = BAD_MUTEX_E;
    }
    else {
        int dupErr = ssl->dupWrite->dupErr;   /* local copy */

        #ifdef WOLFSSL_TLS13
        ret = wolfssl_write_dup_take_tls13_work(ssl);
        #endif /* WOLFSSL_TLS13 */
        wc_UnLockMutex(&ssl->dupWrite->dupMutex);

        /* An error from the read side takes precedence over one hit while
         * taking over its work. */
        if (dupErr != 0) {
            WOLFSSL_MSG("Write dup error from other side");
            ret = dupErr;
        }

        if (ret != 0) {
            ssl->error = ret;
            ret = WOLFSSL_FATAL_ERROR;
        }
        #ifdef WOLFSSL_TLS13
        else {
            /* Do the work delegated by the read side. */
            ret = wolfssl_write_dup_do_tls13_work(ssl);
        }
        #endif /* WOLFSSL_TLS13 */
    }

    return ret;
}
#endif /* HAVE_WRITE_DUP */

/* Write application data to the peer.
 *
 * Performs the handshake when it has not completed. When a write duplicate is
 * in use, work delegated by the read side, such as sending a key update, is
 * done here first.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      data  Application data to write.
 * @param [in]      sz    Length of data in bytes.
 * @return  Number of bytes written on success.
 * @return  BAD_FUNC_ARG when ssl or data is NULL.
 * @return  WRITE_DUP_WRITE_E when called on the read side of a write
 *          duplicate.
 * @return  BAD_MUTEX_E when the write duplicate could not be locked. Neither
 *          of those two sets ssl->error.
 * @return  WOLFSSL_FATAL_ERROR when the handshake or write fails. Call
 *          wolfSSL_get_error() for the reason.
 */
static int wolfSSL_write_internal(WOLFSSL* ssl, const void* data, size_t sz)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_write_internal");

    /* Validate parameters. Nothing on the way to the send reports zero, so ret
     * doubles as the "keep going" flag. */
    if ((ssl == NULL) || (data == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    #ifdef WOLFSSL_QUIC
    if ((ret == 0) && (WOLFSSL_IS_QUIC(ssl))) {
        WOLFSSL_MSG("SSL_write() on QUIC not allowed");
        ret = BAD_FUNC_ARG;
    }
    #endif

    #ifdef HAVE_WRITE_DUP
    if ((ret == 0) && (ssl->dupSide == READ_DUP_SIDE)) {
        WOLFSSL_MSG("Read dup side cannot write");
        ret = WRITE_DUP_WRITE_E;
    }
    /* Only enter special dupWrite logic when error is cleared. This will help
     * with handling async data and other edge case errors. */
    if ((ret == 0) && (ssl->dupWrite != NULL) && (ssl->error == 0)) {
        ret = wolfssl_write_dup_prepare(ssl);
    }
    #endif

    if (ret == 0) {
        #ifdef HAVE_ERRNO_H
        errno = 0;
        #endif

        #ifdef OPENSSL_EXTRA
        if (ssl->CBIS != NULL) {
            ssl->CBIS(ssl, WOLFSSL_CB_WRITE, WOLFSSL_SUCCESS);
            ssl->cbmode = WOLFSSL_CB_WRITE;
        }
        #endif
        ret = SendData(ssl, data, sz);

        WOLFSSL_LEAVE("wolfSSL_write_internal", ret);

        if (ret < 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    return ret;
}

/* Write application data to the peer.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      data  Application data to write.
 * @param [in]      sz    Length of data in bytes.
 * @return  Number of bytes written on success.
 * @return  BAD_FUNC_ARG when ssl or data is NULL, or sz is negative.
 * @return  WOLFSSL_FATAL_ERROR when the write fails. Call
 *          wolfSSL_get_error() for the reason.
 */
WOLFSSL_ABI
int wolfSSL_write(WOLFSSL* ssl, const void* data, int sz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_write");

    /* Validate parameter. */
    if (sz < 0) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_write_internal(ssl, data, (size_t)sz);
    }

    return ret;
}

/* Send a TLS 1.3 application data record containing only padding.
 *
 * Generates cover traffic (RFC 8446 Appendix E). The request applies
 * to the next record only.
 *
 * Arms and clears the request, except when async build is pending.
 * If still armed after write, no record was built (e.g. TLS 1.2 downgrade).
 * Completes any in-progress handshake.
 *
 * On WANT_WRITE the request is not left armed: the record was either
 * already queued (and gets flushed by the next write) or dropped. Calling
 * this function again is safe, but may put a second cover traffic record
 * on the wire if the first one had been queued.
 *
 * @param [in, out] ssl       SSL/TLS object.
 * @param [in]      paddingSz Length of padding in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when arguments are invalid or session is not stream TLS 1.3.
 * @return  BAD_STATE_E when an application write or an unrelated asynchronous
 *          operation is pending.
 * @return  WOLFSSL_FATAL_ERROR when the write fails.
 * @return  NOT_COMPILED_IN when TLS 1.3 support is not built in.
 */
int wolfSSL_send_tls13_cover_traffic(WOLFSSL* ssl, int paddingSz)
{
#ifdef WOLFSSL_TLS13
    int ret;
    int maxFrag;
    char dummy = 0;
#endif

    WOLFSSL_ENTER("wolfSSL_send_tls13_cover_traffic");

    if (ssl == NULL || paddingSz < 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_TLS13
    /* DTLS 1.3 pads to its own minimum length and is unsupported. */
    if (!IsAtLeastTLSv1_3(ssl->version) || ssl->options.dtls) {
        WOLFSSL_MSG("Cover traffic needs a stream TLS 1.3 session");
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    /* Check if armed request matches pending async op.
     * Use original padding size if resuming. */
    if (ssl->error == WC_NO_ERR_TRACE(WC_PENDING_E)) {
        if (!ssl->options.sendCoverTraffic) {
            WOLFSSL_MSG("Cover traffic blocked by pending async op");
            return BAD_STATE_E;
        }
        paddingSz = (int)ssl->options.coverTrafficPadSz;
    }
#endif

    /* Keep padding within the negotiated fragment size. */
    maxFrag = wolfSSL_GetMaxFragSize(ssl);
    /* The record also carries the content type byte, so padding equal to
     * the fragment size would overflow the plaintext limit. */
    if (paddingSz >= maxFrag) {
        WOLFSSL_MSG("Cover traffic padding larger than the max fragment size");
        return BAD_FUNC_ARG;
    }

    /* Disallow if an application write is pending to avoid losing data. */
    if (ssl->buffers.plainSz > 0) {
        WOLFSSL_MSG("Cover traffic needs the pending write to finish first");
        return BAD_STATE_E;
    }

    ssl->options.coverTrafficPadSz = (word16)paddingSz;
    ssl->options.sendCoverTraffic = 1;

    ret = wolfSSL_write(ssl, &dummy, 0);
    if (ret < 0) {
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* An asynchronous build is pending and consumes the padding when it
         * resumes, so leave the request armed for it. Trust ssl->error only
         * when ret is SendData()'s own sentinel -- some early returns skip
         * it. Any other error means no record was built here. */
        if (ret == WOLFSSL_FATAL_ERROR &&
                ssl->error == WC_NO_ERR_TRACE(WC_PENDING_E)) {
            return ret;
        }
    #endif
        Tls13ClearCoverTraffic(ssl);
    }
    else if (ssl->options.sendCoverTraffic ||
             (ret == 0 && ssl->error != 0)) {
        /* Write returned 0 but record wasn't sent (e.g. peer reset
         * or TLS downgrade). Not a success. */
        if (ssl->error == 0)
            ssl->error = BAD_STATE_E;
        Tls13ClearCoverTraffic(ssl);
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        /* SendData() returns the ciphertext length under
         * WOLFSSL_THREADED_CRYPT, not 0. Normalize to the documented
         * contract. */
        ret = 0;
    }

    return ret;
#else
    (void)paddingSz;
    return NOT_COMPILED_IN;
#endif /* WOLFSSL_TLS13 */
}

/* Inject data into the input buffer as if it was received from the peer.
 *
 * Used when the application reads the transport itself.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      data  Data to inject.
 * @param [in]      sz    Length of data in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl or data is NULL, or sz is not positive.
 * @return  BUFFER_ERROR when the input buffer lengths are inconsistent.
 * @return  APP_DATA_READY when the input buffer must be grown while there is
 *          application data left to read.
 * @return  Negative error code from growing the input buffer, such as
 *          MEMORY_E.
 */
int wolfSSL_inject(WOLFSSL* ssl, const void* data, int sz)
{
    int ret = WOLFSSL_SUCCESS;
    int usedLength = 0;
    int maxLength = 0;
    bufferStatic* in = NULL;

    WOLFSSL_ENTER("wolfSSL_inject");

    /* Validate parameters. */
    if ((ssl == NULL) || (data == NULL) || (sz <= 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == WOLFSSL_SUCCESS) {
        in = &ssl->buffers.inputBuffer;

        /* Order the unsigned fields first. Subtracting a larger value wraps
         * and can land back in the positive int range. */
        if ((in->idx > in->length) || (in->length > in->bufferSize)) {
            ret = BUFFER_ERROR;
        }
        else {
            usedLength = (int)(in->length - in->idx);
            /* Free space past all buffered data, where new data is appended. */
            maxLength  = (int)(in->bufferSize - in->length);

            if ((usedLength < 0) || (maxLength < 0)) {
                ret = BUFFER_ERROR;
            }
        }
    }

    if ((ret == WOLFSSL_SUCCESS) && (sz > maxLength)) {
        /* Need to make space */
        if (ssl->buffers.clearOutputBuffer.length > 0) {
            /* clearOutputBuffer points into so reallocating inputBuffer
             * will invalidate clearOutputBuffer and lose app data */
            WOLFSSL_MSG(
                "Can't inject while there is application data to read");
            ret = APP_DATA_READY;
        }
        else {
            /* Compacts the unconsumed data, leaving idx 0 and length
             * usedLength. */
            int growRet = GrowInputBuffer(ssl, sz, usedLength);

            if (growRet < 0) {
                ret = growRet;
            }
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        XMEMCPY(in->buffer + in->length, data, (size_t)sz);
        in->length += (word32)sz;
    }

    return ret;
}

/* Write application data to the peer and return the number of bytes written.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      data  Application data to write.
 * @param [in]      sz    Length of data in bytes.
 * @param [out]     wr    Number of bytes written. May be NULL.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  WOLFSSL_FAILURE when the write fails. Call wolfSSL_get_error() for
 *          the reason.
 */
int wolfSSL_write_ex(WOLFSSL* ssl, const void* data, size_t sz, size_t* wr)
{
    int ret;

    if (wr != NULL) {
        *wr = 0;
    }

    /* Validate parameter, matching wolfSSL_read_ex() and the rest of the
     * file. Reported as an error code rather than the 0 used for "nothing
     * was written", which a caller cannot tell from a short write. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_write_internal(ssl, data, sz);
        if (ret >= 0) {
            if (wr != NULL) {
                *wr = (size_t)ret;
            }

            /* handle partial write cases, if not set then a partial write is
             * considered a failure case, or if set and ret is 0 then is a
             * fail */
            if ((ret == 0) && (ssl->options.partialWrite)) {
                ret = 0;
            }
            else if (((size_t)ret < sz) && (!ssl->options.partialWrite)) {
                ret = 0;
            }
            else {
                /* wrote out all application data, or wrote out 1 byte or more
                 * with partial write flag set */
                ret = 1;
            }
        }
        else {
            ret = 0;
        }
    }

    return ret;
}

/* Read application data from the peer.
 *
 * Performs the handshake when it has not completed.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [out]     data  Buffer to hold application data.
 * @param [in]      sz    Length of buffer in bytes.
 * @param [in]      peek  When 1, data is not removed from the input buffer.
 * @return  Number of bytes read on success.
 * @return  0 when the peer has closed the connection.
 * @return  BAD_FUNC_ARG when ssl or data is NULL.
 * @return  WRITE_DUP_READ_E when called on the write side of a write
 *          duplicate. ssl->error is not set for it.
 * @return  WOLFSSL_FATAL_ERROR when the handshake or read fails. Call
 *          wolfSSL_get_error() for the reason.
 */
static int wolfSSL_read_internal(WOLFSSL* ssl, void* data, size_t sz, int peek)
{
    int ret = 0;
    /* A separate flag is needed rather than gating on ret: the OpenSSL
     * shutdown simulation below reports WOLFSSL_FAILURE, which is zero. */
    int done = 0;

    WOLFSSL_ENTER("wolfSSL_read_internal");

    /* Validate parameters. */
    if ((ssl == NULL) || (data == NULL)) {
        ret = BAD_FUNC_ARG;
        done = 1;
    }

    #ifdef WOLFSSL_QUIC
    if ((!done) && (WOLFSSL_IS_QUIC(ssl))) {
        WOLFSSL_MSG("SSL_read() on QUIC not allowed");
        ret = BAD_FUNC_ARG;
        done = 1;
    }
    #endif
    #if defined(WOLFSSL_ERROR_CODE_OPENSSL) && defined(OPENSSL_EXTRA)
    /* This additional logic is meant to simulate following openSSL behavior:
     * After bidirectional SSL_shutdown complete, SSL_read returns 0 and
     * SSL_get_error_code returns SSL_ERROR_ZERO_RETURN.
     * This behavior is used to know the disconnect of the underlying
     * transport layer.
     *
     * In this logic, CBIORecv is called with a read size of 0 to check the
     * transport layer status. It also returns WOLFSSL_FAILURE so that
     * SSL_read does not return a positive number on failure.
     */

    /* make sure bidirectional TLS shutdown completes */
    if ((!done) && ((ssl->error == WOLFSSL_ERROR_SYSCALL) ||
            (ssl->options.shutdownDone))) {
        /* ask the underlying transport the connection is closed */
        if (ssl->CBIORecv(ssl, (char*)data, 0, ssl->IOCB_ReadCtx)
            == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_CONN_CLOSE))
        {
            ssl->options.isClosed = 1;
            ssl->error = WOLFSSL_ERROR_ZERO_RETURN;
        }
        ret = WOLFSSL_FAILURE;
        done = 1;
    }
    #endif

    #ifdef HAVE_WRITE_DUP
    if ((!done) && (ssl->dupWrite != NULL) &&
            (ssl->dupSide == WRITE_DUP_SIDE)) {
        WOLFSSL_MSG("Write dup side cannot read");
        ret = WRITE_DUP_READ_E;
        done = 1;
    }
    #endif

    if (!done) {
        #ifdef HAVE_ERRNO_H
        errno = 0;
        #endif

        ret = ReceiveData(ssl, (byte*)data, sz, peek);

        #ifdef HAVE_WRITE_DUP
        if (ssl->dupWrite != NULL) {
            if ((ssl->error != 0) &&
                (ssl->error != WC_NO_ERR_TRACE(WANT_READ))
            #ifdef WOLFSSL_ASYNC_CRYPT
                && (ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E))
            #endif
            ) {
                int notifyErr;

                WOLFSSL_MSG("Notifying write side of fatal read error");
                notifyErr  = NotifyWriteSide(ssl, ssl->error);
                if (notifyErr < 0) {
                    ret = ssl->error = notifyErr;
                }
            }
        }
        #endif

        WOLFSSL_LEAVE("wolfSSL_read_internal", ret);

        if (ret < 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    return ret;
}

/* Read application data from the peer without removing it.
 *
 * The same data is returned by the next call to wolfSSL_read().
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [out]     data  Buffer to hold application data.
 * @param [in]      sz    Length of buffer in bytes.
 * @return  Number of bytes read on success.
 * @return  BAD_FUNC_ARG when ssl or data is NULL, or sz is negative.
 * @return  WOLFSSL_FATAL_ERROR when the read fails.
 */
int wolfSSL_peek(WOLFSSL* ssl, void* data, int sz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_peek");

    /* Validate parameter. */
    if (sz < 0) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_read_internal(ssl, data, (size_t)sz, TRUE);
    }

    return ret;
}

/* Read application data from the peer.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [out]     data  Buffer to hold application data.
 * @param [in]      sz    Length of buffer in bytes.
 * @return  Number of bytes read on success.
 * @return  0 when the peer has closed the connection.
 * @return  BAD_FUNC_ARG when ssl or data is NULL, or sz is negative.
 * @return  WOLFSSL_FATAL_ERROR when the read fails. Call wolfSSL_get_error()
 *          for the reason.
 */
WOLFSSL_ABI
int wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_read");

    /* Validate parameters. */
    if (sz < 0) {
        ret = BAD_FUNC_ARG;
    }
    #ifdef OPENSSL_EXTRA
    else if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    #endif
    else {
        #ifdef OPENSSL_EXTRA
        if (ssl->CBIS != NULL) {
            ssl->CBIS(ssl, WOLFSSL_CB_READ, WOLFSSL_SUCCESS);
            ssl->cbmode = WOLFSSL_CB_READ;
        }
        #endif
        ret = wolfSSL_read_internal(ssl, data, (size_t)sz, FALSE);
    }

    return ret;
}

/* Read application data from the peer and report whether any was read.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [out]     data  Buffer to hold application data.
 * @param [in]      sz    Length of buffer in bytes.
 * @param [out]     rd    Number of bytes read. May be NULL. Only set when
 *                        data was read.
 * @return  1 when application data was read.
 * @return  0 when no application data was read. Call wolfSSL_get_error() for
 *          the reason.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_read_ex(WOLFSSL* ssl, void* data, size_t sz, size_t* rd)
{
    int ret;

    /* Validate parameter. Checked unconditionally so the guarded branch does
     * not leave a standalone block. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        #ifdef OPENSSL_EXTRA
        if (ssl->CBIS != NULL) {
            ssl->CBIS(ssl, WOLFSSL_CB_READ, WOLFSSL_SUCCESS);
            ssl->cbmode = WOLFSSL_CB_READ;
        }
        #endif
        ret = wolfSSL_read_internal(ssl, data, sz, FALSE);

        if ((ret > 0) && (rd != NULL)) {
            *rd = (size_t)ret;
        }

        ret = (ret > 0) ? 1 : 0;
    }

    return ret;
}

#ifndef WOLFSSL_LEANPSK

/* Write application data to the peer with socket flags.
 *
 * Flags are set on the socket for the write and restored afterwards.
 *
 * @param [in, out] ssl    SSL/TLS object.
 * @param [in]      data   Application data to write.
 * @param [in]      sz     Length of data in bytes.
 * @param [in]      flags  Flags to pass to the send call.
 * @return  Number of bytes written on success.
 * @return  BAD_FUNC_ARG when ssl or data is NULL, or sz is negative.
 * @return  WOLFSSL_FATAL_ERROR when the write fails.
 */
int wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_send");

    /* Validate parameters. */
    if ((ssl == NULL) || (data == NULL) || (sz < 0)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        int oldFlags = ssl->wflags;

        ssl->wflags = flags;
        ret = wolfSSL_write(ssl, data, sz);
        ssl->wflags = oldFlags;

        WOLFSSL_LEAVE("wolfSSL_send", ret);
    }

    return ret;
}

/* Read application data from the peer with socket flags.
 *
 * Flags are set on the socket for the read and restored afterwards.
 *
 * @param [in, out] ssl    SSL/TLS object.
 * @param [out]     data   Buffer to hold application data.
 * @param [in]      sz     Length of buffer in bytes.
 * @param [in]      flags  Flags to pass to the recv call.
 * @return  Number of bytes read on success.
 * @return  BAD_FUNC_ARG when ssl or data is NULL, or sz is negative.
 * @return  WOLFSSL_FATAL_ERROR when the read fails.
 */
int wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_recv");

    /* Validate parameters. */
    if ((ssl == NULL) || (data == NULL) || (sz < 0)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        int oldFlags = ssl->rflags;

        ssl->rflags = flags;
        ret = wolfSSL_read(ssl, data, sz);
        ssl->rflags = oldFlags;

        WOLFSSL_LEAVE("wolfSSL_recv", ret);
    }

    return ret;
}
#endif

/* Send a user_canceled alert to the peer and shut down the connection.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_SHUTDOWN_NOT_DONE when the shutdown is not complete.
 * @return  WOLFSSL_FAILURE when ssl is NULL or sending the alert fails.
 */
int wolfSSL_SendUserCanceled(WOLFSSL* ssl)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("wolfSSL_SendUserCanceled");

    if (ssl != NULL) {
        ssl->error = SendAlert(ssl, alert_warning, user_canceled);
        if (ssl->error < 0) {
            WOLFSSL_ERROR(ssl->error);
        }
        else {
            ret = wolfSSL_shutdown(ssl);
        }
    }

    WOLFSSL_LEAVE("wolfSSL_SendUserCanceled", ret);

    return ret;
}

/* Flush an alert still sitting in the output buffer.
 *
 * A previous call may have left the close_notify alert buffered when the
 * transport reported WANT_WRITE. Get it out before doing anything else.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in, out] ret  Result for wolfSSL_shutdown() to return. Set only on
 *                       the paths that reach a decision; on the others it is
 *                       left as the caller initialized it. Returning 0 while
 *                       assigning WOLFSSL_SHUTDOWN_NOT_DONE would break the
 *                       caller: it treats an undecided result as "no
 *                       close_notify can ever be sent" and converts it to a
 *                       failure. Every path here that reports "call again"
 *                       therefore returns 1.
 * @return  1 when no later step of the shutdown may run.
 * @return  0 when the caller carries on with the rest of the shutdown. The
 *          result may already have been decided: the exchange can complete
 *          here, and the steps that follow then leave it alone.
 */
static int wolfssl_shutdown_flush_alert(WOLFSSL* ssl, int* ret)
{
    int done = 0;

    if ((ssl->error == WC_NO_ERR_TRACE(WANT_WRITE)) &&
            (ssl->buffers.outputBuffer.length > 0)) {
        int rc = SendBuffered(ssl);

        if (rc != 0) {
            ssl->error = rc;
            /* for error tracing */
            if (rc != WC_NO_ERR_TRACE(WANT_WRITE)) {
                WOLFSSL_ERROR(rc);
            }
            /* The reason has been traced above - don't trace the return
             * value as well. */
            *ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
            done = 1;
        }
        else {
            ssl->error = WOLFSSL_ERROR_NONE;
            /* we succeeded in sending the alert now */
            if (ssl->options.sentNotify)  {
                /* just after we send the alert, if we didn't receive the
                 * alert from the other peer yet, return
                 * WOLFSSL_SHUTDOWN_NOT_DONE */
                if (!ssl->options.closeNotify) {
                    *ret = WOLFSSL_SHUTDOWN_NOT_DONE;
                    done = 1;
                }
                else {
                    ssl->options.shutdownDone = 1;
                    *ret = WOLFSSL_SUCCESS;
                }
            }
        }
    }

    return done;
}

/* Send the close_notify alert to the peer.
 *
 * Not being able to send it right away is not an error - the alert is left in
 * the output buffer and goes out eventually.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in, out] ret  Result for wolfSSL_shutdown() to return. Set only on
 *                       the paths that reach a decision; on the others it is
 *                       left as the caller initialized it. As in
 *                       wolfssl_shutdown_flush_alert(), a path that reports
 *                       "call again" must return 1 - the caller reads an
 *                       undecided result as "no close_notify can ever be
 *                       sent" and turns it into a failure.
 * @return  1 when no later step of the shutdown may run.
 * @return  0 when the caller carries on with the rest of the shutdown. The
 *          result may already have been decided: the exchange can complete
 *          here, and the steps that follow then leave it alone.
 */
static int wolfssl_shutdown_send_close_notify(WOLFSSL* ssl, int* ret)
{
    int done = 0;

    /* try to send close notify, not an error if can't */
    if ((!ssl->options.isClosed) && (!ssl->options.connReset) &&
            (!ssl->options.sentNotify)) {
        ssl->error = SendAlert(ssl, alert_warning, close_notify);

        /* the alert is now sent or sitting in the buffer,
         * where will be sent eventually */
        if ((ssl->error == 0) ||
                (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))) {
            ssl->options.sentNotify = 1;
        }

        if (ssl->error < 0) {
            WOLFSSL_ERROR(ssl->error);
            /* The reason has been traced above - don't trace the return
             * value as well. */
            *ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
            done = 1;
        }
        else if (ssl->options.closeNotify) {
            *ret = WOLFSSL_SUCCESS;
            ssl->options.shutdownDone = 1;
        }
        else {
            *ret = WOLFSSL_SHUTDOWN_NOT_DONE;
            done = 1;
        }
    }

    return done;
}

/* Wait for the peer's close_notify alert to complete a bidirectional shutdown.
 *
 * Called when this side has sent its close_notify but has not seen the
 * peer's, i.e. wolfSSL_shutdown() called again.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the shutdown is complete.
 * @return  WOLFSSL_SHUTDOWN_NOT_DONE when the peer's alert has not arrived.
 * @return  WOLFSSL_FATAL_ERROR on error. Call wolfSSL_get_error() for the
 *          reason.
 */
static int wolfssl_shutdown_recv_close_notify(WOLFSSL* ssl)
{
    int ret;

    /* If there is still buffered application data waiting to be read, do not
     * process incoming records here. clearOutputBuffer.buffer points into
     * inputBuffer, and ProcessReply() may call GrowInputBuffer(), which frees
     * and reallocates inputBuffer. Require the pending data to be drained
     * first. */
    if (ssl->buffers.clearOutputBuffer.length > 0) {
        WOLFSSL_MSG("Pending application data, read it before shutdown");
        ret = WOLFSSL_SHUTDOWN_NOT_DONE;
    }
    else {
        ret = ProcessReply(ssl);
        if ((ret == WC_NO_ERR_TRACE(ZERO_RETURN)) ||
                (ret == WC_NO_ERR_TRACE(SOCKET_ERROR_E))) {
            /* simulate OpenSSL behavior */
            ssl->options.shutdownDone = 1;
            /* Clear error */
            ssl->error = WOLFSSL_ERROR_NONE;
            ret = WOLFSSL_SUCCESS;
        }
        else if (ret == WC_NO_ERR_TRACE(MEMORY_E)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        else if (ret == WC_NO_ERR_TRACE(WANT_READ)) {
            ssl->error = ret;
            ret = WOLFSSL_FATAL_ERROR;
        }
        else if (ssl->error == WOLFSSL_ERROR_NONE) {
            ret = WOLFSSL_SHUTDOWN_NOT_DONE;
        }
        else {
            WOLFSSL_ERROR(ssl->error);
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    return ret;
}

/* Shut the connection down by exchanging close_notify alerts with the peer.
 *
 * Call repeatedly while WOLFSSL_SHUTDOWN_NOT_DONE is returned to complete a
 * bidirectional shutdown.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS when the shutdown is complete.
 * @return  WOLFSSL_SHUTDOWN_NOT_DONE when the peer's close_notify has not
 *          been received yet.
 * @return  SSL_SHUTDOWN_ALREADY_DONE_E when the connection was already closed
 *          and WOLFSSL_SHUTDOWNONCE is defined.
 * @return  WOLFSSL_FATAL_ERROR when ssl is NULL or on error. Call
 *          wolfSSL_get_error() for the reason.
 *
 * SOCKET_PEER_CLOSED_E is reported when the connection was already
 * closed or reset and no close_notify was ever sent, so the exchange
 * can never complete. That covers this side closing by sending a fatal
 * alert as much as the peer going away, and it is only used when no
 * more specific error has been recorded. Under OPENSSL_EXTRA
 * wolfSSL_get_error() reports it as WOLFSSL_ERROR_SYSCALL, so a locally
 * aborted connection surfaces as a syscall error. This case used to return 0,
 * which is WOLFSSL_SHUTDOWN_NOT_DONE under WOLFSSL_ERROR_CODE_OPENSSL,
 * so a caller looping while the result is 0 never terminated.
 *
 * Recording it also appends to the OpenSSL error queue where one is built in
 * (WOLFSSL_HAVE_ERROR_QUEUE, which OPENSSL_ALL, OPENSSL_EXTRA, WOLFSSL_NGINX
 * and WOLFSSL_HAPROXY all enable), so an application that inspects the queue
 * after tearing down an already-aborted connection now finds an entry where
 * it previously found none. Clear it with wolfSSL_ERR_clear_error() if
 * leftover entries matter to the caller.
 */
WOLFSSL_ABI
int wolfSSL_shutdown(WOLFSSL* ssl)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    WOLFSSL_ENTER("wolfSSL_shutdown");

    /* Validate parameter. */
    if (ssl == NULL) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    else if (ssl->options.quietShutdown) {
        WOLFSSL_MSG("quiet shutdown, no close notify sent");
        ret = WOLFSSL_SUCCESS;
    }
    else {
        int done;

        /* Try to flush the buffer first, it might contain the alert */
        done = wolfssl_shutdown_flush_alert(ssl, &ret);
        if (!done) {
            done = wolfssl_shutdown_send_close_notify(ssl, &ret);
        }

        #ifdef WOLFSSL_SHUTDOWNONCE
        if ((!done) &&
                ((ssl->options.isClosed) || (ssl->options.connReset))) {
            /* Shutdown has already occurred.
             * Caller is free to ignore this error. */
            ret = SSL_SHUTDOWN_ALREADY_DONE_E;
            done = 1;
        }
        #endif

        /* wolfSSL_shutdown called again for bidirectional shutdown */
        if ((!done) && (ssl->options.sentNotify) &&
                (!ssl->options.closeNotify)) {
            ret = wolfssl_shutdown_recv_close_notify(ssl);
        }
        else if ((!done) && (!ssl->options.sentNotify) &&
                (ret != WOLFSSL_SUCCESS)) {
            /* No close_notify was sent and the exchange has not completed by
             * other means, so it never will. Record why when nothing else
             * has, so the caller is not left with a failure and no error to
             * query, but keep any more specific error already set.
             *
             * A send can report failure without setting sentNotify and still
             * leave the shutdown complete: SendAlert() returns a positive
             * value when a QUIC send_alert callback fails, which is neither
             * the success nor the negative-error case the helper checks, and
             * the peer's close_notify may already have arrived. Leave a
             * success decided above alone.
             *
             * One case is left out: being called again once the exchange has
             * completed, with both notifies seen. Nothing has gone wrong
             * there, so no error is recorded, and the call still reports
             * failure. Only reachable where wolfSSL_clear() below is not
             * compiled in to reset the flags after a success. */
            WOLFSSL_MSG("Connection closed before close_notify was sent");
            if (ssl->error == WOLFSSL_ERROR_NONE) {
                ssl->error = SOCKET_PEER_CLOSED_E;
                /* Trace it as the other failing paths here do - recording the
                 * error without this leaves nothing in the error trace. */
                WOLFSSL_ERROR(ssl->error);
            }
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    #if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    /* reset WOLFSSL structure state for possible reuse */
    if (ret == WOLFSSL_SUCCESS) {
        if (wolfSSL_clear(ssl) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("could not clear WOLFSSL");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    #endif

    WOLFSSL_LEAVE("wolfSSL_shutdown", ret);

    return ret;
}
#endif /* !NO_TLS */

/* Get the number of bytes of decrypted application data ready to be read.
 *
 * TODO This ssl parameter needs to be changed to const once our ABI checker
 *      stops flagging qualifier additions as ABI breaking.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Number of buffered application data bytes.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 */
WOLFSSL_ABI
int wolfSSL_pending(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_pending");

    /* Validate parameter. */
    if (ssl == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        ret = (int)ssl->buffers.clearOutputBuffer.length;
    }

    return ret;
}

/* Determine whether there is application data available to read.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when there is data buffered.
 * @return  0 when there is no data buffered.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 */
int wolfSSL_has_pending(const WOLFSSL* ssl)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_has_pending");

    /* Validate parameter. */
    if (ssl == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    else if (ssl->buffers.clearOutputBuffer.length > 0) {
        ret = 1;
    }
    #ifdef WOLFSSL_TLS_READ_AHEAD
    /* Read-ahead can leave undecrypted data buffered while the socket itself
     * has no more data. This may be a complete record or only a partial one
     * (e.g. a coalesced read that pulled a record plus the head of the next),
     * so a non-zero return does not guarantee wolfSSL_read() will yield
     * application data without another socket read. Report it so a
     * select()/poll() loop keeps draining until wolfSSL_read() reports
     * WANT_READ, instead of stalling on buffered data. */
    else if (ssl->buffers.inputBuffer.length > ssl->buffers.inputBuffer.idx) {
        ret = 1;
    }
    #endif

    return ret;
}

#ifndef USE_WINDOWS_API
#if !defined(NO_WRITEV) && !defined(NO_TLS)

/* Write the data described by an array of iovecs to the peer.
 *
 * Simulates writev semantics, doesn't actually do block at a time though
 * because of SSL_write behavior and because front adds may be small. The
 * segments are gathered into one buffer and written as a single call.
 *
 * @param [in, out] ssl     SSL/TLS object.
 * @param [in]      iov     Array of buffers to write.
 * @param [in]      iovcnt  Number of entries in iov.
 * @return  Number of bytes written on success.
 * @return  BAD_FUNC_ARG when ssl is NULL, iovcnt is negative, or iov is
 *          NULL with a non-zero iovcnt.
 * @return  BUFFER_E when the total length of the segments overflows.
 * @return  MEMORY_ERROR when the gather buffer cannot be allocated.
 * @return  WOLFSSL_FATAL_ERROR when the write fails. Call wolfSSL_get_error()
 *          for the reason.
 */
int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov, int iovcnt)
{
    #ifdef WOLFSSL_SMALL_STACK
    byte   staticBuffer[1]; /* force heap usage */
    #else
    byte   staticBuffer[FILE_BUFFER_SIZE];
    #endif
    byte*  myBuffer = staticBuffer;
    int    dynamic  = 0;
    size_t sending  = 0;
    size_t idx      = 0;
    int    i;
    int    ret      = 0;

    WOLFSSL_ENTER("wolfSSL_writev");

    /* Validate parameters before anything is read from the object. */
    if ((ssl == NULL) || ((iov == NULL) && (iovcnt != 0)) || (iovcnt < 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Total up the length being sent, checking for overflow. */
    for (i = 0; (ret == 0) && (i < iovcnt); i++) {
        if (!WC_SAFE_SUM_UNSIGNED(size_t, sending, iov[i].iov_len, sending)) {
            ret = BUFFER_E;
        }
    }

    /* Gather into the stack buffer, or the heap when it doesn't fit. Small
     * stack builds have a one byte buffer, so always take the heap. */
    if ((ret == 0) && (sending > sizeof(staticBuffer))) {
        myBuffer = (byte*)XMALLOC(sending, ssl->heap, DYNAMIC_TYPE_WRITEV);
        if (myBuffer == NULL) {
            ret = MEMORY_ERROR;
        }
        else {
            dynamic = 1;
        }
    }

    if (ret == 0) {
        /* The loop below writes exactly the span that is read, but the
         * compiler cannot see that. When wolfSSL_write_internal() is inlined
         * here, the warning is reported against the SendData() call inside
         * it rather than against the call below, and a diagnostic pragma
         * only applies at the line the warning is reported on - so the one
         * below cannot reach it. A definite store does. Do not remove: it is
         * what keeps -Wmaybe-uninitialized quiet on builds that inline this,
         * such as a powerpc64 cross build at -O2. */
        myBuffer[0] = 0;

        for (i = 0; i < iovcnt; i++) {
            XMEMCPY(&myBuffer[idx], iov[i].iov_base, iov[i].iov_len);
            idx += iov[i].iov_len;
        }

        /* Covers the warning when it is reported against the call itself
         * instead, which is where it lands when there is no inlining. */
        PRAGMA_GCC_DIAG_PUSH
        PRAGMA_GCC("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
        ret = wolfSSL_write_internal(ssl, myBuffer, sending);
        PRAGMA_GCC_DIAG_POP
    }

    /* Only set when the allocation above succeeded, so ssl is not NULL. */
    if (dynamic) {
        XFREE(myBuffer, ssl->heap, DYNAMIC_TYPE_WRITEV);
    }

    return ret;
}
#endif
#endif

#ifdef OPENSSL_EXTRA
/* Get the I/O operation the SSL/TLS object is waiting on.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_READING when waiting for the transport to be readable.
 * @return  WOLFSSL_WRITING when waiting for the transport to be writable.
 * @return  WOLFSSL_NOTHING when not waiting on the transport or ssl is NULL.
 */
int wolfSSL_want(WOLFSSL* ssl)
{
    int rw_state = WOLFSSL_NOTHING;

    if (ssl != NULL) {
        if (ssl->error == WC_NO_ERR_TRACE(WANT_READ)) {
            rw_state = WOLFSSL_READING;
        }
        else if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE)) {
            rw_state = WOLFSSL_WRITING;
        }
    }

    return rw_state;
}
#endif

/* Determine whether the last operation is waiting for the transport to be
 * readable.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when the current error is want read.
 * @return  0 otherwise, including when ssl is NULL.
 */
int wolfSSL_want_read(WOLFSSL* ssl)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_want_read");

    if ((ssl != NULL) && (ssl->error == WC_NO_ERR_TRACE(WANT_READ))) {
        ret = 1;
    }

    return ret;
}

/* Determine whether the last operation is waiting for the transport to be
 * writable.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when the current error is want write.
 * @return  0 otherwise, including when ssl is NULL.
 */
int wolfSSL_want_write(WOLFSSL* ssl)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_want_write");

    if ((ssl != NULL) && (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))) {
        ret = 1;
    }

    return ret;
}

/* Get the shutdown state of the connection.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Bit set of WOLFSSL_SENT_SHUTDOWN and WOLFSSL_RECEIVED_SHUTDOWN.
 * @return  0 when ssl is NULL or no close_notify has been sent or received.
 */
int wolfSSL_get_shutdown(const WOLFSSL* ssl)
{
    int isShutdown = 0;

    WOLFSSL_ENTER("wolfSSL_get_shutdown");

    if (ssl != NULL) {
        #if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
        if (ssl->options.shutdownDone) {
            /* The SSL object was possibly cleared with wolfSSL_clear after
             * a successful shutdown. Simulate a response for a full
             * bidirectional shutdown. */
            isShutdown = WOLFSSL_SENT_SHUTDOWN | WOLFSSL_RECEIVED_SHUTDOWN;
        }
        else
        #endif
        {
            /* in OpenSSL, WOLFSSL_SENT_SHUTDOWN = 1, when closeNotifySent   *
             * WOLFSSL_RECEIVED_SHUTDOWN = 2, from close notify or fatal err */
            if (ssl->options.sentNotify) {
                isShutdown |= WOLFSSL_SENT_SHUTDOWN;
            }
            if ((ssl->options.closeNotify) || (ssl->options.connReset)) {
                isShutdown |= WOLFSSL_RECEIVED_SHUTDOWN;
            }
        }
    }

    WOLFSSL_LEAVE("wolfSSL_get_shutdown", isShutdown);
    return isShutdown;
}

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_SSL_API_RW_INCLUDED */
