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
 * @return  WOLFSSL_FATAL_ERROR when the handshake or write fails. Call
 *          wolfSSL_get_error() for the reason.
 */
static int wolfSSL_write_internal(WOLFSSL* ssl, const void* data, size_t sz)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_write");

    if (ssl == NULL || data == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        WOLFSSL_MSG("SSL_write() on QUIC not allowed");
        return BAD_FUNC_ARG;
    }
#endif

#ifdef HAVE_WRITE_DUP
    if (ssl->dupSide == READ_DUP_SIDE) {
        WOLFSSL_MSG("Read dup side cannot write");
        return WRITE_DUP_WRITE_E;
    }
    /* Only enter special dupWrite logic when error is cleared. This will help
     * with handling async data and other edge case errors. */
    if (ssl->dupWrite != NULL && ssl->error == 0) {
        int dupErr = 0;   /* local copy */
        /* Lock ssl->dupWrite to gather what needs to be done. */
        if (wc_LockMutex(&ssl->dupWrite->dupMutex) != 0)
            return BAD_MUTEX_E;
        dupErr = ssl->dupWrite->dupErr;
#ifdef WOLFSSL_TLS13
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
                while (*tail != NULL)
                    tail = &(*tail)->next;
                *tail = ssl->certReqCtx;
                ssl->certReqCtx = ssl->dupWrite->postHandshakeCertReqCtx;
                ssl->dupWrite->postHandshakeCertReqCtx = NULL;
                FreeHandshakeHashes(ssl);
                ssl->hsHashes = ssl->dupWrite->postHandshakeHashState;
                ssl->dupWrite->postHandshakeHashState = NULL;
                ssl->options.sendVerify =
                    ssl->dupWrite->postHandshakeSendVerify;
                ssl->options.sigAlgo = ssl->dupWrite->postHandshakeSigAlgo;
                ssl->options.hashAlgo = ssl->dupWrite->postHandshakeHashAlgo;
            }
#endif /* WOLFSSL_POST_HANDSHAKE_AUTH */
#ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls) {
                /* Schedule key update to be sent. */
                if (ssl->keys.keyUpdateRespond)
                    ssl->dtls13DoKeyUpdate = 1;

                /* Copy over ACKs */
                ssl->dtls13Rtx.sendAcks |= ssl->dupWrite->sendAcks;
                if (ssl->dupWrite->sendAcks) {
                    /* Insert each record number so the
                     * ACK message is properly ordered. */
                    struct Dtls13RecordNumber* rn;
                    for (rn = ssl->dupWrite->sendAckList; rn != NULL;
                         rn = rn->next) {
                        ret = Dtls13RtxAddAck(ssl, rn->epoch, rn->seq);
                        if (ret != 0)
                            break;
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
#endif /* WOLFSSL_TLS13 */
        wc_UnLockMutex(&ssl->dupWrite->dupMutex);

        if (dupErr != 0) {
            WOLFSSL_MSG("Write dup error from other side");
            ssl->error = dupErr;
            return WOLFSSL_FATAL_ERROR;
        }
        if (ret != 0) {
            ssl->error = ret;
            return WOLFSSL_FATAL_ERROR;
        }

#ifdef WOLFSSL_TLS13
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
                    if (ssl->error != WC_NO_ERR_TRACE(WANT_WRITE) &&
                            ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E)) {
                        WOLFSSL_MSG("Post-handshake auth send failed");
                        ssl->error = POST_HAND_AUTH_ERROR;
                    }
                    return WOLFSSL_FATAL_ERROR;
                }
                /* PHA response fully sent: publish the write side's updated
                 * transcript to the read side for the next PHA round. */
                if (ssl->hsHashes != NULL && ssl->dupWrite != NULL) {
                    int syncRet;
                    if (wc_LockMutex(&ssl->dupWrite->dupMutex) != 0)
                        return BAD_MUTEX_E;
                    syncRet = InitHandshakeHashesAndCopy(ssl, ssl->hsHashes,
                        &ssl->dupWrite->postHandshakeSyncedHashState);
                    if (syncRet != 0) {
                        /* On failure the copy may have left a partially
                         * initialized transcript.  The read side only checks
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
                        return WOLFSSL_FATAL_ERROR;
                    }
                }
            }
#endif /* WOLFSSL_POST_HANDSHAKE_AUTH */
#ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls) {
                if (ssl->dtls13KeyUpdateAcked)
                    ret = DoDtls13KeyUpdateAck(ssl);
                ssl->dtls13KeyUpdateAcked = 0;
                if (ret == 0)
                    ret = Dtls13DoScheduledWork(ssl);
            }
            else
#endif /* WOLFSSL_DTLS13 */
            if (ssl->keys.keyUpdateRespond) /* cleared in SendTls13KeyUpdate */
                ret = Tls13UpdateKeys(ssl);
            if (ret != 0) {
                ssl->error = ret;
                return WOLFSSL_FATAL_ERROR;
            }
            /* WANT_WRITE is safe to clear. Data is buffered in output buffer
             * or in DTLS RTX queue */
            ret = 0;
        }
#endif /* WOLFSSL_TLS13 */
    }
#endif

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

    WOLFSSL_LEAVE("wolfSSL_write", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
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
    WOLFSSL_ENTER("wolfSSL_write");

    if (sz < 0)
        return BAD_FUNC_ARG;

    return wolfSSL_write_internal(ssl, data, (size_t)sz);
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
 * @return  MEMORY_E when growing the input buffer fails.
 */
int wolfSSL_inject(WOLFSSL* ssl, const void* data, int sz)
{
    int maxLength;
    int usedLength;

    WOLFSSL_ENTER("wolfSSL_inject");

    if (ssl == NULL || data == NULL || sz <= 0)
        return BAD_FUNC_ARG;

    usedLength = (int)(ssl->buffers.inputBuffer.length -
                       ssl->buffers.inputBuffer.idx);
    maxLength  = (int)(ssl->buffers.inputBuffer.bufferSize -
                       (word32)usedLength);

    if (sz > maxLength) {
        /* Need to make space */
        int ret;
        if (ssl->buffers.clearOutputBuffer.length > 0) {
            /* clearOutputBuffer points into so reallocating inputBuffer will
             * invalidate clearOutputBuffer and lose app data */
            WOLFSSL_MSG("Can't inject while there is application data to read");
            return APP_DATA_READY;
        }
        ret = GrowInputBuffer(ssl, sz, usedLength);
        if (ret < 0)
            return ret;
    }

    XMEMCPY(ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
            data, sz);
    ssl->buffers.inputBuffer.length += sz;

    return WOLFSSL_SUCCESS;
}

/* Write application data to the peer and return the number of bytes written.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      data  Application data to write.
 * @param [in]      sz    Length of data in bytes.
 * @param [out]     wr    Number of bytes written. May be NULL.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when the write fails. Call wolfSSL_get_error() for
 *          the reason.
 */
int wolfSSL_write_ex(WOLFSSL* ssl, const void* data, size_t sz, size_t* wr)
{
    int ret;

    if (wr != NULL) {
        *wr = 0;
    }

    ret = wolfSSL_write_internal(ssl, data, sz);
    if (ret >= 0) {
        if (wr != NULL) {
            *wr = (size_t)ret;
        }

        /* handle partial write cases, if not set then a partial write is
         * considered a failure case, or if set and ret is 0 then is a fail */
        if (ret == 0 && ssl->options.partialWrite) {
            ret = 0;
        }
        else if ((size_t)ret < sz && !ssl->options.partialWrite) {
            ret = 0;
        }
        else {
            /* wrote out all application data, or wrote out 1 byte or more with
             * partial write flag set */
            ret = 1;
        }
    }
    else {
        ret = 0;
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
 * @return  WOLFSSL_FATAL_ERROR when the handshake or read fails. Call
 *          wolfSSL_get_error() for the reason.
 */
static int wolfSSL_read_internal(WOLFSSL* ssl, void* data, size_t sz, int peek)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_read_internal");

    if (ssl == NULL || data == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        WOLFSSL_MSG("SSL_read() on QUIC not allowed");
        return BAD_FUNC_ARG;
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
    if (ssl->error == WOLFSSL_ERROR_SYSCALL || ssl->options.shutdownDone) {
        /* ask the underlying transport the connection is closed */
        if (ssl->CBIORecv(ssl, (char*)data, 0, ssl->IOCB_ReadCtx)
            == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_CONN_CLOSE))
        {
            ssl->options.isClosed = 1;
            ssl->error = WOLFSSL_ERROR_ZERO_RETURN;
        }
        return WOLFSSL_FAILURE;
    }
#endif

#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite && ssl->dupSide == WRITE_DUP_SIDE) {
        WOLFSSL_MSG("Write dup side cannot read");
        return WRITE_DUP_READ_E;
    }
#endif

#ifdef HAVE_ERRNO_H
        errno = 0;
#endif

    ret = ReceiveData(ssl, (byte*)data, sz, peek);

#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite) {
        if (ssl->error != 0 && ssl->error != WC_NO_ERR_TRACE(WANT_READ)
        #ifdef WOLFSSL_ASYNC_CRYPT
            && ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E)
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

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
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
    WOLFSSL_ENTER("wolfSSL_peek");

    if (sz < 0)
        return BAD_FUNC_ARG;

    return wolfSSL_read_internal(ssl, data, (size_t)sz, TRUE);
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
    WOLFSSL_ENTER("wolfSSL_read");

    if (sz < 0)
        return BAD_FUNC_ARG;

    #ifdef OPENSSL_EXTRA
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ssl->CBIS != NULL) {
        ssl->CBIS(ssl, WOLFSSL_CB_READ, WOLFSSL_SUCCESS);
        ssl->cbmode = WOLFSSL_CB_READ;
    }
    #endif
    return wolfSSL_read_internal(ssl, data, (size_t)sz, FALSE);
}

/* returns 0 on failure and 1 on read */
int wolfSSL_read_ex(WOLFSSL* ssl, void* data, size_t sz, size_t* rd)
{
    int ret;

    #ifdef OPENSSL_EXTRA
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ssl->CBIS != NULL) {
        ssl->CBIS(ssl, WOLFSSL_CB_READ, WOLFSSL_SUCCESS);
        ssl->cbmode = WOLFSSL_CB_READ;
    }
    #endif
    ret = wolfSSL_read_internal(ssl, data, sz, FALSE);

    if (ret > 0 && rd != NULL) {
        *rd = (size_t)ret;
    }

    return ret > 0 ? 1 : 0;
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
    int oldFlags;

    WOLFSSL_ENTER("wolfSSL_send");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->wflags;

    ssl->wflags = flags;
    ret = wolfSSL_write(ssl, data, sz);
    ssl->wflags = oldFlags;

    WOLFSSL_LEAVE("wolfSSL_send", ret);

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
    int oldFlags;

    WOLFSSL_ENTER("wolfSSL_recv");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->rflags;

    ssl->rflags = flags;
    ret = wolfSSL_read(ssl, data, sz);
    ssl->rflags = oldFlags;

    WOLFSSL_LEAVE("wolfSSL_recv", ret);

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
    WOLFSSL_ENTER("wolfSSL_recv");

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

/* WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_shutdown(WOLFSSL* ssl)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    WOLFSSL_ENTER("wolfSSL_shutdown");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (ssl->options.quietShutdown) {
        WOLFSSL_MSG("quiet shutdown, no close notify sent");
        ret = WOLFSSL_SUCCESS;
    }
    else {

        /* Try to flush the buffer first, it might contain the alert */
        if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE) &&
            ssl->buffers.outputBuffer.length > 0) {
            ret = SendBuffered(ssl);
            if (ret != 0) {
                ssl->error = ret;
                /* for error tracing */
                if (ret != WC_NO_ERR_TRACE(WANT_WRITE))
                    WOLFSSL_ERROR(ret);
                ret = WOLFSSL_FATAL_ERROR;
                WOLFSSL_LEAVE("wolfSSL_shutdown", ret);
                return ret;
            }

            ssl->error = WOLFSSL_ERROR_NONE;
            /* we succeeded in sending the alert now */
            if (ssl->options.sentNotify)  {
                /* just after we send the alert, if we didn't receive the alert
                 * from the other peer yet, return WOLFSSL_STHUDOWN_NOT_DONE */
                if (!ssl->options.closeNotify) {
                    ret = WOLFSSL_SHUTDOWN_NOT_DONE;
                    WOLFSSL_LEAVE("wolfSSL_shutdown", ret);
                    return ret;
                }
                else {
                    ssl->options.shutdownDone = 1;
                    ret = WOLFSSL_SUCCESS;
                }
            }
        }

        /* try to send close notify, not an error if can't */
        if (!ssl->options.isClosed && !ssl->options.connReset &&
                                      !ssl->options.sentNotify) {
            ssl->error = SendAlert(ssl, alert_warning, close_notify);

            /* the alert is now sent or sitting in the buffer,
             * where will be sent eventually */
            if (ssl->error == 0 || ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))
                ssl->options.sentNotify = 1;

            if (ssl->error < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }

            if (ssl->options.closeNotify) {
                ret = WOLFSSL_SUCCESS;
                ssl->options.shutdownDone = 1;
            }
            else {
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
                WOLFSSL_LEAVE("wolfSSL_shutdown", ret);
                return ret;
            }
        }

#ifdef WOLFSSL_SHUTDOWNONCE
        if (ssl->options.isClosed || ssl->options.connReset) {
            /* Shutdown has already occurred.
             * Caller is free to ignore this error. */
            return SSL_SHUTDOWN_ALREADY_DONE_E;
        }
#endif

        /* wolfSSL_shutdown called again for bidirectional shutdown */
        if (ssl->options.sentNotify && !ssl->options.closeNotify) {
            /* If there is still buffered application data waiting to be read,
             * do not process incoming records here. clearOutputBuffer.buffer
             * points into inputBuffer, and ProcessReply() may call
             * GrowInputBuffer(), which frees and reallocates inputBuffer.
             * Require the pending data to be drained first. */
            if (ssl->buffers.clearOutputBuffer.length > 0) {
                WOLFSSL_MSG("Pending application data, read it before shutdown");
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
                WOLFSSL_LEAVE("wolfSSL_shutdown", ret);
                return ret;
            }
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

/*
 * TODO This ssl parameter needs to be changed to const once our ABI checker
 *      stops flagging qualifier additions as ABI breaking.
 */
WOLFSSL_ABI
int wolfSSL_pending(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_pending");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    return (int)ssl->buffers.clearOutputBuffer.length;
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
    WOLFSSL_ENTER("wolfSSL_has_pending");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    return ssl->buffers.clearOutputBuffer.length > 0;
}

#ifndef USE_WINDOWS_API
    #if !defined(NO_WRITEV) && !defined(NO_TLS)

        /* simulate writev semantics, doesn't actually do block at a time though
           because of SSL_write behavior and because front adds may be small */
        int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov, int iovcnt)
        {
        #ifdef WOLFSSL_SMALL_STACK
            byte   staticBuffer[1]; /* force heap usage */
        #else
            byte   staticBuffer[FILE_BUFFER_SIZE];
        #endif
            byte* myBuffer  = staticBuffer;
            int   dynamic   = 0;
            size_t sending   = 0;
            size_t idx       = 0;
            int   i;
            int   ret;

            WOLFSSL_ENTER("wolfSSL_writev");

            for (i = 0; i < iovcnt; i++)
                if (! WC_SAFE_SUM_UNSIGNED(size_t, sending, iov[i].iov_len,
                                           sending))
                    return BUFFER_E;

            if (sending > sizeof(staticBuffer)) {
                myBuffer = (byte*)XMALLOC(sending, ssl->heap,
                                          DYNAMIC_TYPE_WRITEV);
                if (!myBuffer)
                    return MEMORY_ERROR;

                dynamic = 1;
            }

            for (i = 0; i < iovcnt; i++) {
                XMEMCPY(&myBuffer[idx], iov[i].iov_base, iov[i].iov_len);
                idx += (int)iov[i].iov_len;
            }

           /* myBuffer may not be initialized fully, but the span up to the
            * sending length will be.
            */
            PRAGMA_GCC_DIAG_PUSH
            PRAGMA_GCC("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
            ret = wolfSSL_write_internal(ssl, myBuffer, sending);
            PRAGMA_GCC_DIAG_POP

            if (dynamic)
                XFREE(myBuffer, ssl->heap, DYNAMIC_TYPE_WRITEV);

            return ret;
        }
    #endif
#endif

#ifdef OPENSSL_EXTRA
/* returns SSL_WRITING, SSL_READING or SSL_NOTHING */
int wolfSSL_want(WOLFSSL* ssl)
{
    int rw_state = WOLFSSL_NOTHING;
    if (ssl) {
        if (ssl->error == WC_NO_ERR_TRACE(WANT_READ))
            rw_state = WOLFSSL_READING;
        else if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))
            rw_state = WOLFSSL_WRITING;
    }
    return rw_state;
}
#endif

/* return TRUE if current error is want read */
int wolfSSL_want_read(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_want_read");
    if (ssl->error == WC_NO_ERR_TRACE(WANT_READ))
        return 1;

    return 0;
}

/* return TRUE if current error is want write */
int wolfSSL_want_write(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_want_write");
    if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))
        return 1;

    return 0;
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

    if (ssl) {
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
            if (ssl->options.sentNotify)
                isShutdown |= WOLFSSL_SENT_SHUTDOWN;
            if (ssl->options.closeNotify||ssl->options.connReset)
                isShutdown |= WOLFSSL_RECEIVED_SHUTDOWN;
        }

    }

    WOLFSSL_LEAVE("wolfSSL_get_shutdown", isShutdown);
    return isShutdown;
}

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_SSL_API_RW_INCLUDED */
