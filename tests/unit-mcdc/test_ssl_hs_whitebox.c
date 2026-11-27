/* test_ssl_hs_whitebox.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <wolfssl/options.h>
#include <src/ssl.c>

#if !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)

static int wb_flush_send(WOLFSSL* ssl, char* data, int size, void* context)
{
    int* sent = (int*)context;

    (void)ssl;
    if (size != 1 || data[0] != 'T')
        return WOLFSSL_CBIO_ERR_GENERAL;
    *sent += size;
    return size;
}

/* The flush helpers see the stored phase after a previous call filled the
 * output buffer. Use a transport mock to verify which phase follows. */
static int wb_accept_flush(WOLFSSL* ssl)
{
    static const byte advances[] = {
        ACCEPT_FIRST_REPLY_DONE, SERVER_HELLO_SENT, CERT_SENT,
        CERT_STATUS_SENT, KEY_EXCHANGE_SENT, CERT_REQ_SENT,
        ACCEPT_SECOND_REPLY_DONE, TICKET_SENT, CHANGE_CIPHER_SENT
    };
    size_t i;

    for (i = 0; i < sizeof(advances) / sizeof(advances[0]); i++) {
        ssl->options.acceptState = advances[i];
        ssl->buffers.outputBuffer.length = 1;
        if (wolfssl_accept_flush(ssl) != 0 ||
            ssl->options.acceptState != advances[i] + 1 ||
            ssl->buffers.outputBuffer.length != 0)
            return 1;
    }

    ssl->options.acceptState = ACCEPT_BEGIN;
    ssl->buffers.outputBuffer.length = 1;
    if (wolfssl_accept_flush(ssl) != 0 ||
        ssl->options.acceptState != ACCEPT_BEGIN)
        return 1;

    ssl->options.acceptState = CERT_SENT;
    ssl->fragOffset = 1;
    ssl->buffers.outputBuffer.length = 1;
    if (wolfssl_accept_flush(ssl) != 0 || ssl->options.acceptState != CERT_SENT)
        return 1;
    ssl->fragOffset = 0;
    ssl->options.buildingMsg = 1;
    ssl->buffers.outputBuffer.length = 1;
    if (wolfssl_accept_flush(ssl) != 0 || ssl->options.acceptState != CERT_SENT)
        return 1;
    ssl->options.buildingMsg = 0;
    return 0;
}

static int wb_connect_flush(WOLFSSL* ssl)
{
    ssl->options.connectState = CONNECT_BEGIN;
    ssl->fragOffset = 1;
    ssl->buffers.outputBuffer.length = 1;
    if (wolfssl_connect_flush(ssl) != 0 ||
        ssl->options.connectState != CONNECT_BEGIN)
        return 1;
    ssl->fragOffset = 0;
    ssl->options.buildingMsg = 1;
    ssl->buffers.outputBuffer.length = 1;
    if (wolfssl_connect_flush(ssl) != 0 ||
        ssl->options.connectState != CONNECT_BEGIN)
        return 1;
    ssl->options.buildingMsg = 0;

#ifdef WOLFSSL_DTLS13
    ssl->version = MakeDTLSv1_3();
    ssl->options.dtls = 1;
    ssl->dtls13SendingAckOrRtx = 1;
    ssl->buffers.outputBuffer.length = 1;
    if (wolfssl_connect_flush(ssl) != 0 ||
        ssl->options.connectState != CONNECT_BEGIN ||
        ssl->dtls13SendingAckOrRtx != 0)
        return 1;
#endif
    ssl->buffers.outputBuffer.length = 1;
    if (wolfssl_connect_flush(ssl) != 0 ||
        ssl->options.connectState != CONNECT_BEGIN + 1)
        return 1;
    return 0;
}

int main(void)
{
    WOLFSSL* ssl;
    byte payload = 'T';
    int sent = 0;
    int failed;

    ssl = (WOLFSSL*)XMALLOC(sizeof(*ssl), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL)
        return 1;
    XMEMSET(ssl, 0, sizeof(*ssl));
    ssl->pendingAlert.level = alert_none;
    ssl->buffers.outputBuffer.buffer = &payload;
    ssl->buffers.outputBuffer.bufferSize = 1;
    ssl->CBIOSend = wb_flush_send;
    ssl->IOCB_WriteCtx = &sent;

    failed = wb_accept_flush(ssl);
    failed |= wb_connect_flush(ssl);
    if (sent == 0)
        failed = 1;
    XFREE(ssl, NULL, DYNAMIC_TYPE_SSL);
    if (failed)
        puts("ssl_api_hs white-box: unexpected buffered handshake state");
    return failed;
}

#else

int main(void)
{
    return 0;
}

#endif
