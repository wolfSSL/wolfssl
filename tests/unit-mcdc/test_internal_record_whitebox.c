/* test_internal_record_whitebox.c -- MC/DC white-box driver for
 * GetRecordHeader in src/internal.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* GetRecordHeader is the first thing that looks at bytes off the wire: five
 * bytes of type, version and length, before any key or MAC is involved. Its
 * decisions are the version-mismatch tolerance rules -- which peer, in which
 * handshake state, is allowed to send which version -- and the length and
 * record-type checks that follow.
 *
 * From tests/api, the header always arrives from wolfSSL's own record writer,
 * so rh->pvMajor and rh->pvMinor equal ssl->version on every call and the
 * entire mismatch block is dead. Its operands -- downgrade, connectState,
 * acceptState, dtls, the alert-before-negotiation carve-out -- are only
 * evaluated for a header the local writer would never produce. That is the
 * definition of a condition the black box cannot pair.
 *
 * The fixture is five bytes and a struct. ssl->buffers.inputBuffer.buffer is
 * just a pointer, so it can point at a local array; GetRecordHeader reads
 * RECORD_HEADER_SZ bytes from it and writes only through its out-parameters.
 * Nothing is allocated, nothing is owned, nothing is freed -- which is what
 * distinguishes this from the fixtures in this campaign that crashed: those
 * handed stack objects to a callee that stored them.
 *
 * Vectors are one flip at a time from an ACCEPTING baseline -- a well-formed
 * record for the configured version -- because that is what gives each operand
 * its pair. Sweeping from saturated ends measured a third as much on the
 * sibling driver: both ends get refused before the interesting decision is
 * reached.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - Bail paths print, so "covered nothing" differs from "nothing to say".
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)

static int g_calls;

/* Room for a DTLS record header (13 bytes) as well as a TLS one (5). */
static byte g_input[64];

/* The mutable state GetRecordHeader consults, as data rather than as a
 * sequence of assignments, so a vector is one row and one changed field. */
typedef struct {
    byte type;          /* rh->type            */
    byte pvMajor;       /* rh->pvMajor         */
    byte pvMinor;       /* rh->pvMinor         */
    word16 len;         /* rh->length          */
    byte verMinor;      /* ssl->version.minor  */
    byte side;
    byte downgrade;
    byte handShakeDone;
    byte dtls;
    byte usingCompression;
    byte connectState;
    byte acceptState;
    byte curEpoch;
    byte dtlsEpoch;
    const char* what;
} Rec;

static void wb_record(const Rec* r, WOLFSSL* ssl)
{
    RecordLayerHeader rh;
    word32 idx = 0;
    word16 size = 0;

    XMEMSET(g_input, 0, sizeof(g_input));
    g_input[0] = r->type;
    g_input[1] = r->pvMajor;
    g_input[2] = r->pvMinor;
#ifdef WOLFSSL_DTLS
    if (r->dtls) {
        /* RFC 6347 4.1: epoch at 3-4 and a 48-bit sequence at 5-10 sit
         * between the version and the length, so a DTLS row must put the
         * length at 11-12. Writing it at 3-4 made every DTLS row declare a
         * zero length and carry the intended length as an epoch. */
        g_input[3]  = 0;
        g_input[4]  = r->curEpoch;   /* the epoch the record claims */
        g_input[11] = (byte)(r->len >> 8);
        g_input[12] = (byte)(r->len & 0xff);
    }
    else
#endif
    {
        g_input[3] = (byte)(r->len >> 8);
        g_input[4] = (byte)(r->len & 0xff);
    }

    ssl->buffers.inputBuffer.buffer = g_input;
    ssl->buffers.inputBuffer.bufferSize = (word32)sizeof(g_input);
    ssl->buffers.inputBuffer.length = (word32)sizeof(g_input);
    ssl->buffers.inputBuffer.idx = 0;

    ssl->version.major = SSLv3_MAJOR;
    ssl->version.minor = r->verMinor;
    ssl->options.side = r->side;
    ssl->options.downgrade = r->downgrade;
    ssl->options.handShakeDone = r->handShakeDone;
    ssl->options.usingCompression = r->usingCompression;
    ssl->options.connectState = r->connectState;
    ssl->options.acceptState = r->acceptState;
#ifdef WOLFSSL_DTLS
    ssl->options.dtls = r->dtls;
    ssl->keys.curEpoch = r->curEpoch;
    ssl->keys.dtls_epoch = r->dtlsEpoch;
#else
    (void)r->dtls; (void)r->curEpoch; (void)r->dtlsEpoch;
#endif

    XMEMSET(&rh, 0, sizeof(rh));
    (void)GetRecordHeader(ssl, &idx, &rh, &size);
    g_calls++;
}

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
struct wb_transport {
    int remaining;
    int calls;
};

static int wb_send_retry(WOLFSSL* ssl, char* data, int size, void* context)
{
    struct wb_transport* test = (struct wb_transport*)context;

    (void)ssl;
    test->calls++;
    if (test->remaining-- > 0)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return size == 1 && data[0] == 'T' ? size : WOLFSSL_CBIO_ERR_GENERAL;
}

static int wb_receive_retry(WOLFSSL* ssl, char* data, int size, void* context)
{
    struct wb_transport* test = (struct wb_transport*)context;

    (void)ssl;
    test->calls++;
    if (test->remaining-- > 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    if (size != 1)
        return WOLFSSL_CBIO_ERR_GENERAL;
    data[0] = 'T';
    return size;
}

static int wb_transport_retry(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    static const struct {
        byte autoRetry;
        byte handshakeDone;
        byte dtls;
        int blocked;
        int calls;
        int succeeds;
    } cases[] = {
        { 1, 0, 0, 1, 2, 1 },
        { 0, 0, 0, 1, 1, 0 },
        { 1, 1, 0, 1, 1, 0 },
#ifdef WOLFSSL_DTLS
        { 1, 0, 1, 1, 1, 0 },
#endif
        { 1, 0, 0, WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS + 1,
            WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS + 1, 0 }
    };
    int saved = ctx->autoRetry;
    int failed = 0;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct wb_transport send = { cases[i].blocked, 0 };
        struct wb_transport receive = { cases[i].blocked, 0 };
        byte payload = 'T';
        byte result = 0;

        XMEMSET(ssl, 0, sizeof(*ssl));
        ssl->ctx = ctx;
        ctx->autoRetry = cases[i].autoRetry;
        ssl->options.handShakeDone = cases[i].handshakeDone;
        ssl->options.dtls = cases[i].dtls;
        ssl->CBIOSend = wb_send_retry;
        ssl->CBIORecv = wb_receive_retry;
        ssl->IOCB_WriteCtx = &send;
        ssl->IOCB_ReadCtx = &receive;
        ssl->buffers.outputBuffer.buffer = &payload;
        ssl->buffers.outputBuffer.length = 1;
        ssl->buffers.outputBuffer.bufferSize = 1;

        if (SendBuffered(ssl) != (cases[i].succeeds ? 0 : WANT_WRITE) ||
            send.calls != cases[i].calls ||
            ssl->buffers.outputBuffer.length != (cases[i].succeeds ? 0 : 1))
            failed = 1;
        if (wolfSSLReceive(ssl, &result, 1) !=
            (cases[i].succeeds ? 1 : WANT_READ) ||
            receive.calls != cases[i].calls ||
            result != (cases[i].succeeds ? 'T' : 0))
            failed = 1;
    }
    ctx->autoRetry = (byte)saved;
    return failed;
}
static int wb_input_buffer(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    static const byte data[] = { 0x31, 0x32, 0x33 };
    bufferStatic* input = &ssl->buffers.inputBuffer;
    int failed = 1;

    XMEMSET(ssl, 0, sizeof(*ssl));
    ssl->ctx = ctx;
    ssl->options.processReply = doProcessInit;
    input->buffer = input->staticBuffer;
    input->bufferSize = STATIC_BUFFER_LEN;
    if (STATIC_BUFFER_LEN < sizeof(data))
        return 0;
    XMEMCPY(input->buffer, data, sizeof(data));
    input->length = sizeof(data);
    input->idx = 1;

    if (GrowInputBuffer(ssl, 1, -1) != BAD_FUNC_ARG ||
        GrowInputBuffer(ssl, -1, 1) != BAD_FUNC_ARG ||
        GrowInputBuffer(ssl, STATIC_BUFFER_LEN, sizeof(data) - 1) != 0)
        goto done;
    if (!input->dynamicFlag || input->idx != 0 ||
        input->length != sizeof(data) - 1 ||
        XMEMCMP(input->buffer, data + 1, sizeof(data) - 1) != 0)
        goto done;

    /* Moving buffered input while processing its record would change the
     * offsets that the parser still owns. */
    ssl->options.processReply = getRecordLayerHeader;
    ShrinkInputBuffer(ssl, NO_FORCED_FREE);
    if (!input->dynamicFlag)
        goto done;

    ssl->options.processReply = doProcessInit;
    ShrinkInputBuffer(ssl, NO_FORCED_FREE);
    if (input->dynamicFlag || input->buffer != input->staticBuffer ||
        input->length != sizeof(data) - 1 ||
        XMEMCMP(input->buffer, data + 1, sizeof(data) - 1) != 0)
        goto done;
    failed = 0;

done:
    if (input->dynamicFlag)
        ShrinkInputBuffer(ssl, FORCED_FREE);
    return failed;
}

#endif

int main(void)
{
    int failed = 0;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    size_t i;

    /* The accepting baseline: a well-formed TLS 1.2 handshake record. Every
     * row below is this with one field changed, so each operand it flips has
     * this row as its independence partner. */
    const Rec base = { handshake, SSLv3_MAJOR, TLSv1_2_MINOR, 16,
                       TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0, 0, 0, 0, 0, 0,
                       0, 0, "baseline" };

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal record white-box: wolfSSL_Init failed\n");
        goto done;
    }
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("internal record white-box: CTX_new failed\n");
        goto done;
    }
    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("internal record white-box: out of memory\n");
        goto done;
    }

    {
        /* Each row names the operand it exists to flip. A row is the baseline
         * with one field changed; where a decision needs two fields to be
         * reached at all (a mismatched version AND a state), the row says so. */
        Rec rows[] = {
            /* record type: the switch, and each accepted arm */
            { change_cipher_spec, SSLv3_MAJOR, TLSv1_2_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "ccs" },
            { application_data, SSLv3_MAJOR, TLSv1_2_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "app data" },
            { alert, SSLv3_MAJOR, TLSv1_2_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "alert" },
            { no_type, SSLv3_MAJOR, TLSv1_2_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "no_type" },
            { 0x47 /* 'G', a plain HTTP GET */, 0x45, 0x54, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "HTTP GET" },

            /* zero length: refused for everything except application data,
             * which is the partner for that operand */
            { handshake, SSLv3_MAJOR, TLSv1_2_MINOR, 0,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "0-len hs" },
            { application_data, SSLv3_MAJOR, TLSv1_2_MINOR, 0,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "0-len app" },

            /* over-length, with and without compression, which changes the
             * allowance the comparison is made against */
            { handshake, SSLv3_MAJOR, TLSv1_2_MINOR, 0xFFFF,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0, "too long" },
            { handshake, SSLv3_MAJOR, TLSv1_2_MINOR, 0xFFFF,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,1,0,0,0,0,
              "too long, compressed" },

            /* --- the version-mismatch block, unreachable from tests/api --- */

            /* major differs: the first operand alone */
            { handshake, 0x7F, TLSv1_2_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0,
              "major mismatch" },
            /* minor differs, we are not TLS 1.3: no carve-out applies */
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0,
              "minor mismatch" },
            /* minor differs but equals tls12minor while we are TLS 1.3: the
             * partner that makes the third operand of the mismatch decision
             * matter */
            { handshake, SSLv3_MAJOR, TLSv1_2_MINOR, 16,
              TLSv1_3_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0,
              "1.3 accepting a 1.2 record version" },
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_3_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0,
              "1.3 refusing an older record version" },

            /* server before its first reply is allowed a different version */
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_SERVER_END, 0,0,0,0,0,0,0,0,
              "server, acceptState 0" },
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_SERVER_END, 0,0,0,0,0,
              ACCEPT_THIRD_REPLY_DONE, 0,0, "server, past first reply" },

            /* client with downgrade before its first reply likewise; the two
             * rows below pair the downgrade operand and the state operand */
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 1,0,0,0,0,0,0,0,
              "client downgrade, connectState 0" },
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,0,0,0,0,
              "client without downgrade" },
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 1,0,0,0,
              FIRST_REPLY_DONE, 0,0,0, "client downgrade, past first reply" },

            /* the alert carve-out: an alert sent back before the version is
             * negotiated is tolerated. Four operands, one row each. */
            { alert, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,
              CLIENT_HELLO_SENT, 0,0,0, "alert after ClientHello" },
            { alert, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,
              CONNECT_BEGIN, 0,0,0, "alert in the wrong state" },
            { alert, 0x7F, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,
              CLIENT_HELLO_SENT, 0,0,0, "alert, major also differs" },
            { handshake, SSLv3_MAJOR, TLSv1_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,
              CLIENT_HELLO_SENT, 0,0,0, "not an alert" },
            { alert, SSLv3_MAJOR, TLSv1_3_MINOR, 16,
              TLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,0,0,
              CLIENT_HELLO_SENT, 0,0,0, "alert, minor not lower" },

#ifdef WOLFSSL_DTLS
            /* DTLS: the replay window and epoch checks, which have no pair on
             * a TLS connection at all. The header bytes are re-read by
             * GetDtlsRecordHeader from the same buffer. */
            { handshake, DTLS_MAJOR, DTLSv1_2_MINOR, 16,
              DTLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,1,0,0,0,0,0, "dtls hs" },
            { application_data, DTLS_MAJOR, DTLSv1_2_MINOR, 16,
              DTLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,1,0,0,0,0,0,
              "dtls app data, epoch 0" },
            { application_data, DTLS_MAJOR, DTLSv1_2_MINOR, 16,
              DTLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,1,0,0,0,1,1,
              "dtls app data, epoch 1" },
            { alert, DTLS_MAJOR, DTLSv1_2_MINOR, 16,
              DTLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,1,1,0,0,0,0,1,
              "dtls alert after handshake, epoch 0" },
            { alert, DTLS_MAJOR, DTLSv1_2_MINOR, 16,
              DTLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,1,0,0,0,0,1,
              "dtls alert during handshake" },
            { handshake, DTLS_MAJOR, DTLS_MINOR, 16,
              DTLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,1,0,0,0,0,0,
              "dtls 1.3 record version" },
            { handshake, 0x7F, DTLSv1_2_MINOR, 16,
              DTLSv1_2_MINOR, WOLFSSL_CLIENT_END, 0,0,1,0,0,0,0,0,
              "dtls major mismatch" },
#endif
        };

        XMEMSET(ssl, 0, sizeof(*ssl));
        ssl->ctx = ctx;
        wb_record(&base, ssl);

        for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            /* A fresh zeroed ssl per row: GetRecordHeader advances the DTLS
             * replay window, so a row must not inherit the last row's state. */
            XMEMSET(ssl, 0, sizeof(*ssl));
            ssl->ctx = ctx;
            wb_record(&rows[i], ssl);
            /* the baseline again, so every row has its partner adjacent in
             * the trace as well as in the argument */
            XMEMSET(ssl, 0, sizeof(*ssl));
            ssl->ctx = ctx;
            wb_record(&base, ssl);
        }
    }

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_transport_retry(ctx, ssl)) {
        puts("internal record white-box: unexpected transport retry result");
        failed = 1;
    }
    if (wb_input_buffer(ctx, ssl)) {
        puts("internal record white-box: unexpected input buffer result");
        failed = 1;
    }
#endif

    printf("internal record white-box: %d GetRecordHeader calls\n", g_calls);

done:
    XFREE(ssl, NULL, DYNAMIC_TYPE_SSL);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return failed;
}

#else

int main(void)
{
    printf("internal record white-box: skipped (TLS not built)\n");
    return 0;
}

#endif
