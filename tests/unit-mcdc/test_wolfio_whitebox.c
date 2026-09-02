/* test_wolfio_whitebox.c -- MC/DC white-box driver for src/wolfio.c
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

/* WHY A WHITE-BOX, AND WHY IT NEEDS NO NETWORK.
 *
 * src/wolfio.c looks like it needs a transport, and that reading is wrong. It
 * needs two things, both of which can be supplied locally:
 *
 *   1. A BYTE SOURCE. wolfIO_HttpProcessResponseBuf and
 *      wolfIO_HttpProcessResponseGenericIO take a WolfSSLGenericIORecvCb,
 *      which is just `int (*)(char* buf, int sz, void* ctx)`. Feeding it from
 *      a memory buffer drives the whole HTTP response state machine --
 *      chunked bodies, split headers, truncated input -- with no socket at
 *      all, and lets a vector deliver bytes in exactly the fragments a real
 *      network would not reliably reproduce.
 *
 *   2. A FILE DESCRIPTOR. EmbedReceiveFrom, wolfIO_SockIsDGram and the
 *      TcpBind family want an fd, not a peer. socketpair(AF_UNIX) gives a
 *      real, connected, hermetic pair: no ports, no DNS, no listener, nothing
 *      that can collide with another test or depend on the host's network.
 *      Datagram and stream pairs are both available, which is what
 *      wolfIO_SockIsDGram's getsockopt branch needs in order to have a pair.
 *
 * The memio harness cannot reach any of this: tests/utils.c installs its own
 * IO callbacks, so Embed* is entered by no TLS or DTLS group in the tree.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Every rejecting vector has its accepting partner in THIS binary.
 *   - Bail paths print, so "covered nothing" differs from "nothing to say".
 */

#include <wolfssl/options.h>

#include <src/wolfio.c>

#include <stdio.h>
#include <string.h>

#if defined(USE_WOLFSSL_IO) && !defined(WOLFCRYPT_ONLY)

#include <sys/socket.h>
#include <unistd.h>

static int g_checks;
#define WB_NOTE(what) do { g_checks++; (void)(what); } while (0)

/* ------------------------------------------------------------- byte source */

/* A WolfSSLGenericIORecvCb backed by memory. `drip` caps how many bytes any
 * one call may return, so a vector can force the caller's reassembly loop to
 * run more than once -- the split-header and split-chunk cases that a single
 * large read never produces. */
typedef struct {
    const char* data;
    int         len;
    int         pos;
    int         drip;
    int         failAfter;   /* return -1 once this many calls have been made */
    int         calls;
} MemSrc;

static int wb_mem_recv(char* buf, int sz, void* ctx)
{
    MemSrc* m = (MemSrc*)ctx;
    int n;

    m->calls++;
    if (m->failAfter > 0 && m->calls > m->failAfter)
        return -1;              /* transport error, without a transport */
    n = m->len - m->pos;
    if (n <= 0)
        return 0;               /* clean EOF */
    if (n > sz)
        n = sz;
    if (m->drip > 0 && n > m->drip)
        n = m->drip;
    XMEMCPY(buf, m->data + m->pos, (size_t)n);
    m->pos += n;
    return n;
}

static void wb_http_response(void)
{
    static const char* kAppStr[] = { "application/ocsp-response", NULL };
    /* well formed, content-length bodied */
    static const char kOk[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "\x30\x02\x00\x00";
    /* chunked transfer encoding: exercises the chunk-length state */
    static const char kChunked[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n\x30\x02\x00\x00\r\n0\r\n\r\n";
    /* headers end before a body ever arrives */
    static const char kTruncated[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n";
    /* not HTTP at all: the protocol check rejects */
    static const char kNotHttp[] = "GARBAGE\r\n\r\n";
    /* an error status rather than 200 */
    static const char kNotFound[] =
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

    struct { const char* d; int len; int drip; int failAfter;
             const char* what; } rows[] = {
        { kOk,        (int)sizeof(kOk) - 1,        0, 0, "200 + body" },
        { kOk,        (int)sizeof(kOk) - 1,        1, 0, "200, one byte per read" },
        { kChunked,   (int)sizeof(kChunked) - 1,   0, 0, "chunked" },
        { kChunked,   (int)sizeof(kChunked) - 1,   3, 0, "chunked, split reads" },
        { kTruncated, (int)sizeof(kTruncated) - 1, 0, 0, "headers, no body" },
        { kNotHttp,   (int)sizeof(kNotHttp) - 1,   0, 0, "not HTTP" },
        { kNotFound,  (int)sizeof(kNotFound) - 1,  0, 0, "404" },
        { kOk,        (int)sizeof(kOk) - 1,        1, 2, "read error mid-body" },
    };
    size_t i;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        MemSrc src;
        byte   httpBuf[512];
        byte*  respBuf = NULL;

        XMEMSET(&src, 0, sizeof(src));
        src.data = rows[i].d;
        src.len = rows[i].len;
        src.drip = rows[i].drip;
        src.failAfter = rows[i].failAfter;

        WB_NOTE(wolfIO_HttpProcessResponseGenericIO(wb_mem_recv, &src,
                    kAppStr, &respBuf, httpBuf, (int)sizeof(httpBuf),
                    DYNAMIC_TYPE_TMP_BUFFER, NULL));
        if (respBuf != NULL)
            XFREE(respBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
}

/* --------------------------------------------------------- request builder */

/* `if (reqSz > 0 && reqSzStrLen > 0)` and the CR/LF scan in the name check.
 * Both operands need a pair, and no in-tree caller asks for a zero-length
 * request. */
static void wb_http_request(void)
{
    byte buf[512];

    WB_NOTE(wolfIO_HttpBuildRequestOcsp("example.com", "/ocsp", 4,
                                        buf, (int)sizeof(buf)));
    WB_NOTE(wolfIO_HttpBuildRequestOcsp("example.com", "/ocsp", 0,
                                        buf, (int)sizeof(buf)));
}

/* ---------------------------------------------------- descriptors, no peer */

/* socketpair gives a real connected fd pair with no port, no DNS and no
 * listener, so these vectors are hermetic and cannot collide with anything
 * else running on the host. */
static void wb_sockets(void)
{
    int sp[2];
    int dg[2];

    /* stream pair: wolfIO_SockIsDGram takes its getsockopt branch and returns
     * false; the datagram pair below is the accepting partner. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
        WB_NOTE(wolfIO_SockIsDGram(sp[0]));
        close(sp[0]);
        close(sp[1]);
    }
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dg) == 0) {
        WB_NOTE(wolfIO_SockIsDGram(dg[0]));
        close(dg[0]);
        close(dg[1]);
    }
    /* a closed descriptor makes getsockopt itself fail, which is the operand
     * that a working socket can never take. */
    WB_NOTE(wolfIO_SockIsDGram(-1));
}

/* ---------------------------------------------------------- main */

int main(void)
{
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("wolfio white-box: wolfSSL_Init failed\n");
        goto done;
    }

    wb_http_response();
    wb_http_request();
    wb_sockets();

    printf("wolfio white-box: %d vectors driven\n", g_checks);

done:
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else /* !USE_WOLFSSL_IO */

int main(void)
{
    printf("wolfio white-box: skipped (USE_WOLFSSL_IO not built)\n");
    return 0;
}

#endif
