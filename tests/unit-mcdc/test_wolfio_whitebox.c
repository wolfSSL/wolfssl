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


/* --------------------------------------------------------- wolfIO_DecodeUrl */
/* The URL splitter: scheme, host, port, path, with a bracketed IPv6 form and
 * hard caps on every field. It is reachable from tests/api, but only with the
 * URLs an OCSP responder extension actually carries -- well-formed, http://,
 * host and path present. The operands that matter here are the malformed ones:
 * an unterminated bracket, a CR or LF smuggled into the host, a host or port
 * that hits the length cap, a port with no digits. Those are attacker-supplied
 * and have no independence pair from a parsed certificate.
 *
 * MAX_URL_ITEM_SIZE is private to src/wolfio.c, which is another reason this
 * belongs in a white-box: the API test that covers the same function has to
 * mirror the constant and hope it stays in step. */
static void wb_decode_url(void)
{
    char name[MAX_URL_ITEM_SIZE];
    char path[MAX_URL_ITEM_SIZE];
    word16 port;
    size_t i;

    /* A host and a port at exactly the cap, built rather than written out. */
    static char longHost[MAX_URL_ITEM_SIZE + 32];
    static char longUrl[MAX_URL_ITEM_SIZE + 64];

    static const struct { const char* url; int sz; const char* what; } rows[] = {
        { "http://example.com:8080/ocsp", 28, "the ordinary case" },
        { "example.com:8080/ocsp",        21, "no scheme" },
        { "http://example.com/ocsp",      23, "no port" },
        { "http://example.com",           18, "no port, no path" },
        { "http://[::1]:443/",            17, "bracketed IPv6" },
        { "http://[::1]/",                13, "bracketed IPv6, no port" },
        { "http://[::1",                  11, "bracket never closed" },
        { "http://[",                      8, "bracket, then nothing" },
        { "http://[::1\r]:443/",          18, "CR inside the brackets" },
        { "http://[::1\n]:443/",          18, "LF inside the brackets" },
        { "http://exa\rmple.com/",        20, "CR inside the host" },
        { "http://exa\nmple.com/",        20, "LF inside the host" },
        { "http://example.com:/",         20, "colon, no digits" },
        { "http://example.com:99999999/", 28, "port longer than the field" },
        { "http://example.com:0/",        21, "port zero" },
        { "http://example.com:65535/",    25, "port at the 16-bit ceiling" },
        { "http://example.com:65536/",    25, "port past the ceiling" },
        { "http://example.com:80x/",      23, "non-digit in the port" },
        { "http://",                       7, "scheme and nothing else" },
        { "/",                             1, "a bare path" },
        { "http://example.com/ocsp",       7, "length stops inside the host" },
        { "http://example.com/ocsp",      19, "length stops at the path" },
    };

    /* url NULL and urlSz 0 are the two operands of the first guard, and each
     * out-parameter is optional, so the NULL-check on each has to be paired. */
    WB_NOTE(wolfIO_DecodeUrl(NULL, 10, name, path, &port));
    WB_NOTE(wolfIO_DecodeUrl("http://a/", 0, name, path, &port));
    WB_NOTE(wolfIO_DecodeUrl(NULL, 10, NULL, NULL, NULL));
    WB_NOTE(wolfIO_DecodeUrl("http://example.com:80/x", 23, NULL, path, &port));
    WB_NOTE(wolfIO_DecodeUrl("http://example.com:80/x", 23, name, NULL, &port));
    WB_NOTE(wolfIO_DecodeUrl("http://example.com:80/x", 23, name, path, NULL));

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        XMEMSET(name, 0, sizeof(name));
        XMEMSET(path, 0, sizeof(path));
        port = 0;
        WB_NOTE(wolfIO_DecodeUrl(rows[i].url, rows[i].sz, name, path, &port));
    }

    /* A host longer than MAX_URL_ITEM_SIZE, so the cap operand -- not the
     * delimiter and not the length -- is what stops the copy. */
    XMEMSET(longHost, 'a', sizeof(longHost) - 1);
    longHost[sizeof(longHost) - 1] = 0;
    XSTRNCPY(longUrl, "http://", sizeof(longUrl));
    XSTRNCAT(longUrl, longHost, sizeof(longUrl) - XSTRLEN(longUrl) - 1);
    WB_NOTE(wolfIO_DecodeUrl(longUrl, (int)XSTRLEN(longUrl), name, path, &port));

    /* the same, bracketed, so the IPv6 loop hits its own cap */
    XSTRNCPY(longUrl, "http://[", sizeof(longUrl));
    XSTRNCAT(longUrl, longHost, sizeof(longUrl) - XSTRLEN(longUrl) - 1);
    WB_NOTE(wolfIO_DecodeUrl(longUrl, (int)XSTRLEN(longUrl), name, path, &port));
}

/* ------------------------------------------------------- wolfIO_UrlHasCrlf */
static void wb_url_crlf(void)
{
    WB_NOTE(wolfIO_UrlHasCrlf("http://example.com/", (int)XSTRLEN("http://example.com/")));
    WB_NOTE(wolfIO_UrlHasCrlf("http://example.com/\r\n", (int)XSTRLEN("http://example.com/\r\n")));
    WB_NOTE(wolfIO_UrlHasCrlf("http://exa\rmple.com/", (int)XSTRLEN("http://exa\rmple.com/")));
    WB_NOTE(wolfIO_UrlHasCrlf("http://exa\nmple.com/", (int)XSTRLEN("http://exa\nmple.com/")));
    WB_NOTE(wolfIO_UrlHasCrlf("", (int)XSTRLEN("")));
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
    wb_decode_url();
    wb_url_crlf();

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
