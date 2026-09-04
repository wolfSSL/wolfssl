/* test_internal_clienthello_whitebox.c -- MC/DC white-box driver for
 * DoClientHello in src/internal.c
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

/* FORGED FRAMES INSTEAD OF A HANDSHAKE.
 *
 * The leaf-function white-boxes in this directory have run out of leaves. What
 * is left in internal.c is message handling, and the obvious way to reach it
 * -- stand up two endpoints and run handshakes -- is both expensive and, for
 * MC/DC, mostly useless: two conforming endpoints produce one ClientHello
 * shape, so every operand that distinguishes a hostile hello from a friendly
 * one is evaluated the same way every time.
 *
 * The cheaper move is to forge the frame. DoClientHello takes a byte buffer
 * and a length; it does not take a socket, a peer, or a handshake. So the
 * fixture is a REAL server WOLFSSL -- from a CTX with a certificate loaded, so
 * suites, hashes and buffers are all properly constructed -- fed a
 * hand-assembled ClientHello body. Real endpoint, forged input. Nothing on the
 * wire, nothing to synchronise, and each vector differs from its partner in
 * exactly the byte or flag under test.
 *
 * That is what reaches the decisions the handshake tests cannot: a version
 * below the configured minimum, a compression list with no null method, a
 * session id where a cookie is expected, a renegotiation info extension on a
 * connection that never renegotiated, an extension set that contradicts the
 * options the server was configured with.
 *
 * A send callback is installed because several of these paths answer with a
 * fatal alert; without one the alert path dereferences a NULL CBIOSend.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Bail paths print, so "covered nothing" differs from "nothing to say".
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)

static int g_calls;

static int wb_send_sink(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)buf; (void)ctx;
    return sz;              /* swallow alerts, report them fully written */
}

static int wb_recv_none(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)buf; (void)sz; (void)ctx;
    return WOLFSSL_CBIO_ERR_WANT_READ;
}

/* ------------------------------------------------------------- the forger */

typedef struct {
    byte  buf[768];
    word32 len;
} Frame;

static void fr_reset(Frame* f)   { XMEMSET(f, 0, sizeof(*f)); }
static void fr_u8(Frame* f, byte v)
{
    if (f->len < sizeof(f->buf)) f->buf[f->len++] = v;
}
static void fr_u16(Frame* f, word16 v) { fr_u8(f, (byte)(v >> 8));
                                         fr_u8(f, (byte)(v & 0xff)); }
static void fr_fill(Frame* f, byte v, int n)
{
    int i; for (i = 0; i < n; i++) fr_u8(f, v);
}

/* What a forged ClientHello may differ in. Each field exists because some
 * decision in DoClientHello reads it. */
typedef struct {
    byte  major, minor;      /* the offered version                      */
    int   sessionIdLen;      /* 0, 32, or an illegal length              */
    int   cookieLen;         /* DTLS only                                */
    int   nSuites;           /* cipher suite count (in suites, not bytes)*/
    int   suiteBogus;        /* offer suites the server cannot match     */
    int   compNo;            /* offer the null compression method        */
    int   compZlib;          /* offer zlib                               */
    int   extReneg;          /* renegotiation_info                       */
    int   extTicket;         /* session_ticket                           */
    int   extEtm;            /* encrypt_then_mac                         */
    int   extEms;            /* extended_master_secret                   */
    int   extTruncate;       /* declare more extension bytes than follow */
    const char* what;
} Hello;

/* The suites the SERVER was configured with, echoed back. A forged hello with
 * invented suite bytes fails MatchSuite and returns before the compression,
 * extension and downgrade logic is ever reached -- which is what the first
 * version of this driver did, and why it measured almost nothing. Reading
 * ssl->suites is the difference between a frame that is refused at the door
 * and one that gets deep enough for its one forged field to matter. */
static void wb_build(Frame* f, const Hello* h, int dtls, const WOLFSSL* ssl)
{
    fr_reset(f);
    fr_u8(f, h->major);
    fr_u8(f, h->minor);
    fr_fill(f, 0xAB, RAN_LEN);                 /* client random */

    fr_u8(f, (byte)h->sessionIdLen);
    fr_fill(f, 0xCD, h->sessionIdLen);

    if (dtls) {
        fr_u8(f, (byte)h->cookieLen);
        fr_fill(f, 0xEF, h->cookieLen);
    }

    {
        int have = (ssl->suites != NULL) ? ssl->suites->suiteSz / 2 : 0;
        int n = h->nSuites;
        int i;

        if (!h->suiteBogus && n > have)
            n = have;
        fr_u16(f, (word16)(n * 2));
        for (i = 0; i < n; i++) {
            if (h->suiteBogus) {
                fr_u8(f, 0x00); fr_u8(f, (byte)(0xF0 + i));
            }
            else {
                fr_u8(f, ssl->suites->suites[i * 2]);
                fr_u8(f, ssl->suites->suites[i * 2 + 1]);
            }
        }
    }

    {
        int n = (h->compNo ? 1 : 0) + (h->compZlib ? 1 : 0);
        fr_u8(f, (byte)n);
        if (h->compZlib) fr_u8(f, ZLIB_COMPRESSION);
        if (h->compNo)   fr_u8(f, NO_COMPRESSION);
    }

    /* extensions, assembled into a scratch frame first so the length is
     * known before it is written */
    {
        Frame ext;
        fr_reset(&ext);
        if (h->extReneg) {
            fr_u16(&ext, TLSX_RENEGOTIATION_INFO);
            fr_u16(&ext, 1);
            fr_u8(&ext, 0);                    /* empty renegotiated_connection */
        }
        if (h->extTicket) {
            fr_u16(&ext, TLSX_SESSION_TICKET);
            fr_u16(&ext, 0);
        }
        if (h->extEtm) {
            fr_u16(&ext, TLSX_ENCRYPT_THEN_MAC);
            fr_u16(&ext, 0);
        }
        if (h->extEms) {
            fr_u16(&ext, HELLO_EXT_EXTMS);
            fr_u16(&ext, 0);
        }
        if (ext.len > 0 || h->extTruncate) {
            word32 i;
            fr_u16(f, (word16)(h->extTruncate ? ext.len + 16 : ext.len));
            for (i = 0; i < ext.len; i++)
                fr_u8(f, ext.buf[i]);
        }
    }
}

/* -------------------------------------------------------------- one vector */

/* The ssl is rebuilt per vector: DoClientHello writes session state, suites
 * and extension lists into it, and a second hello on the same object would be
 * a renegotiation rather than the case under test. */
static void wb_hello(WOLFSSL_CTX* ctx, const Hello* h, int dtls,
                     int usingCompression, int useTicket, int encThenMac,
                     int downgrade, byte minDowngrade)
{
    WOLFSSL* ssl = wolfSSL_new(ctx);
    Frame f;
    word32 idx = 0;

    if (ssl == NULL)
        return;

    wolfSSL_SSLSetIORecv(ssl, wb_recv_none);
    wolfSSL_SSLSetIOSend(ssl, wb_send_sink);

    ssl->options.side = WOLFSSL_SERVER_END;
    ssl->options.usingCompression = (byte)usingCompression;
    ssl->options.useTicket = (byte)useTicket;
    ssl->options.encThenMac = (byte)encThenMac;
    ssl->options.downgrade = (byte)downgrade;
    ssl->options.minDowngrade = minDowngrade;
#ifdef WOLFSSL_DTLS
    ssl->options.dtls = (byte)dtls;
    if (dtls) {
        ssl->version.major = DTLS_MAJOR;
        ssl->version.minor = DTLSv1_2_MINOR;
        ssl->options.dtlsStateful = 1;
    }
#endif

    wb_build(&f, h, dtls, ssl);
    {
        int r = DoClientHello(ssl, f.buf, &idx, f.len);
        if (getenv("WB_TRACE"))
            printf("  %-52s -> %d (idx %u of %u)\n", h->what, r,
                   (unsigned)idx, (unsigned)f.len);
    }
    g_calls++;

    wolfSSL_free(ssl);
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    size_t i;
    int dtls;

    /* The accepting baseline, then one field changed per row. A conforming
     * client sends the first row and nothing else; every other row is a hello
     * a server must survive but no test peer produces. */
    static const Hello rows[] = {
     /* maj          min             sid ck ns bog no zl rg tk em ems tr what */
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "baseline TLS 1.2" },
      { SSLv3_MAJOR, TLSv1_3_MINOR,   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "offers 1.3 in the legacy field" },
      { SSLv3_MAJOR, TLSv1_1_MINOR,   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "offers 1.1" },
      { SSLv3_MAJOR, TLSv1_MINOR,     0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "offers 1.0" },
      { SSLv3_MAJOR, SSLv3_MINOR,     0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "offers SSLv3" },
      { 0x02,        0x00,            0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "a major version from no protocol" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,  32, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "carries a session id" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,  64, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "session id longer than the field allows" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        "offers only suites the server has not got" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        "offers no cipher suites at all" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0,64, 0, 1, 0, 0, 0, 0, 0, 0,
        "offers sixty-four suites" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0,
        "zlib only: no null compression method" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0,
        "both compression methods" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        "an empty compression list" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0,
        "renegotiation_info on a fresh connection" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0,
        "asks for a session ticket" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0,
        "asks for encrypt-then-mac" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0,
        "asks for extended master secret" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0,
        "asks for everything at once" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1,
        "extension length longer than the extensions" },
      { SSLv3_MAJOR, TLSv1_2_MINOR,  32, 8, 1, 0, 1, 0, 0, 0, 0, 0, 0,
        "session id and a cookie" },
    };

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal clienthello white-box: wolfSSL_Init failed\n");
        goto done;
    }

    /* A server CTX with a real certificate: wolfSSL_new returns NULL for a
     * server with no certificate loaded, and a NULL ssl is how an earlier
     * white-box in this campaign silently covered nothing while exiting 0. */
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    if (ctx == NULL) {
        printf("internal clienthello white-box: CTX_new failed\n");
        goto done;
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem",
                                         WOLFSSL_FILETYPE_PEM)
            != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem",
                                        WOLFSSL_FILETYPE_PEM)
            != WOLFSSL_SUCCESS) {
        printf("internal clienthello white-box: no server credentials, "
               "nothing driven\n");
        goto done;
    }

    /* Every hello against both compression settings and both downgrade
     * policies, so the server-side operands of each decision get their pair
     * as well as the client-side bytes. */
    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        /* downgrade on for the bulk of the sweep: with it off, any hello
         * whose version differs from the server's is refused at the version
         * check and the rest of the function is never entered. Both settings
         * still appear, so that operand keeps its pair. */
        wb_hello(ctx, &rows[i], 0, 0, 0, 0, 1, SSLv3_MINOR);
        wb_hello(ctx, &rows[i], 0, 1, 0, 0, 1, SSLv3_MINOR);
        wb_hello(ctx, &rows[i], 0, 0, 1, 1, 1, SSLv3_MINOR);
        wb_hello(ctx, &rows[i], 0, 1, 1, 1, 1, SSLv3_MINOR);
        wb_hello(ctx, &rows[i], 0, 0, 0, 0, 0, TLSv1_MINOR);
        /* downgrade allowed, with a floor above what the row offers, which
         * is what belowMinDowngrade exists to detect */
        wb_hello(ctx, &rows[i], 0, 0, 0, 0, 1, TLSv1_2_MINOR);
        wb_hello(ctx, &rows[i], 0, 0, 0, 0, 1, SSLv3_MINOR);
    }

#ifdef WOLFSSL_DTLS
    for (dtls = 1; dtls < 2; dtls++)
        for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
            wb_hello(ctx, &rows[i], dtls, 0, 0, 0, 1, SSLv3_MINOR);
#else
    (void)dtls;
#endif

    printf("internal clienthello white-box: %d forged hellos\n", g_calls);

done:
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal clienthello white-box: skipped (server TLS 1.2 or "
           "certs not built)\n");
    return 0;
}

#endif
