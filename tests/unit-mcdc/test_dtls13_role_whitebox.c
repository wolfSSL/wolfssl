/* test_dtls13_role_whitebox.c -- MC/DC white-box driver for the client/server
 * role decisions in src/dtls13.c
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

/* WHY ROLE DECISIONS NEED A WHITE-BOX.
 *
 * The largest remaining category in dtls.c/dtls13.c is not NULL guards, it is
 * `ssl->options.side == WOLFSSL_CLIENT_END` and its mirror. A connection has
 * exactly one side for its whole life, so every one of these decisions is
 * taken the same way on every call a given endpoint makes -- the operand never
 * varies, and no amount of handshaking or packet forgery makes it vary.
 *
 * A test that owns both endpoints does not help either: the client object
 * takes the client branch every time and the server object the server branch,
 * in two different processes' worth of state. MC/DC wants both outcomes of the
 * same decision recorded in ONE binary's profile, which means calling the
 * function twice with the side field set differently.
 *
 * That is exactly what the fixture allows. These functions read ssl->options,
 * ssl->keys and ssl->dtls13Rtx and take scalars; none of them needs a peer, a
 * transport, or a completed handshake. Setting the side by hand and sweeping
 * the message type against it pairs every operand.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Bail paths print, so "covered nothing" differs from "nothing to say".
 */

#include <wolfssl/options.h>

#include <src/dtls13.c>

#include <stdio.h>
#include <string.h>

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS) && \
    !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)

static int g_checks;
#define WB_NOTE(what) do { g_checks++; (void)(what); } while (0)

/* The handshake types these decisions discriminate on. */
static const byte kTypes[] = {
    client_hello, server_hello, hello_verify_request, hello_retry_request,
    hello_request, encrypted_extensions, certificate, certificate_verify,
    finished, session_ticket, key_update, 200 /* not a handshake type */
};

static const int kSides[2] = { WOLFSSL_CLIENT_END, WOLFSSL_SERVER_END };

/* Reset only what these functions read. Nothing is allocated or owned, so
 * there is no teardown and no ordering between vectors. */
static void wb_reset(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int side)
{
    XMEMSET(ssl, 0, sizeof(*ssl));
    ssl->ctx = ctx;
    ssl->version.major = DTLS_MAJOR;
    ssl->version.minor = DTLS_MINOR;      /* DTLS 1.3 */
    ssl->options.side = (byte)side;
    ssl->options.dtls = 1;
}

/* ------------------------------------------------ Dtls13AcceptFragmented

 * `side == CLIENT_END && type == server_hello` and, under CH fragmentation,
 * `side == SERVER_END && type == client_hello && dtls13ChFrag && dtlsStateful`.
 * Four operands across two decisions; the side operand of each is constant on
 * any real connection. */
static void wb_accept_fragmented(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    size_t t;
    int s, enc, frag, stateful;

    for (s = 0; s < 2; s++) {
        for (t = 0; t < sizeof(kTypes) / sizeof(kTypes[0]); t++) {
            for (enc = 0; enc < 2; enc++) {
                for (frag = 0; frag < 2; frag++) {
                    for (stateful = 0; stateful < 2; stateful++) {
                        wb_reset(ssl, ctx, kSides[s]);
                        /* IsEncryptionOn reads the cipher setup flags; set
                         * them directly so the short-circuit ahead of the
                         * role test gets both values. */
                        ssl->encrypt.setup = (byte)enc;
                        ssl->options.handShakeDone = (byte)enc;
#ifdef WOLFSSL_DTLS_CH_FRAG
                        ssl->options.dtls13ChFrag = (byte)frag;
#endif
                        ssl->options.dtlsStateful = (byte)stateful;
                        WB_NOTE(Dtls13AcceptFragmented(ssl,
                                    (enum HandShakeType)kTypes[t]));
                    }
                }
            }
        }
    }
}

/* ---------------------------------------------------- Dtls13CheckEpoch

 * A switch over handshake type against the record's epoch, with the
 * client/server role deciding which epoch a given message may legally carry.
 * Sweeping (side x type x epoch) pairs every arm. */
static void wb_check_epoch(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    static const word32 kEpochs[] = { 0, DTLS13_EPOCH_EARLYDATA,
                                      DTLS13_EPOCH_HANDSHAKE,
                                      DTLS13_EPOCH_TRAFFIC0, 7 };
    size_t t, e;
    int s;

    for (s = 0; s < 2; s++) {
        for (t = 0; t < sizeof(kTypes) / sizeof(kTypes[0]); t++) {
            for (e = 0; e < sizeof(kEpochs) / sizeof(kEpochs[0]); e++) {
                wb_reset(ssl, ctx, kSides[s]);
                ssl->keys.curEpoch64 = w64From32(0x0, kEpochs[e]);
                WB_NOTE(Dtls13CheckEpoch(ssl,
                            (enum HandShakeType)kTypes[t]));
            }
        }
    }
}

/* -------------------------------------- Dtls13SaveOrFlushClientHello

 * `side == CLIENT_END && connectState >= CLIENT_HELLO_SENT &&
 *  connectState <= HELLO_AGAIN_REPLY` -- three operands, and the two state
 * bounds only matter while the side operand is true, which a server-side
 * object never makes it past. The retransmit list is left empty: the decision
 * under test is above the loop. */
static void wb_save_or_flush(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    static const byte kStates[] = {
        CONNECT_BEGIN, CLIENT_HELLO_SENT, HELLO_AGAIN, HELLO_AGAIN_REPLY,
        FIRST_REPLY_DONE, FINISHED_DONE
    };
    size_t i;
    int s;

    for (s = 0; s < 2; s++) {
        for (i = 0; i < sizeof(kStates) / sizeof(kStates[0]); i++) {
            wb_reset(ssl, ctx, kSides[s]);
            ssl->options.connectState = kStates[i];
            Dtls13SaveOrFlushClientHello(ssl);
            g_checks++;
        }
    }
}

/* ------------------------------------------------- Dtls13SetEpochKeys

 * `e->side != ENCRYPT_AND_DECRYPT_SIDE && e->side != side` -- both operands.
 * A real connection installs keys for one side at a time in a fixed order, so
 * the "already both sides" and "the other side" cases never pair. With no
 * epoch allocated the function returns early, which is itself one of the
 * outcomes; allocating one lets the comparison run. */
static void wb_set_epoch_keys(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    static const enum encrypt_side kEncSides[3] = {
        ENCRYPT_SIDE_ONLY, DECRYPT_SIDE_ONLY, ENCRYPT_AND_DECRYPT_SIDE
    };
    size_t a, b;
    int s;

    for (s = 0; s < 2; s++) {
        for (a = 0; a < 3; a++) {
            /* no epoch yet: the early-return arm */
            wb_reset(ssl, ctx, kSides[s]);
            WB_NOTE(Dtls13SetEpochKeys(ssl, w64From32(0x0, DTLS13_EPOCH_HANDSHAKE),
                                       kEncSides[a]));

            /* an epoch that exists, with each stored side in turn, so
             * `e->side != ENCRYPT_AND_DECRYPT_SIDE && e->side != side` gets
             * every combination */
            for (b = 0; b < 3; b++) {
                wb_reset(ssl, ctx, kSides[s]);
                ssl->dtls13Epochs[0].epochNumber =
                    w64From32(0x0, DTLS13_EPOCH_HANDSHAKE);
                ssl->dtls13Epochs[0].side = (byte)kEncSides[b];
                ssl->dtls13Epochs[0].isValid = 1;
                WB_NOTE(Dtls13SetEpochKeys(ssl,
                            w64From32(0x0, DTLS13_EPOCH_HANDSHAKE),
                            kEncSides[a]));
            }
        }
    }
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("dtls13 role white-box: wolfSSL_Init failed\n");
        goto done;
    }
    /* A client CTX needs no certificate; the side under test is a field on
     * the ssl, set by hand, not a property of the CTX. */
    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (ctx == NULL) {
        printf("dtls13 role white-box: CTX_new failed\n");
        goto done;
    }
    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("dtls13 role white-box: out of memory\n");
        goto done;
    }

    wb_accept_fragmented(ssl, ctx);
    wb_check_epoch(ssl, ctx);
    wb_save_or_flush(ssl, ctx);
    wb_set_epoch_keys(ssl, ctx);

    printf("dtls13 role white-box: %d vectors driven\n", g_checks);

done:
    /* XFREE, not wolfSSL_free: nothing was constructed and the ctx pointer
     * was assigned without taking a reference. */
    XFREE(ssl, NULL, DYNAMIC_TYPE_SSL);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("dtls13 role white-box: skipped (needs DTLS 1.3 and TLS)\n");
    return 0;
}

#endif
