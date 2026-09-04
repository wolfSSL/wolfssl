/* test_internal_sanity_whitebox.c -- MC/DC white-box driver for
 * SanityCheckMsgReceived in src/internal.c
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

/* WHY A WHITE-BOX, AND WHY IT NEEDS NO HANDSHAKE.
 *
 * SanityCheckMsgReceived is the handshake ordering police: for each of the
 * fourteen message types it refuses the message if it arrives on the wrong
 * side, arrives twice, or arrives before or after a message it must follow or
 * precede. It is the densest uncovered cluster in internal.c after the suite
 * table, and every condition in it is a rejection -- which is to say, every
 * condition in it is a check that only a malformed or hostile peer triggers.
 *
 * That is exactly why the handshake tests cannot cover it. A conforming peer
 * walks the one accepted ordering, so on every call from tests/api each of
 * these decisions is taken false, and MC/DC's independence pair -- the operand
 * changing value AND the outcome changing with it -- never exists. Reaching
 * the line is not the same as pairing the operand, and running more handshakes
 * produces more of the same vector.
 *
 * The fixture is the whole trick, and it is smaller than it looks. The
 * function touches ssl->options, ssl->msgsReceived and ssl->specs, and reads
 * ssl->arrays and ssl->status_request only after NULL-guarding them. The one
 * thing it dereferences unguarded is SSL_CM(ssl), which is ssl->ctx->cm. So
 * the fixture is a zeroed WOLFSSL with its ctx pointed at a real CTX -- and
 * nothing else. No certificate, no key, no transport, no peer, and in
 * particular no wolfSSL_new, which returns NULL for a server CTX with no
 * certificate loaded and which is what silently turned an earlier white-box in
 * this campaign into a no-op that still exited 0. Both sides are swept from
 * one client CTX, because options.side is a field, not a constructor argument.
 *
 * The vectors are one-at-a-time sweeps from both saturated baselines, the same
 * construct as the InitSuites driver. For a decision `!A || B || C`, the
 * all-set and all-clear states take it both ways, and the state differing in
 * exactly one bit gives that operand its pair -- for every operand of every
 * decision, from O(n) calls instead of O(2^n). Both sides are swept because
 * roughly half the arms open with a side check, and both message-state and
 * option-state are swept against each other's saturated ends so an operand is
 * never masked by a short-circuit that never varies.
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
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)

static int g_calls;

/* ------------------------------------------------------ message-state bits */

enum {
    M_HELLO_REQUEST = 0, M_CLIENT_HELLO, M_SERVER_HELLO, M_HELLO_VERIFY,
    M_SESSION_TICKET, M_HELLO_RETRY, M_CERTIFICATE, M_CERT_STATUS,
    M_SERVER_KEY_EXCH, M_CERT_REQUEST, M_SERVER_HELLO_DONE, M_CERT_VERIFY,
    M_CLIENT_KEY_EXCH, M_FINISHED, M_CHANGE_CIPHER, M_COUNT
};

/* Set ssl->msgsReceived from a bit mask. The struct is a bitfield, so it
 * cannot be indexed; the switch is the price of sweeping it generically. */
static void wb_set_msgs(WOLFSSL* ssl, word32 mask)
{
    int i;

    XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));
    for (i = 0; i < M_COUNT; i++) {
        if ((mask & (1u << i)) == 0)
            continue;
        switch (i) {
            case M_HELLO_REQUEST:    ssl->msgsReceived.got_hello_request = 1;
                                     break;
            case M_CLIENT_HELLO:     ssl->msgsReceived.got_client_hello = 1;
                                     break;
            case M_SERVER_HELLO:     ssl->msgsReceived.got_server_hello = 1;
                                     break;
            case M_HELLO_VERIFY:
                    ssl->msgsReceived.got_hello_verify_request = 1;
                    break;
            case M_SESSION_TICKET:   ssl->msgsReceived.got_session_ticket = 1;
                                     break;
            case M_HELLO_RETRY:
                    ssl->msgsReceived.got_hello_retry_request = 1;
                    break;
            case M_CERTIFICATE:      ssl->msgsReceived.got_certificate = 1;
                                     break;
            case M_CERT_STATUS:
                    ssl->msgsReceived.got_certificate_status = 1;
                    break;
            case M_SERVER_KEY_EXCH:
                    ssl->msgsReceived.got_server_key_exchange = 1;
                    break;
            case M_CERT_REQUEST:
                    ssl->msgsReceived.got_certificate_request = 1;
                    break;
            case M_SERVER_HELLO_DONE:
                    ssl->msgsReceived.got_server_hello_done = 1;
                    break;
            case M_CERT_VERIFY:
                    ssl->msgsReceived.got_certificate_verify = 1;
                    break;
            case M_CLIENT_KEY_EXCH:
                    ssl->msgsReceived.got_client_key_exchange = 1;
                    break;
            case M_FINISHED:         ssl->msgsReceived.got_finished = 1;
                                     break;
            case M_CHANGE_CIPHER:    ssl->msgsReceived.got_change_cipher = 1;
                                     break;
            default: break;
        }
    }
}

/* ------------------------------------------------------- option-state bits */

enum {
    O_RESUMING = 0, O_VERIFY_PEER, O_PSK_CIPHER, O_ANON_CIPHER,
    O_HAVE_PEER_CERT, O_HAVE_PEER_VERIFY, O_DTLS, O_COUNT
};

static void wb_set_opts(WOLFSSL* ssl, word32 mask)
{
    ssl->options.resuming        = (mask & (1u << O_RESUMING))   ? 1 : 0;
    ssl->options.verifyPeer      = (mask & (1u << O_VERIFY_PEER)) ? 1 : 0;
    ssl->options.usingPSK_cipher = (mask & (1u << O_PSK_CIPHER)) ? 1 : 0;
    ssl->options.usingAnon_cipher= (mask & (1u << O_ANON_CIPHER)) ? 1 : 0;
    ssl->options.havePeerCert    = (mask & (1u << O_HAVE_PEER_CERT)) ? 1 : 0;
    ssl->options.havePeerVerify  = (mask & (1u << O_HAVE_PEER_VERIFY)) ? 1 : 0;
#ifdef WOLFSSL_DTLS
    ssl->options.dtls            = (mask & (1u << O_DTLS)) ? 1 : 0;
#endif
}

/* --------------------------------------------------------------- one call */

/* Reset only what the function reads, then call it. Nothing here is allocated
 * or owned, so there is no teardown and no ordering between vectors. */
static void wb_call(WOLFSSL* ssl, byte type, int side, word32 msgs,
                    word32 opts, byte kea, byte staticEcdh)
{
    ssl->options.side = (byte)side;
    wb_set_msgs(ssl, msgs);
    wb_set_opts(ssl, opts);
    ssl->specs.kea = kea;
    ssl->specs.static_ecdh = staticEcdh;

    (void)SanityCheckMsgReceived(ssl, type);
    g_calls++;
}

/* For one message type on one side: sweep the message state one bit at a time
 * from each saturated end against each saturated option state, then the option
 * state the same way against each saturated message state, then the key
 * exchange values that server_hello_done and certificate_request test. */
static void wb_sweep_type(WOLFSSL* ssl, byte type, int side)
{
    const word32 msgAll = (1u << M_COUNT) - 1u;
    const word32 optAll = (1u << O_COUNT) - 1u;
    word32 optEnds[2];
    int i, e;

    optEnds[0] = 0;
    optEnds[1] = optAll;

    /* message bits, one at a time from both ends, under both option ends */
    for (e = 0; e < 2; e++) {
        wb_call(ssl, type, side, 0,      optEnds[e], rsa_kea, 0);
        wb_call(ssl, type, side, msgAll, optEnds[e], rsa_kea, 0);
        for (i = 0; i < M_COUNT; i++) {
            wb_call(ssl, type, side, 1u << i,          optEnds[e], rsa_kea, 0);
            wb_call(ssl, type, side, msgAll & ~(1u << i), optEnds[e],
                    rsa_kea, 0);
        }
    }

    /* option bits, one at a time from both ends, under both message ends */
    for (e = 0; e < 2; e++) {
        word32 msgs = e ? msgAll : 0;
        for (i = 0; i < O_COUNT; i++) {
            wb_call(ssl, type, side, msgs, 1u << i,          rsa_kea, 0);
            wb_call(ssl, type, side, msgs, optAll & ~(1u << i), rsa_kea, 0);
        }
    }

    /* `ssl->specs.kea != rsa_kea && ... static_ecdh` in certificate_request
     * and server_hello_done: each operand needs a pair, and a build only ever
     * negotiates one kea per connection. The message state omits
     * server_key_exchange so the enclosing decision is entered. */
    {
        const word32 msgs = msgAll & ~(1u << M_SERVER_KEY_EXCH);
        static const byte keas[3] = { rsa_kea, psk_kea, ecc_diffie_hellman_kea };
        size_t k;

        for (k = 0; k < sizeof(keas) / sizeof(keas[0]); k++) {
            wb_call(ssl, type, side, msgs, 0, keas[k], 0);
            wb_call(ssl, type, side, msgs, 0, keas[k], 1);
        }
    }
}


/* ------------------------------------------------ accepting baselines

 * The saturated sweeps above are not enough on their own, and the reason is
 * worth stating because it cost a measurement to find. Most arms are a
 * sequence: first a prerequisite check that returns early, then the
 * out-of-order chain. Sweeping from an all-clear state never reaches the
 * chain, because the prerequisite is missing; sweeping from an all-set state
 * never reaches it either, because the duplicate check fires first. Both ends
 * are refused at the door, and the chain -- which is where the multi-operand
 * decisions actually live -- is evaluated by neither.
 *
 * So each arm gets the state in which its message is ACCEPTED: prerequisites
 * present, its own bit clear, every forbidden successor clear. From there one
 * flipped bit puts exactly one operand of the chain true with the rest false,
 * and the baseline itself is the partner where all of them are false. That is
 * the independence pair, per operand, and the baseline is what a conforming
 * peer produces -- the flips are what an attacker sends.
 */
typedef struct {
    byte   type;
    int    side;
    word32 base;
    const char* what;
} SanityBase;

#define B(x) (1u << (x))

static const SanityBase kBases[] = {
    { hello_request, WOLFSSL_CLIENT_END, 0, "HelloRequest" },
    { client_hello,  WOLFSSL_SERVER_END, 0, "ClientHello" },
    { server_hello,  WOLFSSL_CLIENT_END, 0, "ServerHello" },
    { hello_verify_request, WOLFSSL_CLIENT_END, 0, "HelloVerifyRequest" },

    /* ServerHello seen, ServerHelloDone seen, nothing after it yet. */
    { session_ticket, WOLFSSL_CLIENT_END,
      B(M_SERVER_HELLO) | B(M_SERVER_HELLO_DONE), "SessionTicket" },

    { certificate, WOLFSSL_CLIENT_END, B(M_SERVER_HELLO), "Certificate/client" },
    { certificate, WOLFSSL_SERVER_END, B(M_CLIENT_HELLO), "Certificate/server" },

    { certificate_status, WOLFSSL_CLIENT_END,
      B(M_SERVER_HELLO) | B(M_CERTIFICATE), "CertificateStatus" },

    { server_key_exchange, WOLFSSL_CLIENT_END,
      B(M_SERVER_HELLO) | B(M_CERTIFICATE), "ServerKeyExchange" },

    { certificate_request, WOLFSSL_CLIENT_END,
      B(M_SERVER_HELLO) | B(M_CERTIFICATE) | B(M_SERVER_KEY_EXCH),
      "CertificateRequest" },

    { server_hello_done, WOLFSSL_CLIENT_END,
      B(M_SERVER_HELLO) | B(M_CERTIFICATE) | B(M_SERVER_KEY_EXCH) |
      B(M_CERT_STATUS), "ServerHelloDone" },

    { certificate_verify, WOLFSSL_SERVER_END,
      B(M_CLIENT_HELLO) | B(M_CERTIFICATE) | B(M_CLIENT_KEY_EXCH),
      "CertificateVerify" },

    { client_key_exchange, WOLFSSL_SERVER_END,
      B(M_CLIENT_HELLO) | B(M_CERTIFICATE), "ClientKeyExchange" },

    { finished, WOLFSSL_CLIENT_END,
      B(M_SERVER_HELLO) | B(M_SERVER_HELLO_DONE) | B(M_CHANGE_CIPHER),
      "Finished/client" },
    { finished, WOLFSSL_SERVER_END,
      B(M_CLIENT_HELLO) | B(M_CLIENT_KEY_EXCH) | B(M_CHANGE_CIPHER),
      "Finished/server" },

    { change_cipher_hs, WOLFSSL_CLIENT_END,
      B(M_SERVER_HELLO) | B(M_SERVER_HELLO_DONE), "ChangeCipher/client" },
    { change_cipher_hs, WOLFSSL_SERVER_END,
      B(M_CLIENT_HELLO) | B(M_CLIENT_KEY_EXCH) | B(M_CERT_VERIFY),
      "ChangeCipher/server" },
};

static void wb_sweep_baselines(WOLFSSL* ssl)
{
    const word32 optAll = (1u << O_COUNT) - 1u;
    size_t r;
    int i;

    for (r = 0; r < sizeof(kBases) / sizeof(kBases[0]); r++) {
        const SanityBase* b = &kBases[r];

        /* the accepting vector: every chain operand false */
        wb_call(ssl, b->type, b->side, b->base, 0, rsa_kea, 0);

        /* one operand true at a time, the rest still false */
        for (i = 0; i < M_COUNT; i++)
            wb_call(ssl, b->type, b->side, b->base ^ (1u << i), 0, rsa_kea, 0);

        /* the option operands in the same chains -- resuming, verifyPeer,
         * usingPSK_cipher, usingAnon_cipher, havePeerCert, havePeerVerify,
         * dtls -- paired against the accepting baseline. */
        for (i = 0; i < O_COUNT; i++) {
            wb_call(ssl, b->type, b->side, b->base, 1u << i, rsa_kea, 0);
            wb_call(ssl, b->type, b->side, b->base, optAll & ~(1u << i),
                    rsa_kea, 0);
        }

        /* `kea != rsa_kea && !static_ecdh && !psk-without-hint` decides
         * whether a missing ServerKeyExchange is an error. A build negotiates
         * one kea, so these operands have no pair outside this loop. */
        {
            static const byte keas[3] = { rsa_kea, psk_kea,
                                          ecc_diffie_hellman_kea };
            word32 noSkex = b->base & ~B(M_SERVER_KEY_EXCH);
            size_t k;

            for (k = 0; k < sizeof(keas) / sizeof(keas[0]); k++) {
                wb_call(ssl, b->type, b->side, noSkex, 0, keas[k], 0);
                wb_call(ssl, b->type, b->side, noSkex, 0, keas[k], 1);
            }
        }
    }
}


/* ------------------------------------------------- DoHandShakeMsgType

 * The other half of the ordering police: before a handshake message is
 * dispatched to its parser, this function refuses it if the handshake is
 * already complete, if it is the first message from a server and is not a
 * ServerHello, if it is the first message from a client and is not a
 * ClientHello, or -- for DTLS -- if a ServerHelloDone arrives before the
 * ServerHello. Those are four state guards on top of the length check, and
 * like SanityCheckMsgReceived they are all rejections that a conforming peer
 * never triggers.
 *
 * Two things make it drivable without a handshake. The guards run before any
 * dispatch, so no message body has to parse -- the input can be zeros. And
 * every guard calls SendAlert on its way out, which is the only reason this
 * needs more than the zeroed fixture: a send callback that consumes and
 * discards. Without one the alert path dereferences a NULL CBIOSend.
 *
 * The vectors again sweep one field at a time from a state that is ACCEPTED,
 * because from a saturated state the first guard fires and the rest are never
 * evaluated.
 */

static int wb_send_sink(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)buf; (void)ctx;
    return sz;              /* swallow the alert, report it fully written */
}

static void wb_msgtype(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    static byte input[64];
    static const byte kTypes[] = {
        client_hello, server_hello, server_hello_done, hello_request,
        certificate, finished, session_ticket, 200
    };
    /* Each row is a handshake state. The first is the accepting one for a
     * client receiving a ServerHello; the rest each differ from an accepting
     * state in one field, so that field's operand gets its pair. */
    static const struct {
        int  side;
        byte dtls;
        byte handShakeDone;
        byte handShakeState;
        byte serverState;
        byte clientState;
        const char* what;
    } rows[] = {
        { WOLFSSL_CLIENT_END, 0, 0, NULL_STATE, NULL_STATE, NULL_STATE,
          "client, nothing received yet" },
        { WOLFSSL_CLIENT_END, 0, 0, HANDSHAKE_DONE, SERVER_HELLO_COMPLETE,
          NULL_STATE, "client, handshake already complete" },
        { WOLFSSL_CLIENT_END, 0, 1, NULL_STATE, SERVER_HELLO_COMPLETE,
          NULL_STATE, "client, handShakeDone set" },
        { WOLFSSL_CLIENT_END, 0, 0, NULL_STATE, SERVER_HELLO_COMPLETE,
          NULL_STATE, "client, server hello seen" },
        { WOLFSSL_CLIENT_END, 1, 0, NULL_STATE, NULL_STATE, NULL_STATE,
          "DTLS client, nothing received yet" },
        { WOLFSSL_CLIENT_END, 1, 0, NULL_STATE, SERVER_HELLO_COMPLETE,
          NULL_STATE, "DTLS client, server hello seen" },
        { WOLFSSL_SERVER_END, 0, 0, NULL_STATE, NULL_STATE, NULL_STATE,
          "server, nothing received yet" },
        { WOLFSSL_SERVER_END, 0, 0, NULL_STATE, NULL_STATE,
          CLIENT_HELLO_COMPLETE, "server, client hello seen" },
        { WOLFSSL_SERVER_END, 0, 1, HANDSHAKE_DONE, NULL_STATE,
          CLIENT_HELLO_COMPLETE, "server, handshake complete" },
        { WOLFSSL_SERVER_END, 1, 0, NULL_STATE, NULL_STATE, NULL_STATE,
          "DTLS server, nothing received yet" },
    };
    size_t r, t;

    XMEMSET(input, 0, sizeof(input));

    for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
        for (t = 0; t < sizeof(kTypes) / sizeof(kTypes[0]); t++) {
            word32 idx = 0;

            XMEMSET(ssl, 0, sizeof(*ssl));
            ssl->ctx = ctx;
            ssl->CBIOSend = wb_send_sink;
            ssl->version.major = SSLv3_MAJOR;
            ssl->version.minor = TLSv1_2_MINOR;
            ssl->options.side = (byte)rows[r].side;
            ssl->options.handShakeDone = rows[r].handShakeDone;
            ssl->options.handShakeState = rows[r].handShakeState;
            ssl->options.serverState = rows[r].serverState;
            ssl->options.clientState = rows[r].clientState;
#ifdef WOLFSSL_DTLS
            ssl->options.dtls = rows[r].dtls;
#endif
            /* size fits inside totalSz: the length guard is taken false so
             * the state guards below it are reached at all */
            (void)DoHandShakeMsgType(ssl, input, &idx, kTypes[t], 4,
                                     (word32)sizeof(input));
            g_calls++;

            /* and once with size past totalSz, which is the other half of
             * the `*inOutIdx + size > totalSz` pair */
            idx = 0;
            XMEMSET(ssl, 0, sizeof(*ssl));
            ssl->ctx = ctx;
            ssl->CBIOSend = wb_send_sink;
            ssl->options.side = (byte)rows[r].side;
            (void)DoHandShakeMsgType(ssl, input, &idx, kTypes[t], 4096, 8);
            g_calls++;
        }
    }
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    /* Every message type with an arm, plus one with none, for the default. */
    static const byte kTypes[] = {
        hello_request, client_hello, server_hello, hello_verify_request,
        session_ticket, certificate, certificate_status, server_key_exchange,
        certificate_request, server_hello_done, certificate_verify,
        client_key_exchange, finished, change_cipher_hs, 200
    };
    const int sides[2] = { WOLFSSL_CLIENT_END, WOLFSSL_SERVER_END };
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    size_t t;
    int s;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal sanity white-box: wolfSSL_Init failed\n");
        goto done;
    }

    /* The CTX exists only so SSL_CM(ssl) resolves: the server_hello_done arm
     * reads SSL_CM(ssl)->ocspMustStaple without a NULL guard, which is the one
     * field outside the WOLFSSL that the function reaches for. A client method
     * needs no certificate, and the side under test is a field on the ssl. */
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("internal sanity white-box: CTX_new failed\n");
        goto done;
    }

    /* A zeroed WOLFSSL, not a constructed one. wolfSSL_new would allocate
     * buffers, suites and hashes that this function never reads. */
    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("internal sanity white-box: out of memory\n");
        goto done;
    }
    XMEMSET(ssl, 0, sizeof(*ssl));
    ssl->ctx = ctx;

    for (t = 0; t < sizeof(kTypes) / sizeof(kTypes[0]); t++)
        for (s = 0; s < 2; s++)
            wb_sweep_type(ssl, kTypes[t], sides[s]);

    wb_sweep_baselines(ssl);
    wb_msgtype(ssl, ctx);

    printf("internal sanity white-box: %d SanityCheckMsgReceived calls\n",
           g_calls);

done:
    /* XFREE, not wolfSSL_free: nothing here was constructed, and the ctx
     * pointer was assigned without taking a reference. */
    XFREE(ssl, NULL, DYNAMIC_TYPE_SSL);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal sanity white-box: skipped (TLS 1.2 not built)\n");
    return 0;
}

#endif
