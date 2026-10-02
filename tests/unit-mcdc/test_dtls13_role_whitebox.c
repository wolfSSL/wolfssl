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
#define WB_NOTE(what) do {g_checks++; (void)(what);} while (0)

/* The handshake types these decisions discriminate on. */
static const byte kTypes[] = {
    client_hello, server_hello, hello_verify_request, hello_retry_request,
    hello_request, encrypted_extensions, certificate, certificate_verify,
    finished, session_ticket, key_update, 200 /* not a handshake type */
};

static const int kSides[2] = {WOLFSSL_CLIENT_END, WOLFSSL_SERVER_END};

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
                                                       (enum HandShakeType)
                                                       kTypes[t]));
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
    static const word32 kEpochs[] = {0, DTLS13_EPOCH_EARLYDATA,
                                     DTLS13_EPOCH_HANDSHAKE,
                                     DTLS13_EPOCH_TRAFFIC0, 7};
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
            WB_NOTE(Dtls13SetEpochKeys(ssl, w64From32(0x0,
                                                      DTLS13_EPOCH_HANDSHAKE),
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
                                           w64From32(0x0, DTLS13_EPOCH_HANDSHAKE
                                                     ),
                                           kEncSides[a]));
            }
        }
    }
}

/* ------------------------------------------- guard rows :1364/1572/1270 */
static void wb_encrypt_rn_guard(WOLFSSL* ssl)
{
    byte hdr[16];

    WB_NOTE(Dtls13EncryptRecordNumber(NULL, hdr, sizeof(hdr)));
    WB_NOTE(Dtls13EncryptRecordNumber(ssl, NULL, sizeof(hdr)));
    WB_NOTE(Dtls13EncryptRecordNumber(ssl, hdr, sizeof(hdr)));
}

static void wb_parse_unified_guard(WOLFSSL* ssl)
{
    Dtls13UnifiedHdrInfo info;
    byte hdr[8];

    XMEMSET(hdr, 0, sizeof(hdr));
    WB_NOTE(Dtls13ParseUnifiedRecordLayer(ssl, NULL, sizeof(hdr), &info));
    WB_NOTE(Dtls13ParseUnifiedRecordLayer(ssl, hdr, 0, &info));
    hdr[0] = DTLS13_FIXED_BITS;
    WB_NOTE(Dtls13ParseUnifiedRecordLayer(ssl, hdr, sizeof(hdr), &info));
}

static void wb_unified_cid_bit(void)
{
    WB_NOTE(Dtls13UnifiedHeaderCIDPresent(DTLS13_FIXED_BITS |
                                          DTLS13_CID_BIT));
    WB_NOTE(Dtls13UnifiedHeaderCIDPresent(DTLS13_FIXED_BITS));
    WB_NOTE(Dtls13UnifiedHeaderCIDPresent(0x00));
}

/* ------------------------------------------- frag/send-now rows :452/478/481 */
static void wb_frag_in_output_buffer(WOLFSSL* ssl)
{
    byte mem[16];

    ssl->buffers.outputBuffer.buffer = mem + 8;
    ssl->buffers.outputBuffer.bufferSize = 4;
    /* inside: both operands false */
    WB_NOTE(FragIsInOutputBuffer(ssl, mem + 8));
    /* before the buffer: operand 0 true */
    WB_NOTE(FragIsInOutputBuffer(ssl, mem));
    /* exactly at the end: operand 1 true */
    WB_NOTE(FragIsInOutputBuffer(ssl, mem + 12));
    ssl->buffers.outputBuffer.buffer = NULL;
    ssl->buffers.outputBuffer.bufferSize = 0;
}

static void wb_send_now_rows(WOLFSSL* ssl)
{
    enum HandShakeType types[7];
    byte hsState;
    int i;

    types[0] = client_hello;
    types[1] = hello_retry_request;
    types[2] = finished;
    types[3] = session_ticket;
    types[4] = key_update;
    types[5] = certificate_request;
    types[6] = server_hello;

    /* groupMessages off: operand 0 true */
    ssl->options.groupMessages = 0;
    WB_NOTE(Dtls13SendNow(ssl, server_hello));
    /* groupMessages on, sending fragments: operand 1 true */
    ssl->options.groupMessages = 1;
    ssl->dtls13SendingFragments = 1;
    WB_NOTE(Dtls13SendNow(ssl, server_hello));
    ssl->dtls13SendingFragments = 0;
    /* send-now handshake types: one per operand true */
    for (i = 0; i < 5; i++) {
        WB_NOTE(Dtls13SendNow(ssl, types[i]));
    }
    /* certificate_request: done (operand 5 true) and not done
     * (operand 6 true) */
    hsState = ssl->options.handShakeState;
    ssl->options.handShakeState = HANDSHAKE_DONE;
    WB_NOTE(Dtls13SendNow(ssl, certificate_request));
    ssl->options.handShakeState = hsState;
    WB_NOTE(Dtls13SendNow(ssl, certificate_request));
    /* all false: server_hello */
    WB_NOTE(Dtls13SendNow(ssl, server_hello));
    ssl->options.groupMessages = 0;
}

/* ------------------------------------------- rtx/ack rows :869/873/898/932/991/1009 */
static void wb_rtx_msg_recvd(WOLFSSL* ssl)
{
    DtlsMsg msg;
    DtlsFragBucket b1, b2;
    Dtls13RtxRecord* rtx;
    byte* rtxData;
    Dtls13RecordNumber* rn;
    byte implicitAck = 0;
    byte sendMoreAcks;

    XMEMSET(&msg, 0, sizeof(msg));
    XMEMSET(&b1, 0, sizeof(b1));
    XMEMSET(&b2, 0, sizeof(b2));

    /* -- Dtls13DetectDisruption :869/873 -- */
    /* two buckets, fragOffset past the end */
    b1.m.m.next = &b2;
    b1.m.m.offset = 0;
    b1.m.m.sz = 10;
    b2.m.m.next = NULL;
    b2.m.m.offset = 10;
    b2.m.m.sz = 10;
    msg.fragBucketList = &b1;
    ssl->dtls_rx_msg_list = &msg;
    WB_NOTE(Dtls13DetectDisruption(ssl, 25));
    /* one bucket, fragOffset past the end */
    b1.m.m.next = NULL;
    WB_NOTE(Dtls13DetectDisruption(ssl, 25));
    /* one bucket, fragOffset == offset + sz */
    WB_NOTE(Dtls13DetectDisruption(ssl, 10));
    /* empty frag list */
    msg.fragBucketList = NULL;
    WB_NOTE(Dtls13DetectDisruption(ssl, 10));
    ssl->dtls_rx_msg_list = NULL;

    /* -- Dtls13SaveOrFlushClientHello :932 (via server_hello) -- */
    /* Early in the function: the static-build memory pool is freshest
     * here and the rtx record must be heap-allocated. */
    ssl->options.handShakeDone = 0;
    /* a raw zeroed ssl has side == 0, which is no side at all */
    ssl->options.side = WOLFSSL_CLIENT_END;
    ssl->options.connectState = CLIENT_HELLO_SENT;
    ssl->options.downgrade = 1;
    rtxData = (byte*)XMALLOC(8, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    rtx = (Dtls13RtxRecord*)XMALLOC(sizeof(*rtx), ssl->heap,
                                    DYNAMIC_TYPE_DTLS_MSG);
    if (rtxData != NULL && rtx != NULL) {
        XMEMSET(rtxData, 0x42, 8);
        XMEMSET(rtx, 0, sizeof(*rtx));
        rtx->data = rtxData;
        rtx->length = 8;
        rtx->handshakeType = client_hello;
        ssl->dtls13Rtx.rtxRecords = rtx;
        ssl->dtls13Rtx.rtxRecordTailPtr = &ssl->dtls13Rtx.rtxRecords;
        /* operand 1 false: minDowngrade below DTLSv1_2_MINOR */
        ssl->options.minDowngrade = 0;
        WB_NOTE(Dtls13SaveOrFlushClientHello(ssl));
        /* operand 1 true: the record is consumed, so a fresh one */
        rtxData = (byte*)XMALLOC(8, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
        rtx = (Dtls13RtxRecord*)XMALLOC(sizeof(*rtx), ssl->heap,
                                        DYNAMIC_TYPE_DTLS_MSG);
        if (rtxData != NULL && rtx != NULL) {
            XMEMSET(rtxData, 0x42, 8);
            XMEMSET(rtx, 0, sizeof(*rtx));
            rtx->data = rtxData;
            rtx->length = 8;
            rtx->handshakeType = client_hello;
            ssl->dtls13Rtx.rtxRecords = rtx;
            ssl->dtls13Rtx.rtxRecordTailPtr = &ssl->dtls13Rtx.rtxRecords;
            ssl->options.minDowngrade = DTLSv1_2_MINOR;
            WB_NOTE(Dtls13SaveOrFlushClientHello(ssl));
        } else {
            XFREE(rtxData, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
            XFREE(rtx, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
        }
    } else {
        XFREE(rtxData, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
        XFREE(rtx, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    }
    ssl->options.downgrade = 0;
    ssl->options.connectState = NULL_STATE;

    /* -- Dtls13RtxMsgRecvd :991 + Dtls13RtxRemoveCurAck :898 -- */
    sendMoreAcks = ssl->options.dtls13SendMoreAcks;
    ssl->options.dtls13SendMoreAcks = 1;
    ssl->options.handShakeDone = 1;
    rn = (Dtls13RecordNumber*)XMALLOC(sizeof(*rn), ssl->heap,
                                      DYNAMIC_TYPE_DTLS_MSG);
    if (rn == NULL) {
        return;
    }
    /* matching epoch + seq: both operands true, the node is freed */
    XMEMSET(rn, 0, sizeof(*rn));
    ssl->dtls13Rtx.seenRecords = rn;
    ssl->dtls13Rtx.seenRecordsCount = 1;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, certificate_request, 10, &implicitAck));
    /* epoch mismatch: operand 0 false */
    XMEMSET(rn, 0, sizeof(*rn));
    rn->epoch.n = 1;
    ssl->dtls13Rtx.seenRecords = rn;
    ssl->dtls13Rtx.seenRecordsCount = 1;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, certificate_request, 10, &implicitAck));
    /* seq mismatch: operand 1 false */
    XMEMSET(rn, 0, sizeof(*rn));
    rn->seq.n = 1;
    ssl->dtls13Rtx.seenRecords = rn;
    ssl->dtls13Rtx.seenRecordsCount = 1;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, certificate_request, 10, &implicitAck));
    XFREE(rn, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    ssl->dtls13Rtx.seenRecords = NULL;
    ssl->dtls13Rtx.seenRecordsCount = 0;
    /* 991 operand 1 false: handshake not done */
    ssl->options.handShakeDone = 0;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, certificate_request, 0, &implicitAck));
    /* 991 operand 2 false: not a certificate_request */
    ssl->options.handShakeDone = 1;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, server_hello, 0, &implicitAck));
    /* 991 operand 0 false: peer behind expected */
    ssl->keys.dtls_expected_peer_handshake_number = 1;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, server_hello, 0, &implicitAck));
    ssl->keys.dtls_expected_peer_handshake_number = 0;

    /* -- 1009 -- */
    ssl->options.handShakeDone = 1;
    /* sendMoreAcks on + disruption detected: both operands true */
    b1.m.m.next = &b2;
    msg.fragBucketList = &b1;
    ssl->dtls_rx_msg_list = &msg;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, server_hello, 25, &implicitAck));
    /* fragOffset 0: no disruption */
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, server_hello, 0, &implicitAck));
    /* sendMoreAcks off: operand 0 false */
    ssl->options.dtls13SendMoreAcks = 0;
    WB_NOTE(Dtls13RtxMsgRecvd(ssl, server_hello, 25, &implicitAck));

restore:
    ssl->options.dtls13SendMoreAcks = sendMoreAcks;
    ssl->options.handShakeDone = 0;
    ssl->options.downgrade = 0;
    ssl->options.side = 0;
    ssl->options.connectState = NULL_STATE;
    ssl->dtls_rx_msg_list = NULL;
}

/* ---------------------------------------------------------------- main */


/* Cluster E/F: options and epoch guards in dtls13.c. */
static void wb_opts_epoch_rows(WOLFSSL* ssl)
{
    int save_maxFrag;
    word32 save_fragOff, save_msgLen, save_fragType;
    ProtocolVersion save_version;
    int save_side, save_serverState, save_hsDone, save_seenUnified;
    w64wrapper save_curEpoch, save_dtls13Epoch;
    Dtls13Epoch save_e0;
    Dtls13RecordNumber* save_seen;
    Dtls13Epoch* save_encEpoch;
    Dtls13RecordNumber* seen;
    byte buf[13];
    word32 idx;

    save_maxFrag = ssl->max_fragment;
    save_fragOff = ssl->dtls13FragOffset;
    save_msgLen = ssl->dtls13MessageLength;
    save_fragType = ssl->dtls13FragHandshakeType;
    save_version = ssl->version;
    save_side = ssl->options.side;
    save_serverState = ssl->options.serverState;
    save_hsDone = ssl->options.handShakeDone;
    save_seenUnified = ssl->options.seenUnifiedHdr;
    save_curEpoch = ssl->keys.curEpoch64;
    save_dtls13Epoch = ssl->dtls13Epoch;
    save_e0 = ssl->dtls13Epochs[0];
    save_seen = ssl->dtls13Rtx.seenRecords;
    save_encEpoch = ssl->dtls13EncryptEpoch;

    /* -- Dtls13SendFragmentedInternal :1074 c0/c1/c2 --
     * maxFragment = min(MAX_RECORD_SIZE, ssl->max_fragment), so c1-T
     * (maxFragment > MAX_RECORD_SIZE) is structurally unreachable:
     * residual, documented in the GAPS note. */
    ssl->dtls13FragHandshakeType = application_data;
    ssl->max_fragment = 10;
    WB_NOTE(Dtls13SendFragmentedInternal(ssl));
    ssl->max_fragment = 1000;
    ssl->dtls13FragOffset = 200;
    ssl->dtls13MessageLength = 100;
    WB_NOTE(Dtls13SendFragmentedInternal(ssl));
    ssl->dtls13FragOffset = 0;
    WB_NOTE(Dtls13SendFragmentedInternal(ssl));

    /* -- Dtls13CheckEpoch :1791 c0/c1, :1814 c1 -- */
    ssl->version.major = SSLv3_MAJOR;
    ssl->version.minor = DTLSv1_3_MINOR;
    ssl->keys.curEpoch64.n = 0;
    ssl->options.handShakeDone = 0;
    ssl->options.side = WOLFSSL_CLIENT_END;
    ssl->options.serverState = 0;
    WB_NOTE(Dtls13CheckEpoch(ssl, encrypted_extensions));
    ssl->options.side = WOLFSSL_SERVER_END;
    WB_NOTE(Dtls13CheckEpoch(ssl, encrypted_extensions));
    ssl->options.side = WOLFSSL_CLIENT_END;
    ssl->options.serverState = SERVER_HELLO_COMPLETE;
    WB_NOTE(Dtls13CheckEpoch(ssl, encrypted_extensions));
    ssl->options.serverState = 0;
    WB_NOTE(Dtls13CheckEpoch(ssl, certificate));
    ssl->options.serverState = SERVER_HELLO_COMPLETE;
    WB_NOTE(Dtls13CheckEpoch(ssl, certificate));

    /* -- Dtls13GetEpoch :2312 c1-F -- */
    ssl->dtls13Epochs[0].epochNumber.n = 5;
    ssl->dtls13Epochs[0].isValid = 0;
    WB_NOTE(Dtls13GetEpoch(ssl, w64From32(0, 5)));
    /* -- Dtls13SetOlderEpochSide :2327 c0/c1 -- */
    ssl->dtls13Epochs[0].epochNumber.n = 1;
    ssl->dtls13Epochs[0].isValid = 0;
    WB_NOTE(Dtls13SetOlderEpochSide(ssl, w64From32(0, 2),
                                    ENCRYPT_SIDE_ONLY));
    ssl->dtls13Epochs[0].isValid = 1;
    WB_NOTE(Dtls13SetOlderEpochSide(ssl, w64From32(0, 2),
                                    ENCRYPT_SIDE_ONLY));
    ssl->dtls13Epochs[0].epochNumber.n = 5;
    WB_NOTE(Dtls13SetOlderEpochSide(ssl, w64From32(0, 2),
                                    ENCRYPT_SIDE_ONLY));

    /* -- Dtls13RtxTimeout :2959 c2 -- */
    seen = (Dtls13RecordNumber*)XMALLOC(sizeof(*seen), ssl->heap,
                                        DYNAMIC_TYPE_DTLS_MSG);
    if (seen != NULL) {
        XMEMSET(seen, 0, sizeof(*seen));
        ssl->dtls13Rtx.seenRecords = seen;
        ssl->options.serverState = 0;
        ssl->dtls13EncryptEpoch = NULL;
        ssl->options.seenUnifiedHdr = 1;
        WB_NOTE(Dtls13RtxTimeout(ssl));
        ssl->options.seenUnifiedHdr = 0;
        WB_NOTE(Dtls13RtxTimeout(ssl));
        XFREE(seen, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    }

    /* -- DoDtls13NewConnectionId :3071 c0 -- */
    buf[0] = 0;
    buf[1] = 5;
    buf[2] = 4;
    buf[3] = 1;
    buf[4] = 2;
    buf[5] = 3;
    buf[6] = 4;
    buf[7] = cid_spare;
    idx = 0;
    WB_NOTE(DoDtls13NewConnectionId(ssl, buf, &idx, 8));
    /* c0-F: a second usable cid sees newCid != NULL */
    buf[0] = 0;
    buf[1] = 10;
    buf[2] = 4;
    buf[3] = 1;
    buf[4] = 2;
    buf[5] = 3;
    buf[6] = 4;
    buf[7] = 4;
    buf[8] = 5;
    buf[9] = 6;
    buf[10] = 7;
    buf[11] = 8;
    buf[12] = cid_spare;
    idx = 0;
    WB_NOTE(DoDtls13NewConnectionId(ssl, buf, &idx, 13));

    /* -- SendDtls13Ack :3207 c2 -- */
    ssl->dtls13Epochs[0].epochNumber.n = 0;
    ssl->dtls13Epochs[0].isValid = 1;
    ssl->dtls13EncryptEpoch = &ssl->dtls13Epochs[0];
    ssl->options.side = WOLFSSL_SERVER_END;
    ssl->options.handShakeDone = 0;
    ssl->dtls13Epoch.n = DTLS13_EPOCH_TRAFFIC0;
    WB_NOTE(SendDtls13Ack(ssl));
    ssl->dtls13Epoch.n = DTLS13_EPOCH_HANDSHAKE;
    WB_NOTE(SendDtls13Ack(ssl));

    ssl->max_fragment = save_maxFrag;
    ssl->dtls13FragOffset = save_fragOff;
    ssl->dtls13MessageLength = save_msgLen;
    ssl->dtls13FragHandshakeType = save_fragType;
    ssl->version = save_version;
    ssl->options.side = save_side;
    ssl->options.serverState = save_serverState;
    ssl->options.handShakeDone = save_hsDone;
    ssl->options.seenUnifiedHdr = save_seenUnified;
    ssl->keys.curEpoch64 = save_curEpoch;
    ssl->dtls13Epoch = save_dtls13Epoch;
    ssl->dtls13Epochs[0] = save_e0;
    ssl->dtls13Rtx.seenRecords = save_seen;
    ssl->dtls13EncryptEpoch = save_encEpoch;
}

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
    wb_encrypt_rn_guard(ssl);
    wb_parse_unified_guard(ssl);
    wb_unified_cid_bit();
    wb_frag_in_output_buffer(ssl);
    wb_send_now_rows(ssl);
    wb_opts_epoch_rows(ssl);
    wb_rtx_msg_recvd(ssl);

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
