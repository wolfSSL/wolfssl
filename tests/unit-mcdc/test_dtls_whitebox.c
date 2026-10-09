/* test_dtls_whitebox.c -- MC/DC white-box driver for src/dtls.c
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

/* WHY A WHITE-BOX FOR THIS FILE.
 *
 * Every uncovered condition in src/dtls.c sits in a file-static helper on the
 * stateless (cookie exchange) path: CreateDtls12Cookie, CheckDtlsCookie,
 * FindExtByType, TlsCheckSupportedVersion, ClientHelloSanityCheck,
 * FindPskSuiteFromExt, SendStatelessReplyDtls13, DtlsCidGetSize. The public
 * API reaches them only by feeding a crafted ClientHello through a real
 * handshake, which fixes most of their arguments: a caller cannot ask
 * CreateDtls12Cookie for a NULL secret, or FindExtByType for a length that
 * overruns its own vector, because the code above them never produces those.
 * The independence pairs therefore do not exist from outside, and the API
 * tests that do reach this file were measured first -- the dtls group runs 87
 * of 103 and still leaves 46 of 56 conditions uncovered.
 *
 * This driver includes the .c and calls those static helpers directly, which is the
 * same justification the campaign uses for the 200 static functions in tls.c.
 *
 * Rules this file must satisfy, each learned the hard way:
 *   - main() ALWAYS returns 0. A non-zero exit marks the variant failed and
 *     discards its entire profile, including the parts that worked.
 *   - Vectors come in pairs in ONE binary. A rejection with no accepting
 *     partner demonstrates no independence pair and adds no coverage.
 *   - It compiles under every variant of the module, with a skip stub for the
 *     configurations that do not build the file at all -- a driver that fails
 *     to compile is scored a silent skip, not a failure.
 */

/* Pull dtls.c in verbatim so its file-static helpers are in scope and
 * instrumented in THIS binary. Its object is removed from the archive by the
 * runner, so these definitions are the ones that link.
 *
 * This include comes FIRST and nothing precedes it. dtls.c includes settings.h
 * itself, which picks up user_settings.h under the campaign's
 * -DWOLFSSL_USER_SETTINGS builds and options.h under the --enable-all smoke
 * build. Including settings.h or options.h ahead of it gets the header order
 * wrong for one of those two configurations: an earlier revision of this file
 * did exactly that and failed to compile under gcc/--enable-all with
 * "MAX_EX_DATA undeclared", behind a "No configuration for wolfSSL detected,
 * check header order" warning. */
/* options.h FIRST, before any other wolfSSL header. Under the campaign's
 * --enable-usersettings builds it just defines WOLFSSL_USER_SETTINGS and
 * settings.h then reads user_settings.h; under the --enable-all smoke build it
 * is where every feature macro actually lives. Getting this wrong is silent in
 * the worst way: without it the smoke build compiled this driver with
 * WOLFSSL_DTLS undefined, so it took the skip stub, exited 0, and was recorded
 * as a passing entry in smoke-expected.txt while testing nothing at all. */
#include <wolfssl/options.h>

#include <src/dtls.c>

#include <stdio.h>
#include <string.h>

#if defined(WOLFSSL_DTLS) && !defined(WOLFCRYPT_ONLY)

static int g_checks;

#define WB_NOTE(what) do {g_checks++; (void)(what);} while (0)

/* ------------------------------------------------------------------ helpers */

/* A CH whose vectors are all empty and whose pv is caller supplied. Callers
 * fill in only the field the vector under test depends on, so an unrelated
 * field can never be what actually drove the branch. */
static void wb_ch_init(WolfSSL_CH* ch, ProtocolVersion* pv)
{
    XMEMSET(ch, 0, sizeof(*ch));
    ch->pv = pv;
}

/* ---------------------------------------------- CreateDtls12Cookie :237 */
/* `if (secret == NULL || secretSz == 0)`
 *
 * Both operands need an independence pair, so three vectors: NULL secret with
 * a non-zero size isolates operand 0, a real secret with size 0 isolates
 * operand 1, and a real secret with a real size is the accepting partner that
 * makes both pairs count. Without the third, neither operand has a pair and
 * the rejections prove nothing. */
static void wb_create_dtls12_cookie(WOLFSSL* ssl)
{
    ProtocolVersion pv;
    WolfSSL_CH ch;
    byte cookie[DTLS_COOKIE_SZ];
    static const byte secret[] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
    const byte random[RAN_LEN] = {0};

    pv.major = DTLS_MAJOR;
    pv.minor = DTLSv1_2_MINOR;
    wb_ch_init(&ch, &pv);
    ch.random = random;

    WB_NOTE(CreateDtls12Cookie(ssl, &ch, NULL, sizeof(secret), cookie));
    WB_NOTE(CreateDtls12Cookie(ssl, &ch, secret, 0, cookie));
    WB_NOTE(CreateDtls12Cookie(ssl, &ch, secret, sizeof(secret), cookie));
}

/* ------------------------------------------------- FindExtByType :402 */
/* `if (idx > exts.size || ...)` -- the overrun guard.
 *
 * A well formed extension block never trips this; the caller above always
 * hands FindExtByType a vector whose declared length matches its buffer. The
 * rejecting vector is a block whose inner extension length runs past the end
 * of the block that contains it, which is exactly what a hostile ClientHello
 * carries and what no in-tree caller constructs. */
static void wb_find_ext_by_type(void)
{
    WolfSSL_ConstVector found;
    WolfSSL_ConstVector exts;
    int tlsxFound = 0;
    /* type 0x002b (supported_versions), length 0x0002, body 2 bytes: valid. */
    static const byte ok[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    /* Same header, but the length claims 0x00ff with only 2 bytes present. */
    static const byte overrun[] = {0x00, 0x2b, 0x00, 0xff, 0x03, 0x04};

    exts.elements = ok;
    exts.size = (word32)sizeof(ok);
    WB_NOTE(FindExtByType(&found, TLSX_SUPPORTED_VERSIONS, exts, &tlsxFound));

    exts.elements = overrun;
    exts.size = (word32)sizeof(overrun);
    WB_NOTE(FindExtByType(&found, TLSX_SUPPORTED_VERSIONS, exts, &tlsxFound));
}

/* ----------------------------------------- ClientHelloSanityCheck :984 */
/* `if (ch->pv->minor != DTLSv1_2_MINOR && ch->pv->minor != DTLS_MINOR)`
 *
 * Three minors give both operands a pair: DTLSv1_2_MINOR takes the first
 * operand false, DTLS_MINOR takes the first true and the second false, and a
 * version that is neither takes both true. A handshake only ever produces the
 * first, which is why this needs driving directly. */
static void wb_client_hello_sanity(void)
{
    ProtocolVersion pv;
    WolfSSL_CH ch;
    const byte minors[3] = {DTLSv1_2_MINOR, DTLS_MINOR, 0x0f};
    size_t i;

    for (i = 0; i < sizeof(minors) / sizeof(minors[0]); i++) {
        pv.major = DTLS_MAJOR;
        pv.minor = minors[i];
        wb_ch_init(&ch, &pv);
        WB_NOTE(ClientHelloSanityCheck(&ch, 0));
    }
}

/* ------------------------------------------ TlsCheckSupportedVersion :541 */
/* Compiled in src/dtls.c under WOLFSSL_DTLS13 && !NO_WOLFSSL_SERVER, not under
 * WOLFSSL_DTLS alone -- a DTLS build without 1.3 has no such symbol. */
#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_SERVER)
/* `if (!tlsxFound || tlsxSupportedVersions.elements == NULL)`
 *
 * Operand 0 is isolated by an extension block with no supported_versions in
 * it; the accepting partner carries one. */
static void wb_check_supported_version(WOLFSSL* ssl)
{
    ProtocolVersion pv;
    WolfSSL_CH ch;
    byte isTls13 = 0;
    /* supported_versions carrying a single TLS 1.3 entry */
    static const byte with_sv[] = {0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04};
    /* server_name (0x0000) only: parses cleanly, but no supported_versions */
    static const byte without_sv[] = {0x00, 0x00, 0x00, 0x01, 0x00};

    pv.major = DTLS_MAJOR;
    pv.minor = DTLSv1_2_MINOR;

    wb_ch_init(&ch, &pv);
    ch.extension.elements = without_sv;
    ch.extension.size = (word32)sizeof(without_sv);
    WB_NOTE(TlsCheckSupportedVersion(ssl, &ch, &isTls13));

    wb_ch_init(&ch, &pv);
    ch.extension.elements = with_sv;
    ch.extension.size = (word32)sizeof(with_sv);
    WB_NOTE(TlsCheckSupportedVersion(ssl, &ch, &isTls13));
}
#endif /* WOLFSSL_DTLS13 && !NO_WOLFSSL_SERVER */

/* ------------------------------------------------- DtlsCidGetSize :1146 */
/* Compiled under WOLFSSL_DTLS_CID; a DTLS build without CID has no symbol. */
#ifdef WOLFSSL_DTLS_CID
/* `if (ssl == NULL || size == NULL)` -- both operands, plus the accepting
 * partner with a real ssl and a real out pointer. */
static void wb_cid_get_size(WOLFSSL* ssl)
{
    unsigned int sz = 0;

    WB_NOTE(DtlsCidGetSize(NULL, &sz, 1));
    WB_NOTE(DtlsCidGetSize(ssl, NULL, 1));
    WB_NOTE(DtlsCidGetSize(ssl, &sz, 1));
    WB_NOTE(DtlsCidGetSize(ssl, &sz, 0));
}
#endif /* WOLFSSL_DTLS_CID */

/* --------------------------------------- SendStatelessReplyDtls13 :851 */
/* Compiled under WOLFSSL_DTLS13 && !NO_WOLFSSL_SERVER. */
#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_SERVER)
/* `if (!haveKS || !haveSA || !haveSG)`
 *
 * RFC 8446 section 9.2: a ClientHello that is not resuming must carry
 * key_share, signature_algorithms AND supported_groups. The three flags are set
 * purely by whether FindExtByType locates each extension in ch->extension, so
 * all three operands are drivable by presenting extension blocks that omit one
 * at a time -- no PSK, no handshake state, no IO.
 *
 * Four vectors, which is the minimum for MC/DC over a three-operand OR chain:
 * all three present takes every operand false and is the accepting partner;
 * then each of the three is dropped in turn, and because || short-circuits, the
 * omitted one is the first operand that can be true in its vector. Dropping KS
 * isolates operand 0; dropping SA needs KS present so operand 0 is false first;
 * dropping SG needs both KS and SA present.
 *
 * A real handshake cannot produce these: a conforming client always sends all
 * three, and a non-conforming one is rejected before this point by the record
 * and cookie layers. That is the whole reason this lives in a white-box. */
static void wb_stateless_reply_have_flags(WOLFSSL* ssl)
{
    ProtocolVersion pv;
    WolfSSL_CH ch;
    size_t i;

    /* Minimal well-formed extension bodies. Content beyond the header does not
     * matter for the presence flags -- each parser is entered, and a parse
     * failure exits before line 851 without touching the flags, so a vector
     * that failed to parse would show up as a MISSING pair rather than a false
     * pass. */
    static const byte ext_sa[] = {          /* signature_algorithms 0x000d */
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x04
    };
    static const byte ext_sg[] = {          /* supported_groups     0x000a */
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17
    };
    static const byte ext_ks[] = {          /* key_share            0x0033 */
        0x00, 0x33, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x00
    };

    /* one row per vector: which of KS / SA / SG to include */
    struct wb_reply_row { byte ks, sa, sg; const char* what; };
    static const struct wb_reply_row rows[] = {
        {1, 1, 1, "all three present  -> every operand false"},
        {0, 1, 1, "no key_share       -> operand 0 true"},
        {1, 0, 1, "no sig_algs        -> operand 1 true"},
        {1, 1, 0, "no supported_grps  -> operand 2 true"},
    };

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        byte exts[sizeof(ext_sa) + sizeof(ext_sg) + sizeof(ext_ks)];
        word32 n = 0;
        byte suite[2];

        if (rows[i].sa) {
            XMEMCPY(exts + n, ext_sa, sizeof(ext_sa));
            n += (word32)sizeof(ext_sa);
        }
        if (rows[i].sg) {
            XMEMCPY(exts + n, ext_sg, sizeof(ext_sg));
            n += (word32)sizeof(ext_sg);
        }
        if (rows[i].ks) {
            XMEMCPY(exts + n, ext_ks, sizeof(ext_ks));
            n += (word32)sizeof(ext_ks);
        }

        pv.major = DTLS_MAJOR;
        pv.minor = DTLSv1_3_MINOR;
        wb_ch_init(&ch, &pv);
        /* An even suite size is required by the prologue; two bytes is the
         * smallest legal ClientHello cipher-suite list. */
        suite[0] = 0x13; suite[1] = 0x01;   /* TLS_AES_128_GCM_SHA256 */
        ch.cipherSuite.elements = suite;
        ch.cipherSuite.size = 2;
        ch.extension.elements = exts;
        ch.extension.size = n;

        WB_NOTE(rows[i].what);
        WB_NOTE(SendStatelessReplyDtls13(ssl, &ch));
    }
}
#endif /* WOLFSSL_DTLS13 && !NO_WOLFSSL_SERVER */

/* ------------------------------- SendStatelessReplyDtls13 PSK rows :637/841/845/863/867/876 */
/* Compiled under WOLFSSL_DTLS13 && !NO_WOLFSSL_SERVER && !NO_PSK. */
#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_PSK)
/* PSK server callback: returns a fixed key length (configurable for the
 * >MAX_PSK_KEY_LEN row). FindPskSuite reads ssl->options.server_psk_cb, so the
 * callback is set directly on the ssl object - no ctx plumbing needed. */
static int wb_psk_keylen = 16;
static unsigned int wb_psk_cb(WOLFSSL* ssl, const char* identity,
                              byte* key, word32 max_key_len)
{
    (void)ssl; (void)identity; (void)max_key_len;
    XMEMSET(key, 0x42, 16);
    return (unsigned int)wb_psk_keylen;
}

static void wb_psk_send(WOLFSSL* ssl, const byte* exts, word32 n,
                        byte suite0, byte suite1)
{
    ProtocolVersion pv;
    WolfSSL_CH ch;
    byte suite[2];

    pv.major = DTLS_MAJOR;
    pv.minor = DTLSv1_3_MINOR;
    wb_ch_init(&ch, &pv);
    suite[0] = suite0;
    suite[1] = suite1;
    ch.cipherSuite.elements = suite;
    ch.cipherSuite.size = 2;
    ch.extension.elements = exts;
    ch.extension.size = n;
    WB_NOTE(SendStatelessReplyDtls13(ssl, &ch));
}

/* The PSK path: a valid pre_shared_key extension (identity "A") plus a
 * psk_key_exchange_modes extension. The server PSK callback returns a 16-byte
 * key, so FindPskSuite sets pskInfo.isValid when the CH suite matches the
 * default PSK cipher (TLS_AES_128_GCM_SHA256 = 0x1301). The modes byte selects
 * the PSK_DHE_KE / PSK_KE branch, and the noPskDheKePolicy / onlyPskDheKe
 * options flip the second operand of each. Dropping SG / KS / SA in the
 * no-usable-mode fallback drives the !haveKS / !haveSA / !haveSG operands. */
static void wb_stateless_reply_psk(WOLFSSL* ssl)
{
    static const byte ext_sa[] = {0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x04
    };
    static const byte ext_sg[] = {0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17
    };
    static const byte ext_ks[] = {0x00, 0x33, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17
                                  , 0x00, 0x00};
    static const byte ext_psk[] = {
        0x00, 0x29, 0x00, 0x09, 0x00, 0x07, 0x00, 0x01, 0x41,
        0x00, 0x00, 0x00, 0x00
    };
    static const byte ext_modes_dhe[] = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
    static const byte ext_modes_psk[] = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x00};
    byte exts[64];
    word32 n;

    ssl->options.server_psk_cb = wb_psk_cb;
    ssl->options.noPskDheKePolicy = 0;
    ssl->options.onlyPskDheKe = 0;
    /* The stateless reply refines the suite list from the server's
     * configured suites (WOLFSSL_SUITES(ssl)); an empty list makes
     * FindPskSuiteFromExt's loop a no-op (pskInfo.isValid stays 0).
     * wolfSSL_set_cipher_list does not populate ssl->suites in this
     * build, so set the PSK cipher suite directly. */
    if (ssl->suites == NULL) {
        ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                       DYNAMIC_TYPE_TMP_BUFFER);
        XMEMSET(ssl->suites, 0, sizeof(Suites));
    }
    ssl->suites->suites[0] = 0x13;
    ssl->suites->suites[1] = 0x01;
    ssl->suites->suiteSz = 2;

    /* V1: PSK + DHE + all exts -> 637 c0-T, 841 c1-T, 845 c0-T c1-T */
    n = 0;
    XMEMCPY(exts + n, ext_sa, sizeof(ext_sa)); n += sizeof(ext_sa);
    XMEMCPY(exts + n, ext_sg, sizeof(ext_sg)); n += sizeof(ext_sg);
    XMEMCPY(exts + n, ext_ks, sizeof(ext_ks)); n += sizeof(ext_ks);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_dhe, sizeof(ext_modes_dhe)); n += sizeof(
        ext_modes_dhe);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);

    /* V2: PSK + PSK_KE + all exts -> 845 c0-F, 863 c0-T c1-T */
    n = 0;
    XMEMCPY(exts + n, ext_sa, sizeof(ext_sa)); n += sizeof(ext_sa);
    XMEMCPY(exts + n, ext_sg, sizeof(ext_sg)); n += sizeof(ext_sg);
    XMEMCPY(exts + n, ext_ks, sizeof(ext_ks)); n += sizeof(ext_ks);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_psk, sizeof(ext_modes_psk)); n += sizeof(
        ext_modes_psk);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);

    /* V3: PSK + DHE + noPskDheKePolicy=1 -> 845 c0-T c1-F, 863 c0-F */
    ssl->options.noPskDheKePolicy = 1;
    n = 0;
    XMEMCPY(exts + n, ext_sa, sizeof(ext_sa)); n += sizeof(ext_sa);
    XMEMCPY(exts + n, ext_sg, sizeof(ext_sg)); n += sizeof(ext_sg);
    XMEMCPY(exts + n, ext_ks, sizeof(ext_ks)); n += sizeof(ext_ks);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_dhe, sizeof(ext_modes_dhe)); n += sizeof(
        ext_modes_dhe);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);
    ssl->options.noPskDheKePolicy = 0;

    /* V4: PSK + PSK_KE + onlyPskDheKe=1 -> 863 c0-T c1-F */
    ssl->options.onlyPskDheKe = 1;
    n = 0;
    XMEMCPY(exts + n, ext_sa, sizeof(ext_sa)); n += sizeof(ext_sa);
    XMEMCPY(exts + n, ext_sg, sizeof(ext_sg)); n += sizeof(ext_sg);
    XMEMCPY(exts + n, ext_ks, sizeof(ext_ks)); n += sizeof(ext_ks);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_psk, sizeof(ext_modes_psk)); n += sizeof(
        ext_modes_psk);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);
    ssl->options.onlyPskDheKe = 0;

    /* V5: no usable mode + no SG -> 867 c2-T */
    ssl->options.noPskDheKePolicy = 1;
    n = 0;
    XMEMCPY(exts + n, ext_sa, sizeof(ext_sa)); n += sizeof(ext_sa);
    XMEMCPY(exts + n, ext_ks, sizeof(ext_ks)); n += sizeof(ext_ks);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_dhe, sizeof(ext_modes_dhe)); n += sizeof(
        ext_modes_dhe);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);

    /* V6: no usable mode + no KS -> 867 c0-T */
    n = 0;
    XMEMCPY(exts + n, ext_sa, sizeof(ext_sa)); n += sizeof(ext_sa);
    XMEMCPY(exts + n, ext_sg, sizeof(ext_sg)); n += sizeof(ext_sg);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_dhe, sizeof(ext_modes_dhe)); n += sizeof(
        ext_modes_dhe);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);

    /* V7: no usable mode + no SA -> 867 c1-T */
    n = 0;
    XMEMCPY(exts + n, ext_sg, sizeof(ext_sg)); n += sizeof(ext_sg);
    XMEMCPY(exts + n, ext_ks, sizeof(ext_ks)); n += sizeof(ext_ks);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_dhe, sizeof(ext_modes_dhe)); n += sizeof(
        ext_modes_dhe);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);
    ssl->options.noPskDheKePolicy = 0;

    /* V8: 637 c0-F -> callback returns > MAX_PSK_KEY_LEN (64) */
    wb_psk_keylen = 65;
    n = 0;
    XMEMCPY(exts + n, ext_sa, sizeof(ext_sa)); n += sizeof(ext_sa);
    XMEMCPY(exts + n, ext_sg, sizeof(ext_sg)); n += sizeof(ext_sg);
    XMEMCPY(exts + n, ext_ks, sizeof(ext_ks)); n += sizeof(ext_ks);
    XMEMCPY(exts + n, ext_psk, sizeof(ext_psk)); n += sizeof(ext_psk);
    XMEMCPY(exts + n, ext_modes_dhe, sizeof(ext_modes_dhe)); n += sizeof(
        ext_modes_dhe);
    wb_psk_send(ssl, exts, n, 0x13, 0x01);
    wb_psk_keylen = 16;

    ssl->options.server_psk_cb = NULL;
}
#endif /* WOLFSSL_DTLS13 && !NO_WOLFSSL_SERVER && !NO_PSK */

/* ------------------------------------------- CID rows :1210/1233/1397/1398/1408/1462/1535 */
#ifdef WOLFSSL_DTLS_CID
/* Fixed-size stand-in for ConnectionID (flexible array member); the same
 * layout, so a cast is safe. */
typedef struct WbCid {
    byte length;
    byte id[4];
} WbCid;

static void wb_cid_get_rows(WOLFSSL* ssl)
{
    WbCid id;
    CIDInfo info;
    byte buf[16];
    unsigned char* c0 = NULL;
    int rx;

    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&id, 0, sizeof(id));
    ssl->dtlsCidInfo = &info;

    /* id == NULL: operand 0 true, tx and rx */
    for (rx = 0; rx < 2; rx++) {
        WB_NOTE(DtlsCidGet(ssl, buf, sizeof(buf), rx));
        WB_NOTE(DtlsCidGet0(ssl, &c0, rx));
    }
    /* id->length == 0: operand 1 true */
    id.length = 0;
    info.tx = (ConnectionID*)&id;
    info.rx = (ConnectionID*)&id;
    for (rx = 0; rx < 2; rx++) {
        WB_NOTE(DtlsCidGet(ssl, buf, sizeof(buf), rx));
        WB_NOTE(DtlsCidGet0(ssl, &c0, rx));
    }
    /* accepting partner: a real id */
    id.length = 4;
    id.id[0] = 0x01;
    id.id[1] = 0x02;
    id.id[2] = 0x03;
    id.id[3] = 0x04;
    for (rx = 0; rx < 2; rx++) {
        WB_NOTE(DtlsCidGet(ssl, buf, sizeof(buf), rx));
        WB_NOTE(DtlsCidGet0(ssl, &c0, rx));
    }
    ssl->dtlsCidInfo = NULL;
}

static void wb_cid_replace_tx_rows(WOLFSSL* ssl)
{
    static const byte cid[] = {0x01, 0x02, 0x03};

    WB_NOTE(DtlsCidReplaceTx(NULL, cid, sizeof(cid)));
    WB_NOTE(DtlsCidReplaceTx(ssl, NULL, sizeof(cid)));
    WB_NOTE(DtlsCidReplaceTx(ssl, cid, 0));
    WB_NOTE(DtlsCidReplaceTx(ssl, cid, sizeof(cid)));
}

/* input layout: [cidSz][cid bytes] */
static void wb_cid_parse_rows(WOLFSSL* ssl)
{
    WbCid id;
    CIDInfo* info;
    SecureRenegotiation* scr = NULL;
    byte input[8];
    byte side;
    byte hsState;
    byte hsDone;

    if (wolfSSL_dtls_cid_use(ssl) != WOLFSSL_SUCCESS) {
        return;
    }
    info = DtlsCidGetInfo(ssl);
    if (info == NULL) {
        return;
    }
    id.length = 4;
    id.id[0] = 0x0a;
    id.id[1] = 0x0b;
    id.id[2] = 0x0c;
    id.id[3] = 0x0d;
    info->tx = (ConnectionID*)&id;
    info->negotiated = 1;

    input[0] = 4;
    XMEMCPY(input + 1, id.id, 4);

    /* client side, tx set: re-handshake guard, all clauses true */
    WB_NOTE(TLSX_ConnectionID_Parse(ssl, input, sizeof(input), 1));

    /* client side, tx NULL + negotiated: guard operand 1 true */
    info->tx = NULL;
    WB_NOTE(TLSX_ConnectionID_Parse(ssl, input, sizeof(input), 1));
    info->tx = (ConnectionID*)&id;

    /* server side: guard false, cid compare rows */
    side = ssl->options.side;
    ssl->options.side = WOLFSSL_SERVER_END;
    WB_NOTE(TLSX_ConnectionID_Parse(ssl, input, sizeof(input), 1));
    input[0] = 3;
    WB_NOTE(TLSX_ConnectionID_Parse(ssl, input, sizeof(input), 1));
    input[0] = 4;
    input[1] = 0xff;
    WB_NOTE(TLSX_ConnectionID_Parse(ssl, input, sizeof(input), 1));
    input[1] = id.id[0];
    ssl->options.side = side;

    /* client side + HRR complete: guard operand 1 false */
    ssl->options.serverState = SERVER_HELLO_RETRY_REQUEST_COMPLETE;
    WB_NOTE(TLSX_ConnectionID_Parse(ssl, input, sizeof(input), 1));
    ssl->options.serverState = NULL_STATE;

    /* client side + in-progress SCR: guard operand 2 false */
    scr = (SecureRenegotiation*)XMALLOC(sizeof(*scr), ssl->heap,
                                        DYNAMIC_TYPE_TMP_BUFFER);
    if (scr != NULL) {
        XMEMSET(scr, 0, sizeof(*scr));
        scr->enabled = 1;
        ssl->secure_renegotiation = scr;
        hsState = ssl->options.handShakeState;
        hsDone = ssl->options.handShakeDone;
        ssl->options.handShakeDone = 1;
        ssl->options.handShakeState = SERVER_HELLO_COMPLETE;
        WB_NOTE(TLSX_ConnectionID_Parse(ssl, input, sizeof(input), 1));
        ssl->secure_renegotiation = NULL;
        XFREE(scr, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        ssl->options.handShakeDone = hsDone;
        ssl->options.handShakeState = hsState;
    }
    info->tx = NULL;
    info->negotiated = 0;
}

static void wb_cid_check_rows(WOLFSSL* ssl)
{
    WbCid id;
    CIDInfo info;
    byte input[8];

    input[0] = 0x0a;
    input[1] = 0x0b;
    input[2] = 0x0c;
    input[3] = 0x0d;
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&id, 0, sizeof(id));

    /* info == NULL: operand 0 true */
    ssl->dtlsCidInfo = NULL;
    WB_NOTE(DtlsCIDCheck(ssl, input, sizeof(input)));

    /* info->rx == NULL: operand 1 true */
    ssl->dtlsCidInfo = &info;
    WB_NOTE(DtlsCIDCheck(ssl, input, sizeof(input)));

    /* rx->length == 0: operand 2 true */
    id.length = 0;
    info.rx = (ConnectionID*)&id;
    WB_NOTE(DtlsCIDCheck(ssl, input, sizeof(input)));

    /* accepting partner: rx set + matching input */
    id.length = 4;
    XMEMCPY(id.id, input, 4);
    WB_NOTE(DtlsCIDCheck(ssl, input, sizeof(input)));
    ssl->dtlsCidInfo = NULL;
}
#endif /* WOLFSSL_DTLS_CID */

/* ------------------------------------------- cookie rows :307/330 */
#ifdef WOLFSSL_DTLS13
static void wb_cookie_rows(WOLFSSL* ssl)
{
    WolfSSL_CH ch;
    ProtocolVersion pv;
    Hmac hmac;
    static const byte random[RAN_LEN] = {0};
    byte cookieGood = 0;
    byte secret[32];
    byte secret2[32];
    byte hash[32];
    byte mac[32];
    byte cookie[64];
    byte cookie12[DTLS_COOKIE_SZ];
    int ret;

    pv.major = DTLS_MAJOR;
    pv.minor = DTLSv1_2_MINOR;
    wb_ch_init(&ch, &pv);
    ch.random = random;
    XMEMSET(secret, 0x42, sizeof(secret));
    XMEMSET(secret2, 0x7e, sizeof(secret2));
    XMEMSET(hash, 0x11, sizeof(hash));

    /* -- isTls13 = 1 :307 -- */
    /* no secrets: TlsCheckCookie -> COOKIE_ERROR. The length is
     * big-endian on the wire; ato16 reads it that way. */
    ch.cookieExt.elements = cookie;
    cookie[0] = 0;
    cookie[1] = 4;
    XMEMSET(cookie + 2, 0, 4);
    ch.cookieExt.size = 6;
    WB_NOTE(CheckDtlsCookie(ssl, &ch, 1, &cookieGood));

    /* primary secret set, short cookie -> HRR_COOKIE_ERROR */
    ssl->buffers.tls13CookieSecret.buffer = secret;
    ssl->buffers.tls13CookieSecret.length = sizeof(secret);
    WB_NOTE(CheckDtlsCookie(ssl, &ch, 1, &cookieGood));

    /* primary secret set, valid cookie -> ret > 0 */
    ret = wc_HmacInit(&hmac, ssl->heap, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_HmacSetKey(&hmac, WC_SHA256, secret, sizeof(secret));
    }
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, hash, sizeof(hash));
    }
    if (ret == 0) {
        ret = wc_HmacFinal(&hmac, mac);
    }
    wc_HmacFree(&hmac);
    if (ret == 0) {
        XMEMCPY(cookie, hash, 32);
        XMEMCPY(cookie + 32, mac, 32);
        cookie[0] = 0;
        cookie[1] = 64;
        ch.cookieExt.size = 66;
        WB_NOTE(CheckDtlsCookie(ssl, &ch, 1, &cookieGood));
    }
    ssl->buffers.tls13CookieSecret.buffer = NULL;
    ssl->buffers.tls13CookieSecret.length = 0;

    /* -- isTls13 = 0 :330 -- */
    ssl->buffers.dtlsCookieSecret.buffer = secret;
    ssl->buffers.dtlsCookieSecret.length = sizeof(secret);
    /* good cookie: elements is a SEPARATE buffer from ch.dtls12cookie,
     * precomputed with the same secret so the constant compare matches */
    ch.cookie.elements = cookie12;
    ch.cookie.size = DTLS_COOKIE_SZ;
    ch.dtls12cookieSet = 0;
    ret = CreateDtls12Cookie(ssl, &ch, secret, sizeof(secret), cookie12);
    if (ret == 0) {
        WB_NOTE(CheckDtlsCookie(ssl, &ch, 0, &cookieGood));
    }
    /* bad cookie, no secondary: operand 1 false */
    XMEMSET(cookie12, 0, DTLS_COOKIE_SZ);
    ch.dtls12cookieSet = 0;
    WB_NOTE(CheckDtlsCookie(ssl, &ch, 0, &cookieGood));
    /* bad cookie, secondary length > 0: operand 2 true */
    ssl->buffers.dtlsCookieSecretSecondary.buffer = secret2;
    ssl->buffers.dtlsCookieSecretSecondary.length = sizeof(secret2);
    WB_NOTE(CheckDtlsCookie(ssl, &ch, 0, &cookieGood));
    /* bad cookie, secondary length == 0: operand 2 false */
    ssl->buffers.dtlsCookieSecretSecondary.length = 0;
    WB_NOTE(CheckDtlsCookie(ssl, &ch, 0, &cookieGood));
    ssl->buffers.dtlsCookieSecretSecondary.buffer = NULL;
    ssl->buffers.dtlsCookieSecret.buffer = NULL;
    ssl->buffers.dtlsCookieSecret.length = 0;
}
#endif /* WOLFSSL_DTLS13 */

/* ---------------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* Every bail point says so. An earlier revision returned 0 silently when
     * the fixture could not be built, and the harness scored it 0/56 -- a
     * driver that runs, exits clean and covers nothing looks exactly like a
     * driver with nothing to say. It has to be possible to tell those apart
     * from the log alone. */
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("dtls white-box: wolfSSL_Init failed\n");
        goto done;
    }

    /* CLIENT method deliberately. A server WOLFSSL needs a certificate and key
     * before wolfSSL_new() will hand one back, and this driver has no business
     * loading credentials to reach argument guards that never look at them.
     * The static helpers driven here take ssl only to read heap/version fields. */
#ifndef NO_WOLFSSL_CLIENT
    ctx = wolfSSL_CTX_new(wolfDTLS_client_method());
#else
    ctx = wolfSSL_CTX_new(wolfDTLS_server_method());
#endif
    if (ctx == NULL) {
        printf("dtls white-box: CTX_new failed\n");
        goto done;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("dtls white-box: wolfSSL_new failed\n");
        goto done;
    }

    wb_create_dtls12_cookie(ssl);
    wb_find_ext_by_type();
    wb_client_hello_sanity();
#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_SERVER)
    wb_check_supported_version(ssl);
#endif
#ifdef WOLFSSL_DTLS_CID
    wb_cid_get_size(ssl);
    wb_cid_get_rows(ssl);
    wb_cid_replace_tx_rows(ssl);
    wb_cid_parse_rows(ssl);
    wb_cid_check_rows(ssl);
#endif
#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_SERVER)
    wb_stateless_reply_have_flags(ssl);
    wb_stateless_reply_psk(ssl);
#endif
#ifdef WOLFSSL_DTLS13
    wb_cookie_rows(ssl);
#endif

    printf("dtls white-box: %d vectors driven\n", g_checks);

done:
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    /* Always 0: a non-zero exit discards the whole variant's coverage. */
    return 0;
}

#else /* !WOLFSSL_DTLS || WOLFCRYPT_ONLY */

int main(void)
{
    printf("dtls white-box: skipped (WOLFSSL_DTLS not built)\n");
    return 0;
}

#endif
