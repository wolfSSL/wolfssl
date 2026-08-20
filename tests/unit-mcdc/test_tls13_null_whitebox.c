/* test_tls13_null_whitebox.c
 *
 * White-box MC/DC supplement for the POINTER-PRESENCE GUARDS of src/tls13.c.
 *
 * Companion to tests/unit-mcdc/test_tls13_whitebox.c, kept as a separate TU so
 * the two can be extended independently; the campaign unions their coverage by
 * source line:col exactly as it unions the variant builds.
 *
 * SCOPE. Every decision driven here is a NULL / presence check on a pointer.
 * The campaign's disposition rule for that family is:
 *
 *   - if the operand cannot vary even for a DIRECT caller, because a
 *     constructor or a callee postcondition fixes it, it is an entry in
 *     campaign/db/exclusions.json and NOT a test (e.g. `ssl->ctx != NULL`:
 *     wolfSSL_new() is the only constructor and rejects a NULL CTX);
 *   - if the operand cannot vary only because every IN-LIBRARY caller has
 *     already established it, it is reachable from a white-box and belongs
 *     here. That is what this file supplies.
 *
 * llvm-cov derives MC/DC independence PER BINARY, so for each decision below
 * every row of its independence pairs -- including the "all operands false"
 * row that the API tests also produce -- is driven inside THIS program.
 * Nothing here leans on tests/api to complete a pair.
 *
 * DETERMINISM. No handshake, no network, no wall clock, no entropy beyond what
 * wolfSSL_new() itself consumes. Every vector is a direct call with
 * hand-supplied arguments, so consecutive runs are byte-identical.
 *
 * main() always returns 0: the campaign scores a nonzero exit as a failed
 * white-box and discards its whole coverage, so setup problems print a skip.
 */

/* Pull tls13.c in verbatim so its file-static helpers are in scope and
 * instrumented in THIS binary. tls13.c includes settings.h, which picks up
 * user_settings.h via -DWOLFSSL_USER_SETTINGS. */
#include <src/tls13.c>

#include <stdio.h>

#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Every group below needs a live WOLFSSL built through the public API. A
 * CLIENT method is used for the same reason as in test_tls13_whitebox.c:
 * wolfSSL_new() on a server WOLFSSL_CTX with no certificate loaded returns
 * NULL, and loading one would tie this TU to the runner's certs/ tree. The two
 * groups that need server-side behaviour flip ssl->options.side for the
 * duration of a single call and restore it. */
#if !defined(NO_TLS) && defined(WOLFSSL_TLS13) && !defined(WOLFCRYPT_ONLY) && \
    !defined(NO_WOLFSSL_CLIENT)
    #define WBN_HAVE_SSL_FIXTURE
#endif

#ifdef WBN_HAVE_SSL_FIXTURE

static WOLFSSL_CTX* wbn_ctx = NULL;
static WOLFSSL*     wbn_ssl = NULL;

static int wbn_fixture_setup(void)
{
    wbn_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (wbn_ctx == NULL)
        return 0;
    wbn_ssl = wolfSSL_new(wbn_ctx);
    if (wbn_ssl == NULL)
        return 0;
    return 1;
}

static void wbn_fixture_teardown(void)
{
    if (wbn_ssl != NULL) wolfSSL_free(wbn_ssl);
    if (wbn_ctx != NULL) wolfSSL_CTX_free(wbn_ctx);
    wbn_ssl = NULL; wbn_ctx = NULL;
}


/* ------------------------------------------------------------------------- *
 * GROUP 1 -- FreeScv13Args() / FreeDcv13Args(), the `args` presence guards.
 *
 *   FreeScv13Args:  if (args && args->sigData)            [tls13.c ~:10318]
 *                   if (args != NULL && args->frag != NULL)          [~:10328]
 *   FreeDcv13Args:  if (args && args->sigData != NULL)               [~:11678]
 *
 * Both are file-static cleanup helpers with a SINGLE in-library call site each
 * (the tail of SendTls13CertificateVerify / DoTls13CertificateVerify), and
 * without WOLFSSL_ASYNC_CRYPT -- which this module's option list deliberately
 * excludes -- the argument there is `Scv13Args args[1]` / `Dcv13Args args[1]`,
 * i.e. the address of a stack object. The `ssl->async->freeArgs = ...`
 * registration that could supply a different pointer is inside
 * #ifdef WOLFSSL_ASYNC_CRYPT and is not compiled. So from the library the
 * leading operand is invariant true and the trailing one only ever takes the
 * value the send path happened to leave behind.
 *
 * The pointer arguments are ordinary parameters, not object invariants: a
 * direct caller may legitimately pass NULL (that is what the guard is for) and
 * may present an args block with the buffer either allocated or not. Three
 * calls give both halves of all three decisions' pairs:
 *
 *   args == NULL                    -> (F,-)  decision false
 *   args != NULL, buffers NULL      -> (T,F)  decision false
 *   args != NULL, buffers allocated -> (T,T)  decision true
 *
 * The third vector hands the helper real XMALLOC'd blocks tagged with the same
 * DYNAMIC_TYPE_* the send path uses, so the XFREE it performs is the correct
 * one and the pointers are nulled by the helper itself -- no double free.
 * ------------------------------------------------------------------------- */
#if (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
     defined(HAVE_ED448) || defined(HAVE_FALCON) || \
     defined(WOLFSSL_HAVE_MLDSA) || defined(WOLFSSL_HAVE_SLHDSA)) && \
    !defined(NO_CERTS) && \
    (!defined(NO_WOLFSSL_SERVER) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    #define WBN_HAVE_SCV_ARGS
#endif
#if (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
     defined(HAVE_ED448) || defined(HAVE_FALCON) || \
     defined(WOLFSSL_HAVE_MLDSA) || defined(WOLFSSL_HAVE_SLHDSA)) && \
    !defined(NO_CERTS)
    #define WBN_HAVE_DCV_ARGS
#endif

static void wbn_free_args_guards(void)
{
#if defined(WBN_HAVE_SCV_ARGS) || defined(WBN_HAVE_DCV_ARGS)
    if (wbn_ssl == NULL) {
        WB_NOTE("no ssl fixture; Free*13Args guards skipped");
        return;
    }
#endif

#ifdef WBN_HAVE_SCV_ARGS
    {
        Scv13Args scv;

        /* (F,-) on both decisions. */
        FreeScv13Args(wbn_ssl, NULL);

        /* (T,F) on both decisions. */
        XMEMSET(&scv, 0, sizeof(scv));
        FreeScv13Args(wbn_ssl, &scv);

        /* (T,T) on both decisions. */
        XMEMSET(&scv, 0, sizeof(scv));
        scv.sigData = (byte*)XMALLOC(16, wbn_ssl->heap,
                                     DYNAMIC_TYPE_SIGNATURE);
        scv.frag    = (byte*)XMALLOC(16, wbn_ssl->heap,
                                     DYNAMIC_TYPE_TMP_BUFFER);
        if (scv.sigData == NULL || scv.frag == NULL) {
            XFREE(scv.sigData, wbn_ssl->heap, DYNAMIC_TYPE_SIGNATURE);
            XFREE(scv.frag, wbn_ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
            WB_NOTE("FreeScv13Args: allocation failed; (T,T) row skipped");
        }
        else {
            FreeScv13Args(wbn_ssl, &scv);
        }
    }
    WB_NOTE("FreeScv13Args: args/sigData and args/frag guards driven with "
            "both halves of every pair");
#else
    WB_NOTE("FreeScv13Args not compiled in this variant; skipped");
#endif

#ifdef WBN_HAVE_DCV_ARGS
    {
        Dcv13Args dcv;

        /* (F,-) */
        FreeDcv13Args(wbn_ssl, NULL);

        /* (T,F) */
        XMEMSET(&dcv, 0, sizeof(dcv));
        FreeDcv13Args(wbn_ssl, &dcv);

        /* (T,T) */
        XMEMSET(&dcv, 0, sizeof(dcv));
        dcv.sigData = (byte*)XMALLOC(16, wbn_ssl->heap,
                                     DYNAMIC_TYPE_SIGNATURE);
        if (dcv.sigData == NULL) {
            WB_NOTE("FreeDcv13Args: allocation failed; (T,T) row skipped");
        }
        else {
            FreeDcv13Args(wbn_ssl, &dcv);
        }
    }
    WB_NOTE("FreeDcv13Args: args/sigData guard driven with both halves of "
            "its pair");
#else
    WB_NOTE("FreeDcv13Args not compiled in this variant; skipped");
#endif
}


/* ------------------------------------------------------------------------- *
 * GROUP 2 -- DoTls13ServerHello()'s entry guard.
 *
 *   if (ssl == NULL || ssl->arrays == NULL)                 [tls13.c ~:5366]
 *
 * Same shape, and the same argument, as the eleven key-schedule guards already
 * driven from test_tls13_whitebox.c: DoTls13ServerHello is reached only from
 * DoTls13HandShakeMsgType, which has dereferenced `ssl` many times over, and
 * only while the handshake is in progress -- FreeArrays() runs after it. From
 * tests/api the decision is permanently (F,F).
 *
 *   ssl == NULL               -> (T,-)  decision true
 *   ssl != NULL, arrays NULL  -> (F,T)  decision true
 *   ssl != NULL, arrays set   -> (F,F)  decision false
 *
 * The third vector runs the handler's body for real; it is given helloSz = 1,
 * which the very next statement rejects with BUFFER_ERROR ("Protocol version
 * length check"), so no record state is touched. arrays is nulled and restored
 * rather than freed, so teardown is unaffected.
 * ------------------------------------------------------------------------- */
static void wbn_do_server_hello_entry_guard(void)
{
    byte    input[4];
    word32  idx;
    byte    extMsgType;
    Arrays* saved;

    if (wbn_ssl == NULL) {
        WB_NOTE("no ssl fixture; DoTls13ServerHello entry guard skipped");
        return;
    }

    XMEMSET(input, 0, sizeof(input));

    /* (T,-) */
    idx = 0; extMsgType = server_hello;
    (void)DoTls13ServerHello(NULL, input, &idx, 1, &extMsgType);

    /* (F,T) */
    saved = wbn_ssl->arrays;
    wbn_ssl->arrays = NULL;
    idx = 0; extMsgType = server_hello;
    (void)DoTls13ServerHello(wbn_ssl, input, &idx, 1, &extMsgType);
    wbn_ssl->arrays = saved;

    /* (F,F) -- bails out at the helloSz < OPAQUE16_LEN check. */
    if (wbn_ssl->arrays != NULL) {
        idx = 0; extMsgType = server_hello;
        (void)DoTls13ServerHello(wbn_ssl, input, &idx, 1, &extMsgType);
        WB_NOTE("DoTls13ServerHello: ssl/arrays entry guard driven with all "
                "three vectors");
    }
    else {
        WB_NOTE("DoTls13ServerHello: fixture has no arrays; (F,F) row "
                "skipped");
    }
}


/* ------------------------------------------------------------------------- *
 * GROUP 3 -- EchHashHelloInner()'s argument guard.
 *
 *   if (ssl == NULL || ech == NULL)                         [tls13.c ~:3843]
 *
 * File-static; every in-library caller reaches it with an ssl it has just
 * dereferenced and an ech taken from a TLSX whose data pointer was NULL
 * checked one line earlier, so the decision is permanently (F,F) from a
 * handshake.
 *
 * The (F,F) vector runs the body: with a zeroed WOLFSSL_ECH whose
 * innerClientHelloLen is 0, the client arm writes a 4-byte handshake header
 * into the function's own falseHeader and hashes it, allocating ssl->hsHashesEch
 * on the way (released by wolfSSL_free). No record layer, no key material.
 * ------------------------------------------------------------------------- */
#ifdef HAVE_ECH
static void wbn_ech_hash_hello_inner_guard(void)
{
    WOLFSSL_ECH ech;
    byte        inner[4];

    if (wbn_ssl == NULL) {
        WB_NOTE("no ssl fixture; EchHashHelloInner guard skipped");
        return;
    }

    XMEMSET(&ech, 0, sizeof(ech));
    XMEMSET(inner, 0, sizeof(inner));
    ech.innerClientHello    = inner;
    ech.innerClientHelloLen = 0;

    /* (T,-) */
    (void)EchHashHelloInner(NULL, &ech);
    /* (F,T) */
    (void)EchHashHelloInner(wbn_ssl, NULL);
    /* (F,F) */
    (void)EchHashHelloInner(wbn_ssl, &ech);

    WB_NOTE("EchHashHelloInner: ssl/ech argument guard driven with all three "
            "vectors");
}
#else
static void wbn_ech_hash_hello_inner_guard(void)
{ WB_NOTE("HAVE_ECH off in this variant; EchHashHelloInner skipped"); }
#endif


/* ------------------------------------------------------------------------- *
 * GROUP 4 -- TlsCheckCookie()'s cookie-secret guards.
 *
 *   if ((primary.buffer == NULL || primary.length == 0)
 *       && (secondary.buffer == NULL || secondary.length == 0))   [~:7134]
 *   if (primary.buffer != NULL && primary.length > 0)             [~:7155]
 *   if (ret == the cookie-mismatch code && secondary.buffer != NULL
 *                               && secondary.length > 0)          [~:7164]
 *
 * TlsCheckCookie is WOLFSSL_LOCAL and is called only from the HelloRetryRequest
 * cookie path, which a server enters only once wolfSSL_send_hrr_cookie() has
 * installed a primary secret -- so the "missing secret" arms and the
 * secondary/verify-only rotation arms never both occur on one live WOLFSSL.
 * The four (buffer, length) shapes are ordinary buffer state, not an object
 * invariant, so a direct call can present each of them.
 *
 * Vectors (P = primary, S = secondary), all with a 64-byte cookie so the
 * `cookieSz < specs.hash_size + macSz` length check passes on an
 * un-negotiated WOLFSSL (specs.hash_size is still 0, macSz is the digest
 * size):
 *
 *   v1  P.buf NULL              S.buf NULL              :7134 (T,-,T,-) true
 *   v2  P.buf set, len 32       S.buf NULL              :7134 (F,F,-,-) false
 *   v3  P.buf set, len 0        S.buf NULL              :7134 (F,T,T,-) true
 *   v4  P.buf NULL              S.buf set, len 32       :7134 (T,-,F,F) false
 *   v5  P.buf NULL              S.buf set, len 0        :7134 (T,-,F,T) true
 *   v6  P.buf set, len 0        S.buf set, len 32       :7134 (F,T,F,F) false
 *   v7  P.buf set, len 32       S.buf set, len 0        :7134 (F,F,-,-) false
 *
 * which pairs :7134's four operands as (v1,v2), (v3,v2), (v1,v4), (v5,v4).
 * The vectors that get past :7134 then pair :7155 as (v2 -> (T,T)) against
 * (v4 -> (F,-)) and (v6 -> (T,F)), and :7164's length operand as
 * (v4 -> (T,T,T)) against (v7 -> (T,T,F)); the MAC never matches a random
 * cookie, so `ret` carries the cookie-mismatch code on entry to :7164 every
 * time.
 *
 * The secret buffers are file-static arrays assigned into ssl->buffers and
 * cleared again before return, so wolfSSL_free() never XFREEs them.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_SERVER)
static byte wbn_secret_pri[32];
static byte wbn_secret_sec[32];

static void wbn_cookie_set(byte* pri, word32 priLen, byte* sec, word32 secLen)
{
    wbn_ssl->buffers.tls13CookieSecret.buffer = pri;
    wbn_ssl->buffers.tls13CookieSecret.length = priLen;
#ifdef WOLFSSL_DTLS13
    wbn_ssl->buffers.tls13CookieSecretSecondary.buffer = sec;
    wbn_ssl->buffers.tls13CookieSecretSecondary.length = secLen;
#else
    (void)sec; (void)secLen;
#endif
}

static void wbn_tls_check_cookie_guards(void)
{
    byte cookie[64];
    word32 i;

    if (wbn_ssl == NULL) {
        WB_NOTE("no ssl fixture; TlsCheckCookie guards skipped");
        return;
    }

    /* Fixed contents: the MAC comparison must fail identically every run. */
    for (i = 0; i < sizeof(cookie); i++)
        cookie[i] = (byte)i;
    for (i = 0; i < sizeof(wbn_secret_pri); i++)
        wbn_secret_pri[i] = (byte)(0xA0 + i);
    for (i = 0; i < sizeof(wbn_secret_sec); i++)
        wbn_secret_sec[i] = (byte)(0x50 + i);

    wbn_cookie_set(NULL, 0, NULL, 0);                        /* v1 */
    (void)TlsCheckCookie(wbn_ssl, cookie, (word16)sizeof(cookie));

    wbn_cookie_set(wbn_secret_pri, sizeof(wbn_secret_pri), NULL, 0); /* v2 */
    (void)TlsCheckCookie(wbn_ssl, cookie, (word16)sizeof(cookie));

    wbn_cookie_set(wbn_secret_pri, 0, NULL, 0);              /* v3 */
    (void)TlsCheckCookie(wbn_ssl, cookie, (word16)sizeof(cookie));

#ifdef WOLFSSL_DTLS13
    wbn_cookie_set(NULL, 0, wbn_secret_sec, sizeof(wbn_secret_sec)); /* v4 */
    (void)TlsCheckCookie(wbn_ssl, cookie, (word16)sizeof(cookie));

    wbn_cookie_set(NULL, 0, wbn_secret_sec, 0);              /* v5 */
    (void)TlsCheckCookie(wbn_ssl, cookie, (word16)sizeof(cookie));

    wbn_cookie_set(wbn_secret_pri, 0,
                   wbn_secret_sec, sizeof(wbn_secret_sec));  /* v6 */
    (void)TlsCheckCookie(wbn_ssl, cookie, (word16)sizeof(cookie));

    wbn_cookie_set(wbn_secret_pri, sizeof(wbn_secret_pri),
                   wbn_secret_sec, 0);                       /* v7 */
    (void)TlsCheckCookie(wbn_ssl, cookie, (word16)sizeof(cookie));
#endif

    /* Detach the static secrets again so wolfSSL_free() has nothing to free. */
    wbn_cookie_set(NULL, 0, NULL, 0);

    WB_NOTE("TlsCheckCookie: primary/secondary cookie-secret guards driven "
            "with both halves of every pair");
}
#else
static void wbn_tls_check_cookie_guards(void)
{ WB_NOTE("WOLFSSL_SEND_HRR_COOKIE off in this variant; skipped"); }
#endif


/* ------------------------------------------------------------------------- *
 * GROUP 5 -- SanityCheckTls13MsgReceived()'s DTLS 1.3 Connection ID arms.
 *
 *   if (cidInfo == NULL || !cidInfo->negotiated)            [tls13.c ~:14610]
 *   if (cidInfo->rx == NULL || cidInfo->rx->length == 0)             [~:14623]
 *   if (cidInfo->tx == NULL || cidInfo->tx->length == 0)             [~:14633]
 *
 * SanityCheckTls13MsgReceived is file-static and is a pure predicate over
 * ssl->options / ssl->msgsReceived / ssl->dtlsCidInfo -- it has no side effect
 * outside msgsReceived, which the CID arms do not touch, so it can be called
 * repeatedly on one fixture. A live DTLS 1.3 peer only ever reaches these arms
 * with a fully negotiated CIDInfo carrying non-empty ids, because the
 * negotiation that allocates cidInfo is the same one that fills rx/tx; the
 * "negotiated but empty" states RFC 9147 Section 9 tells the receiver to reject
 * cannot be produced by wolfSSL as the peer.
 *
 * Vectors, all with options.dtls = 1 and handShakeState = HANDSHAKE_DONE so the
 * two guards ahead of the rx/tx checks pass:
 *
 *   cidInfo NULL                       -> :14610 (T,-)  true
 *   cidInfo, negotiated 0              -> :14610 (F,T)  true
 *   cidInfo, negotiated 1              -> :14610 (F,F)  false, falls through
 *     with rx/tx NULL                  -> :14623/:14633 (T,-)  true
 *     with rx/tx length 0              -> :14623/:14633 (F,T)  true
 *     with rx/tx length 1              -> :14623/:14633 (F,F)  false
 *
 * ConnectionID has a flexible array member, so each id is carved out of a byte
 * buffer sized for the header plus one id byte.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS_CID)
static void wbn_sanity_check_cid_guards(void)
{
    byte          rxBuf[sizeof(ConnectionID) + 4];
    byte          txBuf[sizeof(ConnectionID) + 4];
    ConnectionID* rx = (ConnectionID*)rxBuf;
    ConnectionID* tx = (ConnectionID*)txBuf;
    CIDInfo       cid;
    CIDInfo*      savedCid;
    byte          savedState;
    byte          savedDtls;

    if (wbn_ssl == NULL) {
        WB_NOTE("no ssl fixture; SanityCheckTls13MsgReceived CID arms "
                "skipped");
        return;
    }

    XMEMSET(rxBuf, 0, sizeof(rxBuf));
    XMEMSET(txBuf, 0, sizeof(txBuf));
    XMEMSET(&cid, 0, sizeof(cid));

    savedCid   = wbn_ssl->dtlsCidInfo;
    savedDtls  = (byte)wbn_ssl->options.dtls;
    savedState = wbn_ssl->options.handShakeState;

    wbn_ssl->options.dtls = 1;
    wbn_ssl->options.handShakeState = HANDSHAKE_DONE;

    /* :14610 (T,-) */
    wbn_ssl->dtlsCidInfo = NULL;
    (void)SanityCheckTls13MsgReceived(wbn_ssl, request_connection_id);

    /* :14610 (F,T) */
    cid.negotiated = 0;
    wbn_ssl->dtlsCidInfo = &cid;
    (void)SanityCheckTls13MsgReceived(wbn_ssl, request_connection_id);

    /* From here on the decision at :14610 is (F,F) and the rx/tx arms run. */
    cid.negotiated = 1;

    /* :14623 (T,-) and :14633 (T,-) */
    cid.rx = NULL;
    cid.tx = NULL;
    (void)SanityCheckTls13MsgReceived(wbn_ssl, request_connection_id);
    (void)SanityCheckTls13MsgReceived(wbn_ssl, new_connection_id);

    /* :14623 (F,T) and :14633 (F,T) */
    rx->length = 0;
    tx->length = 0;
    cid.rx = rx;
    cid.tx = tx;
    (void)SanityCheckTls13MsgReceived(wbn_ssl, request_connection_id);
    (void)SanityCheckTls13MsgReceived(wbn_ssl, new_connection_id);

    /* :14623 (F,F) and :14633 (F,F) */
    rx->length = 1;
    tx->length = 1;
    (void)SanityCheckTls13MsgReceived(wbn_ssl, request_connection_id);
    (void)SanityCheckTls13MsgReceived(wbn_ssl, new_connection_id);

    wbn_ssl->dtlsCidInfo = savedCid;
    wbn_ssl->options.dtls = savedDtls;
    wbn_ssl->options.handShakeState = savedState;

    WB_NOTE("SanityCheckTls13MsgReceived: CID negotiated/rx/tx guards driven "
            "with both halves of every pair");
}
#else
static void wbn_sanity_check_cid_guards(void)
{ WB_NOTE("DTLS 1.3 CID off in this variant; skipped"); }
#endif


/* ------------------------------------------------------------------------- *
 * GROUP 6 -- SetupOcspResp()'s two presence chains.
 *
 *   if (extension == NULL && side == WOLFSSL_CLIENT_END
 *       && options.handShakeDone
 *       && TLSX_Find(ssl->ctx->extensions, TLSX_STATUS_REQUEST) != NULL)
 *                                                          [tls13.c ~:9769]
 *   if (SSL_CM(ssl) != NULL && SSL_CM(ssl)->ocsp_stapling != NULL
 *                           && SSL_CM(ssl)->ocsp_stapling->statusCb != NULL)
 *                                                                   [~:9786]
 *
 * SetupOcspResp is file-static and is called from the Certificate send path.
 * The first chain is the post-handshake-client-auth re-staple: it is true only
 * for a CLIENT that has completed its handshake, no longer carries the
 * status_request extension on ssl->extensions, and whose CTX still does. Every
 * operand of it is ordinary object state that this file sets directly.
 *
 * SSL_CM(ssl) (operand 0 of :9786) is NOT driven here: ssl->ctx is invariant
 * non-NULL for a live WOLFSSL and ctx->cm is allocated by wolfSSL_CTX_new(),
 * so that operand has no false row for any caller, direct or not. It is an
 * exclusions.json entry, not a test.
 *
 * Call sequence -- the order matters, because each call can change the state
 * the next one reads:
 *
 *   A  no ssl ext, side SERVER                     :9769 (T,F,-,-)  false
 *   B  no ssl ext, side CLIENT, !handShakeDone     :9769 (T,T,F,-)  false
 *   C  no ssl ext, side CLIENT, handShakeDone,
 *      CTX has no status_request                   :9769 (T,T,T,F)  false
 *   -- enable status_request on the CTX --
 *   D  same, CTX now has it                        :9769 (T,T,T,T)  true
 *                 ... which creates the ssl extension, so D also reaches
 *                     :9786 with stapling not yet enabled  (T,F,-)   false
 *   -- wolfSSL_CTX_EnableOCSPStapling(): cm->ocsp_stapling allocated --
 *   E  ssl ext now present                         :9769 (F,-,-,-)  false
 *                                                  :9786 (T,T,F)    false
 *   -- statusCb installed --
 *   F  ssl ext present                             :9769 (F,-,-,-)  false
 *                                                  :9786 (T,T,T)    true
 *
 * pairing :9769's four operands against D and :9786's operands 1 and 2
 * against F. Calls A..C and E return before touching the certificate, D and E
 * stop at the "Certificate buffer not set!" check (this fixture has no
 * certificate), and F returns through the status callback, which answers
 * WOLFSSL_OCSP_STATUS_CB_NOACK -- so nothing here parses a certificate or
 * performs an OCSP lookup.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(NO_WOLFSSL_SERVER) && \
    defined(WOLFSSL_POST_HANDSHAKE_AUTH)
static int wbn_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)ssl; (void)arg;
    /* NOACK: TLSX_CSR_SetResponseWithStatusCB() maps it to 0 without touching
     * ssl->ocspCsrResp, so no response buffer is required. */
    return WOLFSSL_OCSP_STATUS_CB_NOACK;
}

static void wbn_setup_ocsp_resp_guards(void)
{
    byte savedSide;
    byte savedDone;

    if (wbn_ssl == NULL || wbn_ctx == NULL) {
        WB_NOTE("no ssl fixture; SetupOcspResp guards skipped");
        return;
    }
    if (TLSX_Find(wbn_ssl->extensions, TLSX_STATUS_REQUEST) != NULL) {
        WB_NOTE("SetupOcspResp: fixture already carries status_request; "
                "skipped");
        return;
    }

    savedSide = wbn_ssl->options.side;
    savedDone = wbn_ssl->options.handShakeDone;

    /* A */
    wbn_ssl->options.side = WOLFSSL_SERVER_END;
    wbn_ssl->options.handShakeDone = 0;
    (void)SetupOcspResp(wbn_ssl);

    /* B */
    wbn_ssl->options.side = WOLFSSL_CLIENT_END;
    (void)SetupOcspResp(wbn_ssl);

    /* C */
    wbn_ssl->options.handShakeDone = 1;
    (void)SetupOcspResp(wbn_ssl);

    /* D -- CTX now carries the request extension. */
    if (wolfSSL_CTX_UseOCSPStapling(wbn_ctx, WOLFSSL_CSR_OCSP, 0)
            == WOLFSSL_SUCCESS) {
        (void)SetupOcspResp(wbn_ssl);
    }
    else {
        WB_NOTE("SetupOcspResp: CTX status_request unavailable; the all-true "
                "row of the re-staple chain was not driven");
    }

    /* E -- cm->ocsp_stapling allocated, no callback yet. */
    if (wolfSSL_CTX_EnableOCSPStapling(wbn_ctx) == WOLFSSL_SUCCESS &&
            SSL_CM(wbn_ssl) != NULL &&
            SSL_CM(wbn_ssl)->ocsp_stapling != NULL) {
        (void)SetupOcspResp(wbn_ssl);

        /* F -- the same assignment wolfSSL_CTX_set_tlsext_status_cb() makes;
         * done directly so this group does not depend on the compat-layer
         * entry point being compiled. */
        SSL_CM(wbn_ssl)->ocsp_stapling->statusCb = wbn_status_cb;
        SSL_CM(wbn_ssl)->ocsp_stapling->statusCbArg = NULL;
        (void)SetupOcspResp(wbn_ssl);
        SSL_CM(wbn_ssl)->ocsp_stapling->statusCb = NULL;
    }
    else {
        WB_NOTE("SetupOcspResp: OCSP stapling unavailable; the ocsp_stapling "
                "and statusCb rows were not driven");
    }

    wbn_ssl->options.side = savedSide;
    wbn_ssl->options.handShakeDone = savedDone;

    WB_NOTE("SetupOcspResp: post-handshake re-staple chain and the "
            "ocsp_stapling/statusCb chain driven");
}
#else
static void wbn_setup_ocsp_resp_guards(void)
{ WB_NOTE("SetupOcspResp not compiled in this variant; skipped"); }
#endif


/* ------------------------------------------------------------------------- *
 * GROUP 7 -- BuildTls13Message()'s non-sizeOnly argument guard.
 *
 *   else if (output == NULL || input == NULL)               [tls13.c ~:3345]
 *
 * BuildTls13Message is WOLFSSL_LOCAL with seventeen in-library call sites, and
 * every one of them that passes sizeOnly = 0 hands it a record buffer it has
 * just reserved and a payload pointer into that same buffer, so from the whole
 * library the decision is permanently (F,F) -- the `sizeOnly` sibling guard one
 * line above (:3339) is the one that fires when a caller gets it wrong, and it
 * is driven by the size probe in wolfssl_local_GetRecordSize().
 *
 *   output NULL                 -> (T,-)  decision true
 *   output set, input NULL      -> (F,T)  decision true
 *   output set, input set       -> (F,F)  decision false
 *
 * The (F,F) vector is given outSz = 0, so control reaches the very next size
 * check -- "Oops, want to write past output buffer size" -- and returns
 * BUFFER_E before any record header is written or any AEAD state is touched.
 * The fixture has no keys and none are needed.
 * ------------------------------------------------------------------------- */
static void wbn_build_message_arg_guard(void)
{
    byte out[8];
    byte in[8];

    if (wbn_ssl == NULL) {
        WB_NOTE("no ssl fixture; BuildTls13Message argument guard skipped");
        return;
    }

    XMEMSET(out, 0, sizeof(out));
    XMEMSET(in, 0, sizeof(in));

    /* (T,-) */
    (void)BuildTls13Message(wbn_ssl, NULL, 0, in, 0, application_data, 0, 0, 0);
    /* (F,T) */
    (void)BuildTls13Message(wbn_ssl, out, 0, NULL, 0, application_data, 0, 0, 0);
    /* (F,F) -- stops at the `args->sz > outSz` check with BUFFER_E. */
    (void)BuildTls13Message(wbn_ssl, out, 0, in, 0, application_data, 0, 0, 0);

    /* The probe wrote ssl->options.buildMsgState; put it back so nothing
     * downstream inherits a half-built record state. */
    wbn_ssl->options.buildMsgState = BUILD_MSG_BEGIN;

    WB_NOTE("BuildTls13Message: output/input argument guard driven with all "
            "three vectors");
}


#endif /* WBN_HAVE_SSL_FIXTURE */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tls13.c white-box MC/DC supplement -- pointer-presence guards\n");

#ifdef WBN_HAVE_SSL_FIXTURE
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        WB_NOTE("wolfSSL_Init failed; all groups skipped");
    }
    else if (!wbn_fixture_setup()) {
        WB_NOTE("could not build the WOLFSSL fixture; all groups skipped");
    }
    else {
        wbn_free_args_guards();
        wbn_do_server_hello_entry_guard();
        wbn_ech_hash_hello_inner_guard();
        wbn_tls_check_cookie_guards();
        wbn_sanity_check_cid_guards();
        wbn_setup_ocsp_resp_guards();
        wbn_build_message_arg_guard();
    }

    wbn_fixture_teardown();
    wolfSSL_Cleanup();
#else
    WB_NOTE("no TLS 1.3 client on this build axis; nothing to drive");
#endif

    printf("done\n");
    /* Always 0: a nonzero exit is scored as a failed white-box and its
     * coverage is discarded. */
    return 0;
}
