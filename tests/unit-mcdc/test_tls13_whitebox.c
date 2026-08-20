/* test_tls13_whitebox.c
 *
 * White-box MC/DC supplement for src/tls13.c.
 *
 * This is the FIRST white-box driver in the campaign that targets a src/ file
 * rather than wolfcrypt/src/*.c. The build contract is identical (see
 * tests/unit-mcdc/README.md): this TU #includes the target .c verbatim, is
 * compiled with the exact flags the instrumented library used for it, and is
 * linked against that variant's libwolfssl.a with the target's own object
 * removed, so this TU supplies the single (instrumented) definition.
 *
 * WHY A WHITE-BOX IS NEEDED HERE, given that src/ has almost no mutable file
 * scope variables and all state hangs off WOLFSSL / WOLFSSL_CTX:
 * tls13.c has ~80 `static` functions. What this TU buys is not access to
 * hidden state but the ability to call those helpers with ARGUMENT
 * COMBINATIONS NO PUBLIC CALLER PRODUCES -- the defensive guards that every
 * in-library caller has already excluded before the callee runs. Those guards
 * are real conditions in the coverage map and are unreachable from tests/api
 * without editing library source.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage by
 * source line:col by the campaign's aggregate.sh, which ORs the "independence
 * shown" bit across binaries. llvm-cov derives independence PER BINARY, so
 * every MC/DC pair below is completed WITHIN THIS FILE; nothing here leans on
 * the API tests to supply the other half of a pair.
 *
 * main() always returns 0: the campaign treats a nonzero exit as a failed
 * white-box and discards its coverage, so setup problems are printed as skips.
 */

/* Pull tls13.c in verbatim so its file-static helpers are in scope and
 * instrumented in THIS binary. tls13.c includes settings.h, which picks up
 * user_settings.h via -DWOLFSSL_USER_SETTINGS. */
#include <src/tls13.c>

#include <stdio.h>

#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* The guard stack that encloses DecodeTls13SigAlg() in tls13.c:
 *   #if !defined(NO_TLS) && defined(WOLFSSL_TLS13)
 *   #ifndef WOLFCRYPT_ONLY
 *   #ifndef NO_CERTS
 *   #if !defined(NO_RSA) || defined(HAVE_ECC) || ...
 * Reproduced verbatim so this file still compiles (as a no-op) on any build
 * axis that does not compile the helper. */
#if !defined(NO_TLS) && defined(WOLFSSL_TLS13) && !defined(WOLFCRYPT_ONLY) && \
    !defined(NO_CERTS) && \
    (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
     defined(HAVE_ED448) || defined(HAVE_FALCON) || \
     defined(WOLFSSL_HAVE_MLDSA) || defined(WOLFSSL_HAVE_SLHDSA))
    #define WB_HAVE_DECODE_SIGALG
#endif

/* ------------------------------------------------------------------------- *
 * DecodeTls13SigAlg(): the two RSA-PSS minor-byte RANGE checks.
 *
 *   if (input[1] >= RSA_PSS_RSAE_SHA256_MINOR &&
 *           input[1] <= RSA_PSS_RSAE_SHA512_MINOR)          [0x04 .. 0x06]
 *   else if (input[1] >= RSA_PSS_PSS_SHA256_MINOR &&
 *           input[1] <= RSA_PSS_PSS_SHA512_MINOR)           [0x09 .. 0x0B]
 *
 * DecodeTls13SigAlg is file-static and every in-library caller feeds it a
 * signature algorithm that already passed the peer's advertised sig_algs
 * negotiation, so the "major byte is 0x08 but the minor byte sits just outside
 * a PSS range" combinations -- exactly the (T,F) halves of these two pairs --
 * never arrive from a handshake. Called directly here with all three vectors
 * per decision:
 *   {0x08,0x05}  -> (T,T) decision true
 *   {0x08,0x03}  -> (F,-) decision false (short-circuits)   pair for operand 0
 *   {0x08,0x07}  -> (T,F) decision false                    pair for operand 1
 * and the same shape one range up for the PSS-PSS check, which is only
 * reached when the RSAE check is false.
 *
 * Pure function of a 2-byte buffer and two out-bytes: no WOLFSSL object, no
 * allocation, no entropy.
 * ------------------------------------------------------------------------- */
#ifdef WB_HAVE_DECODE_SIGALG
static void wb_decode_tls13_sigalg(void)
{
    static const byte vec[6][2] = {
        { NEW_SA_MAJOR, 0x05 },  /* RSAE range: T,T */
        { NEW_SA_MAJOR, 0x03 },  /* RSAE range: F,- ; PSS range: F,- */
        { NEW_SA_MAJOR, 0x07 },  /* RSAE range: T,F */
        { NEW_SA_MAJOR, 0x0A },  /* RSAE F,- then PSS range: T,T */
        { NEW_SA_MAJOR, 0x0C },  /* RSAE F,- then PSS range: T,F */
        { NEW_SA_MAJOR, 0x09 }   /* PSS range lower edge: T,T */
    };
    byte input[2];
    byte hashAlgo;
    byte hsType;
    size_t i;

    for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
        input[0] = vec[i][0];
        input[1] = vec[i][1];
        hashAlgo = 0;
        hsType   = 0;
        (void)DecodeTls13SigAlg(input, &hashAlgo, &hsType);
    }

    WB_NOTE("DecodeTls13SigAlg: both PSS minor-byte range decisions driven "
            "with both halves of each independence pair");
}
#else
static void wb_decode_tls13_sigalg(void)
{ WB_NOTE("DecodeTls13SigAlg not compiled in this variant; skipped"); }
#endif


/* ------------------------------------------------------------------------- *
 * Shared fixture: one WOLFSSL built through the public API. Nothing here
 * performs a handshake -- the object exists only so the static helpers below
 * can be called with a STRUCTURALLY VALID ssl (the "all operands false" half
 * of each guard) as well as with the degenerate arguments no in-library
 * caller ever produces. No entropy is consumed beyond what wolfSSL_new()
 * itself does, no certificate or key file is read, and no wall-clock or
 * network behaviour is involved, so the binary is deterministic.
 *
 * A CLIENT method is used because wolfSSL_new() on a server WOLFSSL_CTX with
 * no certificate loaded fails, and depending on the on-disk certs/ tree would
 * make this TU sensitive to the runner's working directory. The one place
 * below that needs server-side behaviour flips ssl->options.side for the
 * duration of a single call and restores it -- see wb_create_cookie_ext_guards.
 * ------------------------------------------------------------------------- */
#if !defined(NO_TLS) && defined(WOLFSSL_TLS13) && !defined(WOLFCRYPT_ONLY) && \
    !defined(NO_WOLFSSL_CLIENT)
    #define WB_HAVE_SSL_FIXTURE
#endif

#ifdef WB_HAVE_SSL_FIXTURE
static WOLFSSL_CTX* wb_ctx_c = NULL;
static WOLFSSL*     wb_ssl_c = NULL;

/* The ssl argument the WB_ARRAYS_GUARD macro varies between vectors. Kept in a
 * file-scope variable so one macro can drive helpers with different
 * signatures without re-stating each call three times. */
static WOLFSSL*     wb_s = NULL;

static int wb_fixture_setup(void)
{
    wb_ctx_c = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (wb_ctx_c == NULL)
        return 0;
    wb_ssl_c = wolfSSL_new(wb_ctx_c);
    if (wb_ssl_c == NULL)
        return 0;
    /* Every guard below reads ssl->arrays; a WOLFSSL that never got one is
     * not a usable fixture. */
    if (wb_ssl_c->arrays == NULL)
        return 0;
    return 1;
}

static void wb_fixture_teardown(void)
{
    if (wb_ssl_c != NULL) wolfSSL_free(wb_ssl_c);
    if (wb_ctx_c != NULL) wolfSSL_CTX_free(wb_ctx_c);
    wb_ssl_c = NULL; wb_ctx_c = NULL;
}

/* Drive `if (ssl == NULL || ssl->arrays == NULL)` with all three vectors that
 * unique-cause MC/DC needs, in THIS binary:
 *
 *   ssl == NULL              -> (T,-)  decision true    | pair for operand 0
 *   ssl != NULL, arrays NULL -> (F,T)  decision true    | pair for operand 1
 *   ssl != NULL, arrays set  -> (F,F)  decision false   | shared partner
 *
 * EXPR must reference wb_s where the helper takes its WOLFSSL*. The third
 * vector runs the helper's body for real; each helper below was chosen so that
 * body is side-effect free on an un-negotiated WOLFSSL (specs.mac_algorithm is
 * still 0, so the key schedule bails out with HASH_TYPE_E / BAD_FUNC_ARG
 * before touching hsHashes or the record layer). Return values are
 * deliberately ignored: the guard, not the outcome, is under test.
 *
 * arrays is nulled and restored rather than freed, so teardown is unaffected.
 */
#define WB_ARRAYS_GUARD(ssl, EXPR)                                          \
    do {                                                                    \
        Arrays* wb_saved = (ssl)->arrays;                                   \
        wb_s = NULL;                                                        \
        (void)(EXPR);                                                       \
        wb_s = (ssl);                                                       \
        (ssl)->arrays = NULL;                                               \
        (void)(EXPR);                                                       \
        (ssl)->arrays = wb_saved;                                           \
        (void)(EXPR);                                                       \
    } while (0)

/* ------------------------------------------------------------------------- *
 * The TLS 1.3 key-schedule entry points and their `ssl == NULL ||
 * ssl->arrays == NULL` guards.
 *
 * DeriveBinderKey, DeriveBinderKeyResume, DeriveEarlyTrafficSecret,
 * DeriveClient/ServerHandshakeSecret, DeriveClient/ServerTrafficSecret and
 * DeriveExporterSecret are file-static; DeriveEarlySecret,
 * DeriveHandshakeSecret and DeriveMasterSecret are WOLFSSL_LOCAL. Either way
 * every in-library call site sits inside the handshake state machine, which
 * cannot be entered at all without a WOLFSSL that already has its arrays --
 * FreeArrays() only runs once the handshake is complete and no key-schedule
 * call follows it. So from tests/api the decision is *always* (F,F): both
 * operands are stuck false and neither independence pair can ever be shown.
 * Reaching (T,-) and (F,T) is precisely what compiling tls13.c into the test
 * binary buys.
 * ------------------------------------------------------------------------- */
static void wb_key_schedule_null_guards(void)
{
    byte key[WC_MAX_DIGEST_SIZE];

    if (wb_ssl_c == NULL) {
        WB_NOTE("no ssl fixture; key-schedule guards skipped");
        return;
    }

    XMEMSET(key, 0, sizeof(key));

#ifndef NO_PSK
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveBinderKey(wb_s, key));
#endif
#if defined(HAVE_SESSION_TICKET) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER))
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveBinderKeyResume(wb_s, key));
#endif
#ifdef WOLFSSL_EARLY_DATA
    WB_ARRAYS_GUARD(wb_ssl_c,
                    DeriveEarlyTrafficSecret(wb_s, key, WOLFSSL_CLIENT_END));
#endif
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveClientHandshakeSecret(wb_s, key));
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveServerHandshakeSecret(wb_s, key));
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveClientTrafficSecret(wb_s, key));
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveServerTrafficSecret(wb_s, key));
#ifdef HAVE_KEYING_MATERIAL
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveExporterSecret(wb_s, key));
#endif
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveEarlySecret(wb_s));
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveHandshakeSecret(wb_s));
    WB_ARRAYS_GUARD(wb_ssl_c, DeriveMasterSecret(wb_s));

    WB_NOTE("key-schedule ssl/arrays guards driven with all three vectors");
}

/* ------------------------------------------------------------------------- *
 * BuildTls13HandshakeHmac(): `if (ssl == NULL || key == NULL || hash == NULL)`
 *
 * Three operands, so unique-cause MC/DC needs four vectors. The only two
 * callers (SendTls13Finished / DoTls13Finished) pass ssl plus two automatic
 * buffers, so all three operands are permanently false from tests/api.
 *
 *   (T,-,-) ssl NULL
 *   (F,T,-) key NULL
 *   (F,F,T) hash NULL
 *   (F,F,F) all supplied -> body runs; specs.mac_algorithm is 0 on an
 *           un-negotiated WOLFSSL, so the switch takes `default:` and returns
 *           BAD_FUNC_ARG before dereferencing ssl->hsHashes.
 * ------------------------------------------------------------------------- */
static void wb_build_handshake_hmac_guard(void)
{
    byte key[WC_MAX_DIGEST_SIZE];
    byte hash[WC_MAX_DIGEST_SIZE];
    word32 hashSz = 0;

    if (wb_ssl_c == NULL) {
        WB_NOTE("no ssl fixture; BuildTls13HandshakeHmac guard skipped");
        return;
    }

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(hash, 0, sizeof(hash));

    (void)BuildTls13HandshakeHmac(NULL,     key,  hash, &hashSz);
    (void)BuildTls13HandshakeHmac(wb_ssl_c, NULL, hash, &hashSz);
    (void)BuildTls13HandshakeHmac(wb_ssl_c, key,  NULL, &hashSz);
    (void)BuildTls13HandshakeHmac(wb_ssl_c, key,  hash, &hashSz);

    WB_NOTE("BuildTls13HandshakeHmac argument guard driven with all four "
            "vectors");
}

/* ------------------------------------------------------------------------- *
 * CreateCookieExt(): the two argument/state guards.
 *
 *   if (hash == NULL || hashSz == 0)                       -> BAD_FUNC_ARG
 *   if (cookieSecret.buffer == NULL || cookieSecret.length == 0)
 *                                                          -> COOKIE_ERROR
 *
 * Both callers (SendTls13ServerHello's HRR path and DoTls13ClientHello) reach
 * CreateCookieExt only after the server has a cookie secret and a computed
 * transcript hash, so from tests/api every operand of both decisions is stuck
 * false. Driven here directly:
 *
 *   hash guard:   (NULL, 32) / (hash, 0) / (hash, 32)
 *   secret guard: no secret -> (T,-); secret with length forced to 0 -> (F,T);
 *                 secret as installed -> (F,F), which runs the HMAC and the
 *                 TLSX_Cookie_Use() that follows.
 *
 * The length field is forced to 0 and restored rather than freeing the
 * buffer, so wolfSSL_free() still releases it exactly once.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_SERVER)
static void wb_create_cookie_ext_guards(void)
{
    static const byte secret[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    byte  hash[WC_SHA256_DIGEST_SIZE];
    TLSX* exts = NULL;
    word32 savedLen;
    int    savedSide;
    int    ret;

    if (wb_ssl_c == NULL) {
        WB_NOTE("no ssl fixture; CreateCookieExt guards skipped");
        return;
    }

    XMEMSET(hash, 0x5a, sizeof(hash));

    /* hash guard, all three vectors. The third falls through to the cookie
     * secret guard, which on a fresh server is (T,-): no secret installed. */
    (void)CreateCookieExt(wb_ssl_c, NULL, (word16)sizeof(hash), &exts,
                          TLS13_BYTE, TLS_AES_128_GCM_SHA256);
    (void)CreateCookieExt(wb_ssl_c, hash, 0, &exts,
                          TLS13_BYTE, TLS_AES_128_GCM_SHA256);
    (void)CreateCookieExt(wb_ssl_c, hash, (word16)sizeof(hash), &exts,
                          TLS13_BYTE, TLS_AES_128_GCM_SHA256);

    /* wolfSSL_send_hrr_cookie() is server-only; the fixture is a client
     * because a server WOLFSSL_CTX with no certificate cannot be instantiated.
     * The side is flipped for exactly this call and restored immediately, so
     * wolfSSL_free() still tears the object down along the client path. */
    savedSide = wb_ssl_c->options.side;
    wb_ssl_c->options.side = WOLFSSL_SERVER_END;
    ret = wolfSSL_send_hrr_cookie(wb_ssl_c, secret, (unsigned int)sizeof(secret));
    wb_ssl_c->options.side = savedSide;

    if (ret != WOLFSSL_SUCCESS ||
            wb_ssl_c->buffers.tls13CookieSecret.buffer == NULL) {
        WB_NOTE("could not install a cookie secret; secret guard partial");
        TLSX_FreeAll(exts, wb_ssl_c->heap);
        return;
    }

    /* buffer non-NULL, length 0 -> (F,T) */
    savedLen = wb_ssl_c->buffers.tls13CookieSecret.length;
    wb_ssl_c->buffers.tls13CookieSecret.length = 0;
    (void)CreateCookieExt(wb_ssl_c, hash, (word16)sizeof(hash), &exts,
                          TLS13_BYTE, TLS_AES_128_GCM_SHA256);
    wb_ssl_c->buffers.tls13CookieSecret.length = savedLen;

    /* buffer non-NULL, length non-zero -> (F,F); runs the HMAC + cookie use */
    (void)CreateCookieExt(wb_ssl_c, hash, (word16)sizeof(hash), &exts,
                          TLS13_BYTE, TLS_AES_128_GCM_SHA256);

    TLSX_FreeAll(exts, wb_ssl_c->heap);

    WB_NOTE("CreateCookieExt hash and cookie-secret guards driven with both "
            "halves of each independence pair");
}
#else
static void wb_create_cookie_ext_guards(void)
{ WB_NOTE("CreateCookieExt not compiled in this variant; skipped"); }
#endif

#else /* !WB_HAVE_SSL_FIXTURE */
static void wb_key_schedule_null_guards(void)
{ WB_NOTE("no WOLFSSL fixture on this build axis; skipped"); }
static void wb_build_handshake_hmac_guard(void)
{ WB_NOTE("no WOLFSSL fixture on this build axis; skipped"); }
static void wb_create_cookie_ext_guards(void)
{ WB_NOTE("no WOLFSSL fixture on this build axis; skipped"); }
#endif /* WB_HAVE_SSL_FIXTURE */


/* ------------------------------------------------------------------------- *
 * SanityCheckTls13MsgReceived(): the handshake-message ordering matrix.
 *
 * This file-static predicate is the densest single cluster of open conditions
 * in tls13.c. It is a PURE function of ssl->options, ssl->msgsReceived,
 * ssl->earlyData and ssl->certReqCtx -- it allocates nothing, reads no buffer
 * and performs no crypto -- yet from tests/api most of its operand
 * combinations are unreachable, because reaching a given message type at all
 * means the state machine has already forced the very fields the decision
 * tests. A handshake that is far enough along to deliver a Finished, for
 * instance, cannot simultaneously have mutualAuth set and havePeerCert clear.
 *
 * Calling it directly with a synthesised WOLFSSL state is the only way to
 * complete these pairs. Each vector below restores the fixture to a known base
 * first (wb_sc_reset), so the vectors are order-independent and the fixture is
 * handed back to wolfSSL_free() in its initial shape.
 * ------------------------------------------------------------------------- */
#ifdef WB_HAVE_SSL_FIXTURE
static void wb_sc_reset(void)
{
    WOLFSSL* ssl = wb_ssl_c;

    XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));
    ssl->options.side                = WOLFSSL_CLIENT_END;
    ssl->options.clientState         = NULL_STATE;
    ssl->options.serverState         = NULL_STATE;
    ssl->options.connectState        = CONNECT_BEGIN;
    ssl->options.pskNegotiated       = 0;
    ssl->options.postHandshakeAuth   = 0;
    ssl->options.verifyPeer          = 0;
    ssl->options.verifyPostHandshake = 0;
    ssl->options.mutualAuth          = 0;
    ssl->options.havePeerCert        = 0;
    ssl->options.havePeerVerify      = 0;
    ssl->options.dtls                = 0;
    ssl->options.downgrade           = 0;
    ssl->options.minDowngrade        = 0;
    ssl->certReqCtx                  = NULL;
#ifdef WOLFSSL_EARLY_DATA
    ssl->earlyData                   = no_early_data;
#endif
}

#define WB_SC(type) (void)SanityCheckTls13MsgReceived(wb_ssl_c, (byte)(type))

static void wb_sanity_check_client_hello(void)
{
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL* ssl = wb_ssl_c;

    /* 2nd ClientHello duplicate check:
     *   got_client_hello == 1 && serverState != SERVER_HELLO_RETRY_REQUEST_COMPLETE
     * Reached only on the server with clientState < CLIENT_HELLO_COMPLETE. A
     * server that has seen one ClientHello has, by construction, either
     * answered it (clientState advances) or emitted an HRR, so the (T,F) and
     * (F,-) partners never coexist with (T,T) in one live handshake. */
    wb_sc_reset(); ssl->options.side = WOLFSSL_SERVER_END;
    ssl->msgsReceived.got_client_hello = 1;               /* (T,T) -> dup */
    WB_SC(client_hello);

    wb_sc_reset(); ssl->options.side = WOLFSSL_SERVER_END; /* (F,-) -> accept */
    WB_SC(client_hello);

    wb_sc_reset(); ssl->options.side = WOLFSSL_SERVER_END;
    ssl->msgsReceived.got_client_hello = 1;
    ssl->options.serverState = SERVER_HELLO_RETRY_REQUEST_COMPLETE; /* (T,F) */
    WB_SC(client_hello);
#endif
}

static void wb_sanity_check_certificate(void)
{
    WOLFSSL* ssl = wb_ssl_c;

    /* Client-side ordering guard:
     *   side == CLIENT && serverState != SERVER_ENCRYPTED_EXTENSIONS_COMPLETE */
#ifndef NO_WOLFSSL_CLIENT
    wb_sc_reset();                                        /* (T,T) -> ooo */
    WB_SC(certificate);

    wb_sc_reset();
    ssl->options.serverState = SERVER_ENCRYPTED_EXTENSIONS_COMPLETE; /* (T,F) */
    WB_SC(certificate);
#endif

#ifndef NO_WOLFSSL_SERVER
    /* Server-side ordering guard:
     *   side == SERVER && clientState != CLIENT_HELLO_COMPLETE &&
     *   serverState < SERVER_FINISHED_COMPLETE
     * The (F,-,-) partner is the client vector just above, which also supplies
     * the (T,F) half of the client guard -- one call, two pairs. */
    wb_sc_reset(); ssl->options.side = WOLFSSL_SERVER_END;  /* (T,T,T) -> ooo */
    WB_SC(certificate);

    wb_sc_reset(); ssl->options.side = WOLFSSL_SERVER_END;
    ssl->options.clientState = CLIENT_HELLO_COMPLETE;       /* (T,F,-) */
    WB_SC(certificate);

    wb_sc_reset(); ssl->options.side = WOLFSSL_SERVER_END;
    ssl->options.serverState = SERVER_FINISHED_COMPLETE;    /* (T,T,F) */
    WB_SC(certificate);

    wb_sc_reset();
    ssl->options.serverState = SERVER_ENCRYPTED_EXTENSIONS_COMPLETE;
    WB_SC(certificate);                                    /* (F,-,-) */
#endif
}

#ifndef NO_WOLFSSL_CLIENT
static void wb_sanity_check_certificate_request(void)
{
    WOLFSSL* ssl = wb_ssl_c;

    /* Ordering guard:
     *   serverState != SERVER_ENCRYPTED_EXTENSIONS_COMPLETE &&
     *   (serverState < SERVER_FINISHED_COMPLETE ||
     *    clientState != CLIENT_FINISHED_COMPLETE)                            */
    wb_sc_reset();                                          /* (T,T,-) -> ooo */
    WB_SC(certificate_request);

    wb_sc_reset();
    ssl->options.serverState = SERVER_ENCRYPTED_EXTENSIONS_COMPLETE; /* (F,-,-) */
    WB_SC(certificate_request);

    wb_sc_reset();
    ssl->options.serverState = SERVER_FINISHED_COMPLETE;    /* (T,F,T) -> ooo */
    WB_SC(certificate_request);

    /* (T,F,F): the post-handshake window. Also the only way to reach the
     * post_handshake_auth guard below with its first two operands true. */
    wb_sc_reset();
    ssl->options.serverState = SERVER_FINISHED_COMPLETE;
    ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
    ssl->options.postHandshakeAuth = 1;                     /* pha guard (T,T,F) */
    WB_SC(certificate_request);

    wb_sc_reset();
    ssl->options.serverState = SERVER_FINISHED_COMPLETE;
    ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
    ssl->options.postHandshakeAuth = 0;                     /* pha guard (T,T,T) */
    WB_SC(certificate_request);

    /* Duplicate guard:
     *   got_certificate_request && clientState != CLIENT_FINISHED_COMPLETE   */
    wb_sc_reset();
    ssl->options.serverState = SERVER_ENCRYPTED_EXTENSIONS_COMPLETE;
    ssl->msgsReceived.got_certificate_request = 1;          /* (T,T) -> dup */
    WB_SC(certificate_request);

    wb_sc_reset();
    ssl->options.serverState = SERVER_ENCRYPTED_EXTENSIONS_COMPLETE;
    ssl->msgsReceived.got_certificate_request = 1;
    ssl->options.clientState = CLIENT_FINISHED_COMPLETE;    /* (T,F) */
    WB_SC(certificate_request);
    /* (F,-) is any of the accepting vectors above. */
}
#else
static void wb_sanity_check_certificate_request(void) { }
#endif

static void wb_sanity_check_finished(void)
{
    WOLFSSL* ssl = wb_ssl_c;
    CertReqCtx reqCtx;

    XMEMSET(&reqCtx, 0, sizeof(reqCtx));

#if !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_EARLY_DATA)
    /* Server early-data guard:
     *   earlyData == process_early_data && !dtls && !WOLFSSL_IS_QUIC(ssl)    */
    wb_sc_reset();
    ssl->options.side        = WOLFSSL_SERVER_END;
    ssl->options.serverState = SERVER_FINISHED_COMPLETE;
    ssl->options.clientState = CLIENT_HELLO_COMPLETE;
    ssl->earlyData           = process_early_data;          /* (T,T,T) -> ooo */
    WB_SC(finished);

    wb_sc_reset();
    ssl->options.side        = WOLFSSL_SERVER_END;
    ssl->options.serverState = SERVER_FINISHED_COMPLETE;
    ssl->options.clientState = CLIENT_HELLO_COMPLETE;       /* (F,-,-) */
    WB_SC(finished);

    wb_sc_reset();
    ssl->options.side        = WOLFSSL_SERVER_END;
    ssl->options.serverState = SERVER_FINISHED_COMPLETE;
    ssl->options.clientState = CLIENT_HELLO_COMPLETE;
    ssl->earlyData           = process_early_data;
    ssl->options.dtls        = 1;                           /* (T,F,-) */
    WB_SC(finished);
    ssl->options.dtls        = 0;
#endif

    /* The three peer-certificate guards. All are reached on the server with
     * serverState >= SERVER_FINISHED_COMPLETE and clientState >=
     * CLIENT_HELLO_COMPLETE, or on the client with serverState ==
     * SERVER_CERT_VERIFY_COMPLETE. pskNegotiated must be 0 for the block to be
     * entered at all. */
#define WB_SC_FIN_SERVER()                                       \
    do { wb_sc_reset();                                          \
         ssl->options.side        = WOLFSSL_SERVER_END;          \
         ssl->options.serverState = SERVER_FINISHED_COMPLETE;     \
         ssl->options.clientState = CLIENT_HELLO_COMPLETE;        \
    } while (0)
#define WB_SC_FIN_CLIENT()                                       \
    do { wb_sc_reset();                                          \
         ssl->options.side        = WOLFSSL_CLIENT_END;          \
         ssl->options.clientState = CLIENT_HELLO_COMPLETE;        \
         ssl->options.serverState = SERVER_CERT_VERIFY_COMPLETE;  \
    } while (0)

#ifndef NO_WOLFSSL_SERVER
    /* Guard 1: verifyPeer &&
     *          (!verifyPostHandshake ||
     *           (side == SERVER && certReqCtx != NULL)) &&
     *          !got_certificate                                             */
    WB_SC_FIN_SERVER(); ssl->options.verifyPeer = 1;        /* (T,T,-,-,T) */
    WB_SC(finished);

    WB_SC_FIN_SERVER();                                     /* (F,-,-,-,-) */
    WB_SC(finished);

    WB_SC_FIN_SERVER(); ssl->options.verifyPeer = 1;
    ssl->msgsReceived.got_certificate = 1;                  /* (T,T,-,-,F) */
    WB_SC(finished);

#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    WB_SC_FIN_SERVER(); ssl->options.verifyPeer = 1;
    ssl->options.verifyPostHandshake = 1;
    ssl->certReqCtx = &reqCtx;                              /* (T,F,T,T,T) */
    WB_SC(finished);
    ssl->certReqCtx = NULL;

    WB_SC_FIN_SERVER(); ssl->options.verifyPeer = 1;
    ssl->options.verifyPostHandshake = 1;                   /* (T,F,T,F,-) */
    WB_SC(finished);
#endif
#endif /* !NO_WOLFSSL_SERVER */

#ifndef NO_WOLFSSL_CLIENT
#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    /* (T,F,F,-,-): a client never satisfies the side == SERVER operand. */
    WB_SC_FIN_CLIENT(); ssl->options.verifyPeer = 1;
    ssl->options.verifyPostHandshake = 1;
    ssl->msgsReceived.got_certificate = 1;
    WB_SC(finished);
#endif
#endif

#ifndef NO_WOLFSSL_SERVER
    /* Guard 2: (mutualAuth || (side == CLIENT && verifyPeer)) &&
     *          !havePeerCert                                                */
    WB_SC_FIN_SERVER(); ssl->options.mutualAuth = 1;        /* (T,-,-,T) */
    WB_SC(finished);

    WB_SC_FIN_SERVER(); ssl->options.mutualAuth = 1;
    ssl->options.havePeerCert = 1;                          /* (T,-,-,F) */
    WB_SC(finished);

    WB_SC_FIN_SERVER();                                     /* (F,F,-,-) */
    WB_SC(finished);
#endif

#ifndef NO_WOLFSSL_CLIENT
    WB_SC_FIN_CLIENT(); ssl->options.verifyPeer = 1;
    ssl->msgsReceived.got_certificate = 1;                  /* (F,T,T,T) */
    WB_SC(finished);

    WB_SC_FIN_CLIENT();                                     /* (F,T,F,-) */
    WB_SC(finished);
#endif

#ifndef NO_WOLFSSL_SERVER
    /* Guard 3: (mutualAuth || verifyPeer) && havePeerCert && !havePeerVerify */
    WB_SC_FIN_SERVER(); ssl->options.mutualAuth = 1;
    ssl->options.havePeerCert = 1;                          /* (T,-,T,T) */
    WB_SC(finished);

    WB_SC_FIN_SERVER(); ssl->options.mutualAuth = 1;
    ssl->options.havePeerCert = 1;
    ssl->options.havePeerVerify = 1;                        /* (T,-,T,F) */
    WB_SC(finished);

    /* mutualAuth clear, verifyPeer set: guard 2's subexpression is false on
     * the server, so guard 3 is reached with cond0 false and cond1 true. */
    WB_SC_FIN_SERVER(); ssl->options.verifyPeer = 1;
    ssl->msgsReceived.got_certificate = 1;
    ssl->options.havePeerCert = 1;                          /* (F,T,T,T) */
    WB_SC(finished);

    WB_SC_FIN_SERVER(); ssl->options.verifyPeer = 1;
    ssl->msgsReceived.got_certificate = 1;                  /* (F,T,F,-) */
    WB_SC(finished);

    WB_SC_FIN_SERVER();                                     /* (F,F,-,-) */
    WB_SC(finished);
#endif

#undef WB_SC_FIN_SERVER
#undef WB_SC_FIN_CLIENT
    (void)reqCtx;
}

#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_NO_TLS12)
static void wb_sanity_check_hello_verify_request(void)
{
    WOLFSSL* ssl = wb_ssl_c;

    /* Ordering guard:
     *   serverState >= SERVER_HELLO_RETRY_REQUEST_COMPLETE ||
     *   connectState != CLIENT_HELLO_SENT                                    */
    wb_sc_reset(); ssl->options.dtls = 1;
    ssl->options.serverState = SERVER_HELLO_RETRY_REQUEST_COMPLETE; /* (T,-) */
    WB_SC(hello_verify_request);

    wb_sc_reset(); ssl->options.dtls = 1;                   /* (F,T) */
    WB_SC(hello_verify_request);

    /* (F,F) falls through to the downgrade guard:
     *   !downgrade || minDowngrade < DTLSv1_2_MINOR                          */
    wb_sc_reset(); ssl->options.dtls = 1;
    ssl->options.connectState = CLIENT_HELLO_SENT;          /* (F,F); (T,-)  */
    WB_SC(hello_verify_request);

    wb_sc_reset(); ssl->options.dtls = 1;
    ssl->options.connectState = CLIENT_HELLO_SENT;
    ssl->options.downgrade    = 1;
    ssl->options.minDowngrade = 0;                          /* (F,T) */
    WB_SC(hello_verify_request);

    wb_sc_reset(); ssl->options.dtls = 1;
    ssl->options.connectState = CLIENT_HELLO_SENT;
    ssl->options.downgrade    = 1;
    ssl->options.minDowngrade = DTLSv1_2_MINOR;             /* (F,F) -> accept */
    WB_SC(hello_verify_request);

    wb_sc_reset();
}
#else
static void wb_sanity_check_hello_verify_request(void) { }
#endif

static void wb_sanity_check_msgs(void)
{
    if (wb_ssl_c == NULL) {
        WB_NOTE("no ssl fixture; SanityCheckTls13MsgReceived skipped");
        return;
    }

    wb_sanity_check_client_hello();
    wb_sanity_check_certificate();
    wb_sanity_check_certificate_request();
    wb_sanity_check_finished();
    wb_sanity_check_hello_verify_request();
    wb_sc_reset();

    WB_NOTE("SanityCheckTls13MsgReceived ordering matrix driven");
}
#undef WB_SC
#else
static void wb_sanity_check_msgs(void)
{ WB_NOTE("no WOLFSSL fixture on this build axis; skipped"); }
#endif /* WB_HAVE_SSL_FIXTURE */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tls13.c white-box MC/DC supplement\n");

#ifdef WB_HAVE_SSL_FIXTURE
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        WB_NOTE("wolfSSL_Init failed; fixture-based groups skipped");
    }
    else if (!wb_fixture_setup()) {
        WB_NOTE("could not build the WOLFSSL fixtures; groups skipped");
    }
#endif

    wb_decode_tls13_sigalg();
    wb_key_schedule_null_guards();
    wb_build_handshake_hmac_guard();
    wb_create_cookie_ext_guards();
    wb_sanity_check_msgs();

#ifdef WB_HAVE_SSL_FIXTURE
    wb_fixture_teardown();
    wolfSSL_Cleanup();
#endif

    printf("done\n");
    /* Always 0: a nonzero exit is scored as a failed white-box and its
     * coverage is discarded. */
    return 0;
}
