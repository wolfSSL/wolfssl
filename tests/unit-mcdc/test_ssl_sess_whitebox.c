/* test_ssl_sess_whitebox.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* Both session caches walk their row backwards from the most recently used
 * entry, and both start that walk the same way:
 *
 *     idx = row->nextIdx - 1;
 *     if (idx < 0 || idx >= SESSIONS_PER_ROW)
 *         idx = SESSIONS_PER_ROW - 1;      -- back to front, previous was end
 *
 * nextIdx is the ring's insertion point and lives in [0, SESSIONS_PER_ROW), so
 * idx lands in [-1, SESSIONS_PER_ROW-1]. The first operand is true exactly
 * when nextIdx is 0 -- an untouched row, or one that has just wrapped. The
 * second cannot be true at all while the ring is maintained correctly; it
 * defends against a corrupted row, and is recorded as an exclusion rather than
 * chased.
 *
 * Both halves have to run in this one binary or neither operand pairs: a
 * lookup that only ever starts on an empty ring shows idx < 0 true and never
 * false, which is no independence pair and scores nothing. Each vector below
 * is therefore run twice, once against nextIdx 0 and once against a nextIdx
 * in the middle of the ring.
 *
 * Whether the first operand is covered therefore depends on what the cache
 * happens to hold when some earlier test in the same binary last touched it --
 * not on anything this file does. That is not a hypothetical: ssl_sess.c
 * measured 32/120 one night and 33/120 the next from identical wolfssl and
 * campaign commits on the same host. Driving the lookup against a row that is
 * known to be empty makes the operand a property of the test instead.
 *
 * The caches are file-static in ssl_sess.c, which is #included into ssl.c, so
 * this white-box includes src/ssl.c and the module entry names src/ssl.c as
 * its "tu" while reporting against src/ssl_sess.c.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 */

#include <wolfssl/options.h>

#include <src/ssl.c>
#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(NO_SESSION_CACHE) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_CLIENT_CACHE) \
    && !defined(NO_CERTS)

static int g_checks;

/* Exercise the copy helper directly: normal callers own both sessions and
 * never ask it to copy onto the source. */
static int wb_session_copy_guards(void)
{
    WOLFSSL_SESSION* input = wolfSSL_SESSION_new();
    WOLFSSL_SESSION* output = wolfSSL_SESSION_new();
    int failed = 0;

    if (input == NULL || output == NULL) {
        failed = 1;
        goto done;
    }
    if (wolfSSL_DupSession(NULL, output, 0) != WOLFSSL_FAILURE)
        failed = 1;
    if (wolfSSL_DupSession(input, NULL, 0) != WOLFSSL_FAILURE)
        failed = 1;
    if (wolfSSL_DupSession(input, input, 0) != WOLFSSL_FAILURE)
        failed = 1;
    if (wolfSSL_DupSession(input, output, 0) != WOLFSSL_SUCCESS)
        failed = 1;

done:
    wolfSSL_SESSION_free(output);
    wolfSSL_SESSION_free(input);
    return failed;
}

#if defined(HAVE_SESSION_TICKET) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_session_ticket_copy(void)
{
    WOLFSSL_SESSION* input = wolfSSL_SESSION_new();
    WOLFSSL_SESSION* output = wolfSSL_SESSION_new();
    WOLFSSL_SESSION* copy = NULL;
    byte ticket[sizeof(input->staticTicket) + 16];
    word16 length = (word16)sizeof(ticket);
    int failed = 0;

    if (input == NULL || output == NULL) {
        failed = 1;
        goto done;
    }
    XMEMSET(ticket, 0x6a, sizeof(ticket));
    if (SetSessionTicket(input, ticket, length) != 0) {
        failed = 1;
        goto done;
    }

    if (wolfSSL_DupSession(input, output, 1) != WOLFSSL_FAILURE)
        failed = 1;
    if (SetSessionTicket(output, ticket, length - 1) != 0)
        failed = 1;
    if (wolfSSL_DupSession(input, output, 1) != WOLFSSL_FAILURE)
        failed = 1;

    if (wolfSSL_DupSession(input, output, 0) != WOLFSSL_SUCCESS ||
            output->ticket == input->ticket || output->ticketLen != length ||
            XMEMCMP(output->ticket, ticket, length) != 0)
        failed = 1;
    if (wolfSSL_DupSession(input, output, 1) != WOLFSSL_SUCCESS ||
            output->ticketLen != length)
        failed = 1;

    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    copy = wolfSSL_SESSION_dup(input);
    mcdc_fa_restore();
    if (copy != NULL) {
        failed = 1;
        wolfSSL_SESSION_free(copy);
    }
    copy = wolfSSL_SESSION_dup(input);
    if (copy == NULL || copy->ticket == input->ticket ||
            copy->ticketLen != length ||
            XMEMCMP(copy->ticket, ticket, length) != 0)
        failed = 1;

done:
    wolfSSL_SESSION_free(copy);
    wolfSSL_SESSION_free(output);
    wolfSSL_SESSION_free(input);
    return failed;
}
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) && \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_session_nonce_copy(void)
{
    WOLFSSL_SESSION* input = wolfSSL_SESSION_new();
    WOLFSSL_SESSION* output = wolfSSL_SESSION_new();
    byte nonce[MAX_TICKET_NONCE_STATIC_SZ + 1];
    byte prealloc[sizeof(nonce)];
    byte capacity, used;
    int ret, failed = 0;

    if (input == NULL || output == NULL) {
        failed = 1;
        goto done;
    }
    XMEMSET(nonce, 0x3e, sizeof(nonce));
    if (SessionTicketNoncePopulate(input, nonce, sizeof(nonce)) != 0) {
        failed = 1;
        goto done;
    }

    capacity = sizeof(prealloc);
    used = 0;
    if (wolfSSL_DupSessionEx(input, output, 1, 0, NULL, &capacity, &used) !=
            WOLFSSL_FAILURE || used)
        failed = 1;
    capacity = sizeof(prealloc) - 1;
    if (wolfSSL_DupSessionEx(input, output, 1, 0, prealloc, &capacity, &used)
            != WOLFSSL_FAILURE || used)
        failed = 1;
    capacity = sizeof(prealloc);
    if (wolfSSL_DupSessionEx(input, output, 1, 0, prealloc, &capacity, &used)
            != WOLFSSL_SUCCESS || !used || capacity != sizeof(nonce) ||
            XMEMCMP(prealloc, nonce, sizeof(nonce)) != 0)
        failed = 1;

    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    ret = wolfSSL_DupSession(input, output, 0);
    mcdc_fa_restore();
    if (ret != WOLFSSL_FAILURE)
        failed = 1;
    if (wolfSSL_DupSession(input, output, 0) != WOLFSSL_SUCCESS ||
            output->ticketNonce.data == NULL ||
            output->ticketNonce.data == input->ticketNonce.data ||
            output->ticketNonce.len != sizeof(nonce) ||
            XMEMCMP(output->ticketNonce.data, nonce, sizeof(nonce)) != 0)
        failed = 1;

done:
    wolfSSL_SESSION_free(output);
    wolfSSL_SESSION_free(input);
    return failed;
}
#endif

#if defined(HAVE_EXT_CACHE) && defined(WOLFSSL_TLS13) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
struct wb_external_cache {
    WOLFSSL_SESSION* session;
    int transfer;
    int lookups;
};

static WOLFSSL_SESSION* wb_external_get(WOLFSSL* ssl, const byte* id, int len,
    int* copy)
{
    struct wb_external_cache* cache =
        (struct wb_external_cache*)wolfSSL_GetIOReadCtx(ssl);
    WOLFSSL_SESSION* session = cache->session;

    if (id == NULL || len != ID_LEN)
        return NULL;
    cache->lookups++;
    *copy = !cache->transfer;
    if (cache->transfer)
        cache->session = NULL;
    return session;
}

/* Drive the internal cache lookup with independently owned sessions. */
static int wb_external_cache_lookup(WOLFSSL_CTX* ctx)
{
    struct wb_external_cache cache = { NULL, 0, 0 };
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_SESSION* output = wolfSSL_SESSION_new();
    int failed = 1;

    cache.session = wolfSSL_SESSION_new();
    if (ssl == NULL || output == NULL || cache.session == NULL)
        goto done;

    wolfSSL_SetIOReadCtx(ssl, &cache);
    wolfSSL_CTX_sess_set_get_cb(ctx, wb_external_get);
    ssl->options.internalCacheLookupOff = 1;
    ssl->version = MakeTLSv1_2();
    cache.session->version = MakeTLSv1_2();

    if (CheckSessionMatch(NULL, cache.session) ||
            CheckSessionMatch(ssl, NULL) ||
            !CheckSessionMatch(ssl, cache.session))
        goto done;
    if (GetSessionFromCache(ssl, output, 0) != WOLFSSL_FAILURE ||
            cache.lookups != 0)
        goto done;

    ssl->options.haveSessionId = 1;
    if (GetSessionFromCache(ssl, NULL, 0) != WOLFSSL_FAILURE ||
            GetSessionFromCache(ssl, output, 1) != WOLFSSL_FAILURE ||
            cache.lookups != 0)
        goto done;
    if (GetSessionFromCache(ssl, output, 0) != WOLFSSL_SUCCESS ||
            cache.lookups != 1)
        goto done;

    cache.session->version = MakeTLSv1_3();
    if (GetSessionFromCache(ssl, output, 0) != WOLFSSL_FAILURE ||
            cache.lookups != 2)
        goto done;
    cache.transfer = 1;
    ssl->version = MakeTLSv1_3();
    ssl->options.haveSessionId = 0;
    ssl->session->haveAltSessionID = 1;
    cache.session->haveAltSessionID = 1;
    if (GetSessionFromCache(ssl, ssl->session, 0) != WOLFSSL_SUCCESS ||
            cache.lookups != 3 || cache.session != NULL)
        goto done;
    if (GetSessionFromCache(ssl, output, 0) != WOLFSSL_FAILURE ||
            cache.lookups != 4)
        goto done;
    failed = 0;

done:
    wolfSSL_CTX_sess_set_get_cb(ctx, NULL);
    wolfSSL_SESSION_free(cache.session);
    wolfSSL_SESSION_free(output);
    wolfSSL_free(ssl);
    return failed;
}
#endif

int main(void)
{
    int failed = 0;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    byte         id[ID_LEN];
    WOLFSSL_SESSION* got;

    wolfSSL_Init();

    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("ssl_sess white-box: no CTX\n");
        goto done;
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("ssl_sess white-box: no SSL\n");
        goto done;
    }

    XMEMSET(id, 0x5C, sizeof(id));

    /* wolfSSL_GetSessionClient returns before the ring walk if the context has
     * the cache switched off, which would make every vector below a no-op. */
    ctx->sessionCacheOff = 0;
    ssl->options.side = WOLFSSL_CLIENT_END;

    /* Every client row emptied: nextIdx 0 everywhere, so the backwards walk
     * starts at idx == -1 whichever row the id hashes to. totalCount 0 keeps
     * the loop below it from reading entries that were never written. */
    {
        int r;
        for (r = 0; r < CLIENT_SESSION_ROWS; r++) {
            ClientCache[r].nextIdx    = 0;
            ClientCache[r].totalCount = 0;
        }
    }
    got = wolfSSL_GetSessionClient(ssl, id, (int)sizeof(id));
    printf("  GetSessionClient on an empty ring (nextIdx 0) -> %s\n",
           got == NULL ? "no session" : "session");
    g_checks++;

    /* Same shape on the server-side cache, reached through the lookup that
     * TlsSessionCacheGetAndLock serves. */
    {
        int r;
        for (r = 0; r < SESSION_ROWS; r++) {
            SessionCache[r].nextIdx    = 0;
            SessionCache[r].totalCount = 0;
        }
    }
    {
        const WOLFSSL_SESSION* s = NULL;
        word32 lockedRow = 0;
        int    ret;

        ret = TlsSessionCacheGetAndLock(id, &s, &lockedRow, 1,
                                        WOLFSSL_CLIENT_END);
        if (ret == 0)
            TlsSessionCacheUnlockRow(lockedRow);
        printf("  TlsSessionCacheGetAndLock on an empty ring    -> ret %d\n",
               ret);
        g_checks++;
    }

    /* And once more with a row that has wrapped: nextIdx back at 0 with
     * entries present, which is the other way the first operand goes true. */
    {
        int r;
        for (r = 0; r < CLIENT_SESSION_ROWS; r++) {
            ClientCache[r].nextIdx    = 0;
            ClientCache[r].totalCount = CLIENT_SESSIONS_PER_ROW;
        }
    }
    got = wolfSSL_GetSessionClient(ssl, id, (int)sizeof(id));
    printf("  GetSessionClient on a wrapped ring            -> %s\n",
           got == NULL ? "no match" : "match");
    g_checks++;

    /* The accepting partner for both, without which neither operand pairs:
     * nextIdx in the middle of the ring, so idx is >= 0 and < the row size and
     * the guard is (F,F). */
    {
        int r;
        for (r = 0; r < CLIENT_SESSION_ROWS; r++) {
            ClientCache[r].nextIdx    = 1;
            ClientCache[r].totalCount = 1;
        }
        for (r = 0; r < SESSION_ROWS; r++) {
            SessionCache[r].nextIdx    = 1;
            SessionCache[r].totalCount = 1;
        }
    }
    got = wolfSSL_GetSessionClient(ssl, id, (int)sizeof(id));
    printf("  GetSessionClient mid-ring (nextIdx 1)         -> %s\n",
           got == NULL ? "no match" : "match");
    g_checks++;
    {
        const WOLFSSL_SESSION* s2 = NULL;
        word32 lockedRow2 = 0;
        int    ret2;

        ret2 = TlsSessionCacheGetAndLock(id, &s2, &lockedRow2, 1,
                                         WOLFSSL_CLIENT_END);
        if (ret2 == 0)
            TlsSessionCacheUnlockRow(lockedRow2);
        printf("  TlsSessionCacheGetAndLock mid-ring            -> ret %d\n",
               ret2);
        g_checks++;
    }

    /* Leave the caches as they were found. */
    {
        int r;
        for (r = 0; r < CLIENT_SESSION_ROWS; r++) {
            ClientCache[r].nextIdx    = 0;
            ClientCache[r].totalCount = 0;
        }
        for (r = 0; r < SESSION_ROWS; r++) {
            SessionCache[r].nextIdx    = 0;
            SessionCache[r].totalCount = 0;
        }
    }

    if (wb_session_copy_guards()) {
        puts("ssl_sess white-box: unexpected session copy guard result");
        failed = 1;
    }
#if defined(HAVE_SESSION_TICKET) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_session_ticket_copy()) {
        puts("ssl_sess white-box: unexpected ticket copy result");
        failed = 1;
    }
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) && \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_session_nonce_copy()) {
        puts("ssl_sess white-box: unexpected nonce copy result");
        failed = 1;
    }
#endif

#if defined(HAVE_EXT_CACHE) && defined(WOLFSSL_TLS13) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_external_cache_lookup(ctx)) {
        puts("ssl_sess white-box: unexpected external cache result");
        failed = 1;
    }
#endif

    printf("ssl_sess white-box: %d vectors driven\n", g_checks);

done:
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return failed;
}

#else

int main(void)
{
    printf("ssl_sess white-box: skipped (needs the session and client caches)\n");
    return 0;
}

#endif
