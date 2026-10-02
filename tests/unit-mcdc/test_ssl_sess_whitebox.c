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
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 */

#include <wolfssl/options.h>

#include <src/ssl.c>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(NO_SESSION_CACHE) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_CLIENT_CACHE) \
    && !defined(NO_CERTS)

static int g_checks;

int main(void)
{
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

    printf("ssl_sess white-box: %d vectors driven\n", g_checks);

done:
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("ssl_sess white-box: skipped (needs the session and client caches)\n");
    return 0;
}

#endif
