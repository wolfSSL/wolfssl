/* test_internal_eddsa_whitebox.c -- MC/DC white-box driver for the
 * file-static EdDSA_Update message-cache allocation guard in src/internal.c
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

/* WHY A WHITE-BOX.
 *
 * EdDSA_Update()'s cache-growth guard is
 *     if ((ret == 0) && (ssl->hsHashes->messages != NULL))
 * `ret` is 0 unless the growth allocation just above it failed, and a real
 * client-auth handshake never sees that allocation fail, so `ret == 0` is
 * pinned true across the whole real corpus -- the operand this driver targets
 * never gets to flip there. (The other operand, hsHashes->messages != NULL,
 * already gets both values across a real cached handshake, as successive
 * updates append to a buffer that starts NULL -- that is why only one operand
 * is a gap here.)
 *
 * The only way to make the allocation fail on demand, without a real
 * out-of-memory condition, is mcdc_fault_alloc.h's counted allocator mock:
 * arm it for exactly the one XMALLOC inside this call, so this call's
 * allocation fails while everything the driver itself allocates around it
 * (the fixture's own buffers) does not.
 *
 * MC/DC's independence pair has to be demonstrated inside ONE binary's own
 * execution trace -- the campaign's union is a logical OR of per-binary
 * covered bits, not a merge of raw traces -- so both the failing and the
 * succeeding vector are produced by THIS driver.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - The target carries the SAME preprocessor guard that encloses it in
 *     internal.c.
 */

#include <wolfssl/options.h>

#include <src/internal.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12)

#ifndef NO_TLS
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)) || \
                (defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))

static int g_calls;

static void wb_eddsa_update(void)
{
    WOLFSSL   ssl;
    HS_Hashes hashes;
    byte      old_msgs1[4];
    byte      old_msgs2[4];
    byte*     prepped;
    static const byte data[4] = { 0xAA, 0xBB, 0xCC, 0xDD };

    XMEMSET(&ssl, 0, sizeof(ssl));
    ssl.heap = NULL;
    ssl.options.cacheMessages = 1;

    mcdc_fa_install();

    /* operand false: the growth allocation for this call fails, so ret !=
     * 0 and the guard short-circuits on its first operand. hsHashes->
     * messages is left untouched (still old_msgs1, which this driver owns
     * and frees itself -- the function never reached the free-the-old-
     * buffer step). */
    XMEMSET(&hashes, 0, sizeof(hashes));
    XMEMCPY(old_msgs1, data, sizeof(old_msgs1));
    prepped = (byte*)XMALLOC(sizeof(old_msgs1), NULL, DYNAMIC_TYPE_HASHES);
    if (prepped != NULL) {
        XMEMCPY(prepped, old_msgs1, sizeof(old_msgs1));
        hashes.messages = prepped;
        hashes.length   = (int)sizeof(old_msgs1);
        ssl.hsHashes = &hashes;

        mcdc_fa_arm_only(1);   /* the one XMALLOC inside EdDSA_Update */
        (void)EdDSA_Update(&ssl, data, (int)sizeof(data));
        mcdc_fa_disarm();
        g_calls++;

        XFREE(hashes.messages, NULL, DYNAMIC_TYPE_HASHES);
        hashes.messages = NULL;
    }

    /* operand true: the same call, unarmed. The allocation succeeds, the
     * old buffer is freed BY THE FUNCTION and replaced, and the driver
     * frees the new one afterward. */
    XMEMSET(&hashes, 0, sizeof(hashes));
    XMEMCPY(old_msgs2, data, sizeof(old_msgs2));
    prepped = (byte*)XMALLOC(sizeof(old_msgs2), NULL, DYNAMIC_TYPE_HASHES);
    if (prepped != NULL) {
        XMEMCPY(prepped, old_msgs2, sizeof(old_msgs2));
        hashes.messages = prepped;
        hashes.length   = (int)sizeof(old_msgs2);
        ssl.hsHashes = &hashes;

        (void)EdDSA_Update(&ssl, data, (int)sizeof(data));
        g_calls++;

        /* the function replaced hashes.messages with a freshly grown
         * buffer (old length + sizeof(data)); that is what needs freeing
         * now, not "prepped" (which the function already freed). */
        XFREE(hashes.messages, NULL, DYNAMIC_TYPE_HASHES);
        hashes.messages = NULL;
    }

    mcdc_fa_restore();
    ssl.hsHashes = NULL;
}

#endif /* !WOLFSSL_NO_CLIENT_AUTH && (SM2 || ED25519 || ED448) */
#endif /* !NO_TLS */

/* ---------------------------------------------------------------------- main */

int main(void)
{
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("internal EdDSA white-box: wolfSSL_Init failed\n");
        return 0;
    }

#ifndef NO_TLS
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)) || \
                (defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
    wb_eddsa_update();
    printf("internal EdDSA white-box: %d static-guard calls\n", g_calls);
#else
    printf("internal EdDSA white-box: skipped (no EdDSA client auth)\n");
#endif
#else
    printf("internal EdDSA white-box: skipped (NO_TLS)\n");
#endif

    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal EdDSA white-box: skipped (TLS 1.2 not built)\n");
    return 0;
}

#endif
