/* test_ssl_certman_whitebox.c
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

/* GetCAByName() walks the CertManager's CA hash table:
 *
 *     while (signers && ret == NULL) {
 *         if (XMEMCMP(hash, signers->subjectNameHash, ...) == 0)
 *             ret = signers;
 *         signers = signers->next;
 *     }
 *
 * The second operand is false only when a match was just assigned AND the
 * bucket still has an entry after it, so the loop condition gets re-evaluated
 * with ret set. If the match is the last entry in its bucket -- or the only
 * one -- signers goes NULL and the first operand short-circuits instead.
 *
 * That makes the operand a property of CA-table occupancy rather than of any
 * test: it needs two CAs that hash to the same row of CA_TABLE_SIZE, and the
 * lookup has to ask for the one that is not at the tail. Which certificates a
 * suite happens to load, and the order they were added in, decide whether that
 * ever happens. It is why this single condition was covered on one machine and
 * not on another from the same tree, the same tests and the same certificates
 * -- the 2026-09-05 and 2026-09-06 sweeps measured 49/113 where this host
 * measured 50/113, and the difference was exactly this line.
 *
 * Rather than leave it to whichever CAs a run happens to load, the bucket is
 * built here. GetCAByName reads only subjectNameHash and next and takes
 * cm->caLock, so two zeroed Signers linked head-to-tail are a complete and
 * safe fixture -- nothing else in either object is ever dereferenced. They
 * live on the stack, so the row is detached again before the CertManager is
 * freed; leaving them linked would send the teardown walking into this frame.
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

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && !defined(NO_SKID)

static int g_checks;

int main(void)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;
    Signer head;
    Signer tail;
    byte   hashHead[SIGNER_DIGEST_SIZE];
    byte   hashTail[SIGNER_DIGEST_SIZE];
    byte   hashMiss[SIGNER_DIGEST_SIZE];
    Signer* got;

    wolfSSL_Init();

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        printf("ssl_certman white-box: no CertManager\n");
        goto done;
    }

    XMEMSET(&head, 0, sizeof(head));
    XMEMSET(&tail, 0, sizeof(tail));
    XMEMSET(hashHead, 0x11, sizeof(hashHead));
    XMEMSET(hashTail, 0x22, sizeof(hashTail));
    XMEMSET(hashMiss, 0x33, sizeof(hashMiss));
    XMEMCPY(head.subjectNameHash, hashHead, SIGNER_DIGEST_SIZE);
    XMEMCPY(tail.subjectNameHash, hashTail, SIGNER_DIGEST_SIZE);

    /* One row, two entries: head -> tail. Which row does not matter; the walk
     * visits every row until it finds something. */
    head.next = &tail;
    tail.next = NULL;
    cm->caTable[0] = &head;

    /* (T,F): the match is the head, so a signer remains after it and the loop
     * condition is evaluated once more with ret already set. */
    got = GetCAByName(cm, hashHead);
    printf("  GetCAByName head of a two-entry row -> %s\n",
           got == &head ? "found" : "MISSED");
    g_checks++;

    /* (F,-): the match is the tail, so signers goes NULL and the first operand
     * ends the loop before the second is looked at. */
    got = GetCAByName(cm, hashTail);
    printf("  GetCAByName tail of a two-entry row -> %s\n",
           got == &tail ? "found" : "MISSED");
    g_checks++;

    /* No match anywhere: every row is walked to its end. */
    got = GetCAByName(cm, hashMiss);
    printf("  GetCAByName absent hash             -> %s\n",
           got == NULL ? "not found" : "UNEXPECTED");
    g_checks++;

    /* The NULL-manager guard above the walk. */
    got = GetCAByName(NULL, hashHead);
    printf("  GetCAByName NULL manager            -> %s\n",
           got == NULL ? "NULL" : "UNEXPECTED");
    g_checks++;

    /* Detach before teardown: both Signers are on this stack frame. */
    cm->caTable[0] = NULL;

    printf("ssl_certman white-box: %d vectors driven\n", g_checks);

done:
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("ssl_certman white-box: skipped (needs certs and SKID)\n");
    return 0;
}

#endif
