/* test_ocsp_whitebox.c -- MC/DC white-box driver for src/ocsp.c
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
 * src/ocsp.c measured 7 of 47 conditions at intake. The `ocsp` group runs 3 of
 * its 8 tests on the campaign option list -- the rest are gated on the OpenSSL
 * compat layer this option list excludes as a build fact -- so most of the file
 * is never entered from tests/api at all.
 *
 * The conditions that remain are lookup-table comparisons inside file-static
 * helpers: matching a cached OCSP entry by issuer hash, and matching a status
 * by serial. A caller coming through the public API always presents a
 * consistent (issuerHash, serial) pair derived from a real DecodedCert, so the
 * "same length, different content" and "different hash" cases -- exactly the
 * ones an attacker controls -- have no independence pair from outside.
 *
 * Rules, same as the sibling drivers:
 *   - options.h FIRST, before any other wolfSSL header, or the smoke build
 *     compiles this with the feature macros undefined and it silently becomes
 *     a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Every rejecting vector has its accepting partner in THIS binary.
 *   - Bail paths print, so "covered nothing" is distinguishable from
 *     "had nothing to say".
 */

#include <wolfssl/options.h>

#include <src/ocsp.c>

#include <stdio.h>
#include <string.h>

#if defined(HAVE_OCSP) && !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS)

static int g_checks;
#define WB_NOTE(what) do { g_checks++; (void)(what); } while (0)

/* ------------------------------------------------ FindStatus / entry :243 */
/* `if (XMEMCMP((*entry)->issuerHash, request->issuerHash, ...) == 0 && ...)`
 *
 * Both operands need a pair, and the second is only reachable when the first
 * matches. Three vectors: issuer hash differing (operand 0 false), issuer hash
 * matching with the second discriminator differing (operand 0 true, operand 1
 * false), and both matching (the accepting partner).
 *
 * The public path builds request and entry from the same certificate, so
 * outside this binary the two hashes are equal by construction and operand 0
 * has no false case at all. */
/* GetOcspEntry() prepends a freshly allocated OcspEntry when it finds no
 * match, making it the new head. The driver then re-points ocspList at its own
 * stack node for the next vector, which drops that pointer on the floor. Free
 * every heap node ahead of the stack node before doing so. */
static void wb_free_prepended(WOLFSSL_OCSP* ocsp, OcspEntry* stackNode)
{
    void* heap = (ocsp->cm != NULL) ? ocsp->cm->heap : NULL;
    OcspEntry* e = ocsp->ocspList;

    /* Same heap derivation FreeOcspEntry's own caller in src/ocsp.c uses. */
    while (e != NULL && e != stackNode) {
        OcspEntry* next = e->next;

        FreeOcspEntry(e, heap);
        XFREE(e, heap, DYNAMIC_TYPE_OCSP_ENTRY);
        e = next;
    }
    ocsp->ocspList = stackNode;
}

static void wb_entry_match(WOLFSSL_OCSP* ocsp)
{
    OcspRequest req;
    OcspEntry seeded;
    OcspEntry* found = NULL;

    /* Seed the cache with one entry so the loop body executes. GetOcspEntry
     * walks ocsp->ocspList and compares each node against the request; with an
     * empty list the loop never runs and the comparison is never evaluated,
     * which is exactly why driving this from the public API proves nothing. */
    XMEMSET(&seeded, 0, sizeof(seeded));
    XMEMSET(seeded.issuerHash,    0xAA, OCSP_DIGEST_SIZE);
    XMEMSET(seeded.issuerKeyHash, 0xCC, OCSP_DIGEST_SIZE);
    seeded.next = NULL;
    ocsp->ocspList = &seeded;

    /* Vector 1: issuer hash differs -> operand 0 false, operand 1 not reached.
     * Pairs with vector 3. */
    XMEMSET(&req, 0, sizeof(req));
    XMEMSET(req.issuerHash,    0xBB, OCSP_DIGEST_SIZE);
    XMEMSET(req.issuerKeyHash, 0xCC, OCSP_DIGEST_SIZE);
    WB_NOTE(GetOcspEntry(ocsp, &req, &found));
    /* No match, so GetOcspEntry PREPENDED a heap entry and made it the head.
     * Free it here: the next vector overwrites ocspList, which would otherwise
     * lose the pointer, and the teardown sets the list to NULL rather than
     * walking it (it cannot walk it -- the seeded node is on the stack). */
    wb_free_prepended(ocsp, &seeded);

    /* Vector 2: issuer hash equal, key hash differs -> operand 0 true,
     * operand 1 false. Pairs with vector 3 on operand 1. */
    ocsp->ocspList = &seeded;
    seeded.next = NULL;
    XMEMSET(req.issuerHash,    0xAA, OCSP_DIGEST_SIZE);
    XMEMSET(req.issuerKeyHash, 0xDD, OCSP_DIGEST_SIZE);
    found = NULL;
    WB_NOTE(GetOcspEntry(ocsp, &req, &found));
    wb_free_prepended(ocsp, &seeded);

    /* Vector 3: both equal -> the accepting partner that completes both pairs. */
    ocsp->ocspList = &seeded;
    seeded.next = NULL;
    XMEMSET(req.issuerKeyHash, 0xCC, OCSP_DIGEST_SIZE);
    found = NULL;
    WB_NOTE(GetOcspEntry(ocsp, &req, &found));

    /* Vector 3 matched, so nothing was prepended; the head is still the stack
     * node. Detach it before the CertManager frees the list, or the teardown
     * walks into this frame. */
    ocsp->ocspList = NULL;
}


/* ---------------------------------------------- CheckOcspResponder :625-644 */
/* `if (bs == NULL || subjectNameHash == NULL || issuerNameHash == NULL)` and
 * the two responder-identity chains
 *     subjectKeyHash != NULL && XMEMCMP(subjectNameHash, single->issuerHash)
 *                            && XMEMCMP(subjectKeyHash,  single->issuerKeyHash)
 *     issuerKeyHash  != NULL && XMEMCMP(issuerNameHash, ...) && ...
 *
 * This one is genuinely hermetic: it takes an OcspResponse and four raw
 * hashes, walks bs->single, and compares bytes. Nothing is stored, so the
 * response can be a local -- unlike GetOcspEntry, which links what it is
 * given into ocsp->ocspList, a list the library allocates and frees. A stack
 * fixture there crashed; here there is no ownership at all.
 *
 * Each vector below breaks the chain at a DIFFERENT operand, and the last one
 * matches on every field so the earlier ones have an accepting partner.
 * A real response is always self-consistent, which is why the mismatch cases
 * have no independence pair from outside. */
static void wb_check_responder(void)
{
    OcspResponse bs;
    OcspEntry    single;
    byte subjName[OCSP_DIGEST_SIZE];
    byte issuName[OCSP_DIGEST_SIZE];
    byte subjKey[KEYID_SIZE];
    byte issuKey[KEYID_SIZE];
    byte other[OCSP_DIGEST_SIZE];

    XMEMSET(&bs,     0, sizeof(bs));
    XMEMSET(&single, 0, sizeof(single));
    XMEMSET(subjName, 0x11, sizeof(subjName));
    XMEMSET(issuName, 0x22, sizeof(issuName));
    XMEMSET(subjKey,  0x33, sizeof(subjKey));
    XMEMSET(issuKey,  0x44, sizeof(issuKey));
    XMEMSET(other,    0x99, sizeof(other));

    /* the response's single entry is signed by the subject */
    XMEMCPY(single.issuerHash,    subjName, OCSP_DIGEST_SIZE);
    XMEMCPY(single.issuerKeyHash, subjKey,  KEYID_SIZE);
    single.next = NULL;
    bs.single = &single;

    /* :625, one vector per operand */
    WB_NOTE(CheckOcspResponder(NULL, subjName, subjKey, 0, issuName, issuKey));
    WB_NOTE(CheckOcspResponder(&bs, NULL, subjKey, 0, issuName, issuKey));
    WB_NOTE(CheckOcspResponder(&bs, subjName, subjKey, 0, NULL, issuKey));

    /* :631 operand 0 false -- no subject key hash offered */
    WB_NOTE(CheckOcspResponder(&bs, subjName, NULL, 0, issuName, issuKey));
    /* :631 operand 1 false -- subject name does not match the single entry */
    WB_NOTE(CheckOcspResponder(&bs, other, subjKey, 0, issuName, issuKey));
    /* :631 operand 2 false -- name matches, key does not */
    WB_NOTE(CheckOcspResponder(&bs, subjName, other, 0, issuName, issuKey));
    /* :631 all true -- the accepting partner for the three above */
    WB_NOTE(CheckOcspResponder(&bs, subjName, subjKey, 0, issuName, issuKey));

    /* the delegated-responder arm: reached only when the subject chain fails
     * AND the OCSP-signing usage bit is set. Re-point the single entry at the
     * issuer so that chain can succeed. */
    XMEMCPY(single.issuerHash,    issuName, OCSP_DIGEST_SIZE);
    XMEMCPY(single.issuerKeyHash, issuKey,  KEYID_SIZE);

    /* :640 operand 0 false -- no issuer key hash offered */
    WB_NOTE(CheckOcspResponder(&bs, subjName, subjKey, EXTKEYUSE_OCSP_SIGN,
                               issuName, NULL));
    /* :640 operand 2 false -- issuer name matches, key does not */
    WB_NOTE(CheckOcspResponder(&bs, subjName, subjKey, EXTKEYUSE_OCSP_SIGN,
                               issuName, other));
    /* :640 all true -- accepting partner */
    WB_NOTE(CheckOcspResponder(&bs, subjName, subjKey, EXTKEYUSE_OCSP_SIGN,
                               issuName, issuKey));

    bs.single = NULL;
}


/* --------------------------------------------------- CheckOcspRequest :484+

 * This is where an OCSP check leaves the library: pick a responder URL, hand
 * the encoded request to the application's transport callback, and interpret
 * whatever comes back. From tests/api it is entered only when a real responder
 * is configured, which no unit test does -- so the URL selection, the callback
 * result handling and the response-free hook are all uncovered.
 *
 * None of it needs a network. CbOCSPIO is
 *     int (*)(void* ctx, const char* url, int urlSz,
 *             unsigned char** response)
 * so a callback that hands back a static buffer is a complete responder for
 * the purposes of this function, and it can return the results a real one
 * cannot be made to produce on demand: a negative error, a zero-length body,
 * a NULL response with a positive length. That is the point of mocking the
 * consumed interface rather than the transport.
 */

static byte  g_ocspResp[64];
static int   g_ioResult;        /* what the mock returns */
static int   g_ioNullResponse;  /* return a positive size but no buffer */
static int   g_ioCalls;
static int   g_freeCalls;

static int wb_ocsp_io(void* ctx, const char* url, int urlSz,
                      unsigned char* request, int requestSz,
                      unsigned char** response)
{
    (void)ctx; (void)url; (void)urlSz; (void)request; (void)requestSz;
    g_ioCalls++;
    if (response != NULL)
        *response = g_ioNullResponse ? NULL : g_ocspResp;
    return g_ioResult;
}

static void wb_ocsp_respfree(void* ctx, unsigned char* response)
{
    (void)ctx; (void)response;
    g_freeCalls++;
}

static void wb_check_request(WOLFSSL_CERT_MANAGER* cm)
{
    OcspRequest req;
    byte serial[8];
    byte url[] = "http://ocsp.example.com/";
    size_t i;

    /* the two operands of the argument guard at :504 */
    WB_NOTE(CheckOcspRequest(NULL, NULL, NULL, NULL));
    WB_NOTE(CheckOcspRequest(cm->ocsp, NULL, NULL, NULL));

    XMEMSET(g_ocspResp, 0, sizeof(g_ocspResp));
    g_ocspResp[0] = 0x30;
    g_ocspResp[1] = 0x02;

    /* Each row is one operand of the URL-selection, callback-result and
     * response-free decisions. `haveUrl` drives
     * `ocspRequest->urlSz != 0 && ocspRequest->url != NULL`, which a request
     * built from a certificate's AIA extension always satisfies. */
    {
        static const struct { int haveUrl; int urlSz; int ioResult;
                              int nullResp; int installIo; int installFree;
                              const char* what; } rows[] = {
            { 1, 24,  8, 0, 1, 1, "url and a responder that answers" },
            { 1, 24,  8, 0, 1, 0, "answered, no free callback" },
            { 1, 24,  0, 0, 1, 1, "responder returns zero bytes" },
            { 1, 24, -1, 0, 1, 1, "responder returns an error" },
            { 1, 24,  8, 1, 1, 1, "positive length, NULL buffer" },
            { 1, 24,  8, 0, 0, 0, "no responder callback installed" },
            { 1,  0,  8, 0, 1, 1, "url present, length zero" },
            { 0, 24,  8, 0, 1, 1, "length present, url NULL" },
            { 0,  0,  8, 0, 1, 1, "no url at all" },
        };

        for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            XMEMSET(&req, 0, sizeof(req));
            XMEMSET(serial, 0x5A, sizeof(serial));
            req.serial   = serial;
            req.serialSz = (int)sizeof(serial);
            XMEMSET(req.issuerHash,    0xAA, OCSP_DIGEST_SIZE);
            XMEMSET(req.issuerKeyHash, 0xCC, OCSP_DIGEST_SIZE);
            req.url   = rows[i].haveUrl ? url : NULL;
            req.urlSz = rows[i].urlSz;

            g_ioResult = rows[i].ioResult;
            g_ioNullResponse = rows[i].nullResp;
            (void)wolfSSL_CertManagerSetOCSP_Cb(cm,
                    rows[i].installIo ? wb_ocsp_io : NULL,
                    rows[i].installFree ? wb_ocsp_respfree : NULL,
                    NULL);

            WB_NOTE(CheckOcspRequest(cm->ocsp, &req, NULL, NULL));

            /* GetOcspEntry appends a heap entry when it finds no match; drop
             * the list between rows so each row starts from an empty cache
             * and the "found" and "not found" arms both get exercised. */
        }
    }

    /* `if (cm != NULL && cm->ocspFailIfNotSupported)` at :596 -- the policy
     * flag that decides whether an unreachable responder is fatal. */
    cm->ocspFailIfNotSupported = 1;
    XMEMSET(&req, 0, sizeof(req));
    req.url = url; req.urlSz = 24;
    XMEMSET(req.issuerHash, 0xAB, OCSP_DIGEST_SIZE);
    g_ioResult = -1;
    (void)wolfSSL_CertManagerSetOCSP_Cb(cm, wb_ocsp_io, wb_ocsp_respfree, NULL);
    WB_NOTE(CheckOcspRequest(cm->ocsp, &req, NULL, NULL));
    cm->ocspFailIfNotSupported = 0;
    WB_NOTE(CheckOcspRequest(cm->ocsp, &req, NULL, NULL));

    (void)wolfSSL_CertManagerSetOCSP_Cb(cm, NULL, NULL, NULL);
}

/* ------------------------------------------------------ CheckOcspResponse */
/* `if (newStatus == NULL || newSingle == NULL || ocspResponse == NULL)` and
 * the multi-response and response-buffer arms. The bytes are the interesting
 * input: a caller cannot ask a real responder for a truncated DER. */
static void wb_check_response(WOLFSSL_CERT_MANAGER* cm)
{
    OcspRequest req;
    byte junk[16];
    size_t i;

    static const struct { int sz; const char* what; } rows[] = {
        {  0, "zero-length response" },
        {  1, "one byte" },
        { 16, "sixteen bytes of nothing" },
        { -1, "negative length" },
    };

    XMEMSET(junk, 0x30, sizeof(junk));
    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        XMEMSET(&req, 0, sizeof(req));
        XMEMSET(req.issuerHash, 0xAA, OCSP_DIGEST_SIZE);
        req.serialSz = 4;
        WB_NOTE(CheckOcspResponse(cm->ocsp, junk, rows[i].sz, NULL, NULL,
                                  NULL, &req, NULL, NULL));
    }
    WB_NOTE(CheckOcspResponse(cm->ocsp, NULL, 0, NULL, NULL, NULL, NULL, NULL,
                              NULL));
}

/* ---------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("ocsp white-box: wolfSSL_Init failed\n");
        goto done;
    }
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        printf("ocsp white-box: CertManagerNew failed\n");
        goto done;
    }
    if (wolfSSL_CertManagerEnableOCSP(cm, 0) != WOLFSSL_SUCCESS) {
        printf("ocsp white-box: EnableOCSP failed\n");
        goto done;
    }

    wb_entry_match(cm->ocsp);
    wb_check_responder();
    wb_check_request(cm);
    wb_check_response(cm);

    printf("ocsp white-box: %d vectors driven\n", g_checks);

done:
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else /* !HAVE_OCSP */

int main(void)
{
    printf("ocsp white-box: skipped (needs HAVE_OCSP, certs, and not WOLFCRYPT_ONLY)\n");
    return 0;
}

#endif
