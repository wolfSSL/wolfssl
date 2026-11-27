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
 */

#include <wolfssl/options.h>

#include <wolfssl/wolfcrypt/wc_port.h>

#if defined(WOLFSSL_PTHREADS) && !defined(SINGLE_THREADED) && \
    !defined(NO_CERTS) && !defined(NO_SKID) && !defined(NO_TLS) && \
    !defined(WOLFCRYPT_ONLY) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    #define WB_CERTMAN_MUTEX_ERRORS
    static int wb_init_mutex(wolfSSL_Mutex* mutex);
    static int wb_lock_mutex(wolfSSL_Mutex* mutex);
    #define wc_InitMutex(mutex) wb_init_mutex(mutex)
    #define wc_LockMutex(mutex) wb_lock_mutex(mutex)
#endif
#include <src/ssl.c>
#ifdef WB_CERTMAN_MUTEX_ERRORS
    #undef wc_InitMutex
    #undef wc_LockMutex
#endif
#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && !defined(NO_SKID)

static int g_checks;

#ifdef WB_CERTMAN_MUTEX_ERRORS
static int wb_fail_next_init;
static wolfSSL_Mutex* wb_failed_lock;

static int wb_init_mutex(wolfSSL_Mutex* mutex)
{
    if (wb_fail_next_init) {
        wb_fail_next_init = 0;
        return BAD_MUTEX_E;
    }
    return wc_InitMutex(mutex);
}

static int wb_lock_mutex(wolfSSL_Mutex* mutex)
{
    if (mutex == wb_failed_lock)
        return BAD_MUTEX_E;
    return wc_LockMutex(mutex);
}

static int wb_certman_mutex_errors(WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_CERT_MANAGER* failedCm;
    int failed = 0;

    wb_fail_next_init = 1;
    failedCm = wolfSSL_CertManagerNew();
    if (failedCm != NULL || wb_fail_next_init != 0)
        failed = 1;
    wb_fail_next_init = 0;
    wolfSSL_CertManagerFree(failedCm);

    wb_failed_lock = &cm->caLock;
    if (wolfSSL_CertManagerUnloadCAs(cm) != BAD_MUTEX_E ||
        wolfSSL_CertManagerUnloadTypeCerts(cm, WOLFSSL_USER_CA) != BAD_MUTEX_E)
        failed = 1;
    wb_failed_lock = NULL;

    if (wolfSSL_CertManagerUnloadCAs(NULL) != BAD_FUNC_ARG ||
        wolfSSL_CertManagerUnloadTypeCerts(NULL, WOLFSSL_USER_CA) !=
            BAD_FUNC_ARG ||
        wolfSSL_CertManagerUnloadCAs(cm) != WOLFSSL_SUCCESS ||
        wolfSSL_CertManagerUnloadTypeCerts(cm, WOLFSSL_USER_CA) !=
            WOLFSSL_SUCCESS)
        failed = 1;
    return failed;
}
#endif

#if !defined(NO_RSA) && !defined(NO_TLS) && \
    !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#include <wolfssl/certs_test.h>

static int wb_certman_alloc_errors(WOLFSSL_CERT_MANAGER* cm)
{
    const byte* cert = ca_cert_der_2048;
    long length = sizeof_ca_cert_der_2048;
    WOLFSSL_CERT_MANAGER* failedCm;
    int ret;
    int failed = 0;

    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    failedCm = wolfSSL_CertManagerNew();
    mcdc_fa_restore();
    if (failedCm != NULL)
        failed = 1;
    wolfSSL_CertManagerFree(failedCm);

    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    ret = wolfSSL_CertManagerLoadCABuffer(cm, cert, length,
        WOLFSSL_FILETYPE_ASN1);
    mcdc_fa_restore();

    if (ret != WOLFSSL_FATAL_ERROR ||
        wolfSSL_CertManagerLoadCABuffer(NULL, cert, length,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_FATAL_ERROR ||
        wolfSSL_CertManagerLoadCABuffer(cm, cert, length,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
        wolfSSL_CertManagerUnloadCAs(cm) != WOLFSSL_SUCCESS)
        failed = 1;
    return failed;
}
#endif

#if defined(HAVE_CRL) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_crl_enable_failures(WOLFSSL_CERT_MANAGER* cm)
{
    static const byte der[] = {0x30, 0};
    int ret, failed = 0;

    if (wolfSSL_CertManagerLoadCRLBuffer(cm, NULL, sizeof(der),
            WOLFSSL_FILETYPE_ASN1) != BAD_FUNC_ARG)
        failed = 1;

    /* Fail before any of the loaders opens a file or decodes a CRL. */
    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    ret = wolfSSL_CertManagerLoadCRLBuffer(cm, der, sizeof(der),
        WOLFSSL_FILETYPE_ASN1);
    mcdc_fa_restore();
    if (ret != WOLFSSL_FATAL_ERROR || cm->crl != NULL)
        failed = 1;

    /* With allocation restored the loader reaches decoding. An empty DER
     * sequence is rejected there, and the initialized CRL store remains. */
    ret = wolfSSL_CertManagerLoadCRLBuffer(cm, der, sizeof(der),
        WOLFSSL_FILETYPE_ASN1);
    if (ret >= 0 || cm->crl == NULL)
        failed = 1;
    if (wolfSSL_CertManagerLoadCRLBuffer(cm, der, sizeof(der),
            WOLFSSL_FILETYPE_ASN1) >= 0)
        failed = 1;
    if (wolfSSL_CertManagerFreeCRL(cm) != WOLFSSL_SUCCESS)
        failed = 1;
#ifndef NO_FILESYSTEM
    if (wolfSSL_CertManagerLoadCRL(cm, NULL, WOLFSSL_FILETYPE_PEM, 0) !=
            BAD_FUNC_ARG ||
        wolfSSL_CertManagerLoadCRLFile(cm, NULL, WOLFSSL_FILETYPE_PEM) !=
            BAD_FUNC_ARG)
        failed = 1;

    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    ret = wolfSSL_CertManagerLoadCRL(cm, "./certs/crl",
        WOLFSSL_FILETYPE_PEM, 0);
    mcdc_fa_restore();
    if (ret != WOLFSSL_FATAL_ERROR || cm->crl != NULL)
        failed = 1;
    (void)wolfSSL_CertManagerLoadCRL(cm, "./certs/crl",
        WOLFSSL_FILETYPE_PEM, 0);
    if (cm->crl == NULL)
        failed = 1;
    else {
        (void)wolfSSL_CertManagerLoadCRL(cm, "./certs/no-such-directory",
            WOLFSSL_FILETYPE_PEM, 0);
    }
    if (wolfSSL_CertManagerFreeCRL(cm) != WOLFSSL_SUCCESS)
        failed = 1;

    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    ret = wolfSSL_CertManagerLoadCRLFile(cm, "./certs/crl/crl.pem",
        WOLFSSL_FILETYPE_PEM);
    mcdc_fa_restore();
    if (ret != WOLFSSL_FATAL_ERROR || cm->crl != NULL)
        failed = 1;
    ret = wolfSSL_CertManagerLoadCRLFile(cm, "./certs/no-such-crl.pem",
        WOLFSSL_FILETYPE_PEM);
    if (ret >= 0 || cm->crl == NULL)
        failed = 1;
    if (wolfSSL_CertManagerLoadCRLFile(cm, "./certs/no-such-crl.pem",
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_BAD_FILE)
        failed = 1;
    if (wolfSSL_CertManagerFreeCRL(cm) != WOLFSSL_SUCCESS)
        failed = 1;
#endif
    return failed;
}
#endif

#if defined(HAVE_OCSP) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
static int wb_ca_by_key_hash(WOLFSSL_CERT_MANAGER* cm)
{
    byte hash[KEYID_SIZE];
    Signer direct;
    Signer fallback;
    int failed = 0;

    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(&direct, 0, sizeof(direct));
    XMEMSET(&fallback, 0, sizeof(fallback));
    XMEMCPY(direct.subjectKeyIdHash, hash, sizeof(hash));
    XMEMCPY(direct.subjectKeyHash, hash, sizeof(hash));
    XMEMCPY(fallback.subjectKeyHash, hash, sizeof(hash));

    if (GetCAByKeyHash(NULL, hash) != NULL ||
            GetCAByKeyHash(cm, NULL) != NULL ||
            GetCAByKeyHash(cm, hash) != NULL)
        failed = 1;

    cm->caTable[HashSigner(hash)] = &direct;
    if (GetCAByKeyHash(cm, hash) != &direct)
        failed = 1;

    /* A signer can be found through its public-key hash when its subject
     * key identifier differs. */
    direct.subjectKeyIdHash[0] = 1;
    direct.subjectKeyHash[0] = 1;
    fallback.subjectKeyIdHash[0] = 2;
    direct.next = &fallback;
    if (GetCAByKeyHash(cm, hash) != &fallback)
        failed = 1;

    cm->caTable[HashSigner(hash)] = NULL;
    return failed;
}
#endif

int main(void)
{
    int failed = 0;
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

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (GetCAByNameSkip(cm, hashHead, &head) != NULL ||
        GetCAByNameSkip(cm, hashHead, &tail) != &head) {
        puts("ssl_certman white-box: unexpected skipped signer result");
        failed = 1;
    }
#endif

    /* Detach before teardown: both Signers are on this stack frame. */
    cm->caTable[0] = NULL;

#if defined(HAVE_CRL) && !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_crl_enable_failures(cm)) {
        puts("ssl_certman white-box: unexpected CRL allocation result");
        failed = 1;
    }
#endif

#if defined(HAVE_OCSP) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_ca_by_key_hash(cm)) {
        puts("ssl_certman white-box: unexpected signer lookup result");
        failed = 1;
    }
#endif

#ifdef WB_CERTMAN_MUTEX_ERRORS
    if (wb_certman_mutex_errors(cm)) {
        puts("ssl_certman white-box: unexpected mutex result");
        failed = 1;
    }
#endif
#if !defined(NO_RSA) && !defined(NO_TLS) && \
    !defined(MCDC_FA_UNAVAILABLE) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    if (wb_certman_alloc_errors(cm)) {
        puts("ssl_certman white-box: unexpected allocation result");
        failed = 1;
    }
#endif

    printf("ssl_certman white-box: %d vectors driven\n", g_checks);

done:
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    wolfSSL_Cleanup();
    return failed;
}

#else

int main(void)
{
    printf("ssl_certman white-box: skipped (needs certs and SKID)\n");
    return 0;
}

#endif
