/* test_crl_whitebox.c -- MC/DC white-box driver for src/crl.c
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
 * src/crl.c measured 3 of 48 conditions at intake -- the lowest in the whole
 * campaign -- and the reason is driver reach, not difficulty. There is no `crl`
 * test group: CRL work lives inside the `certman` group, which runs 11 of its
 * 36 tests on the campaign option list because the rest are gated on the
 * OpenSSL compat layer that this option list deliberately excludes as a build
 * fact. So most of crl.c is never entered at all from tests/api.
 *
 * What remains is reachable only by calling the file's own helpers with
 * argument combinations the public API never produces: a revoked-cert lookup
 * with neither a serial nor a serial hash, a CertManager with a missing-CRL
 * callback installed but no CRL loaded, a serial that matches in length but
 * not in content. This driver does that directly.
 *
 * Rules, same as the other drivers in this directory:
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 *   - Every rejecting vector has its accepting partner in THIS binary.
 *   - Bail paths print, so a driver that covers nothing is distinguishable
 *     from a driver that had nothing to say.
 */

/* crl.c first and nothing before it: it includes settings.h, which picks up
 * user_settings.h under the campaign builds and options.h under the
 * --enable-all smoke build. Putting settings.h or options.h ahead of it breaks
 * the header order for one of the two. */
/* options.h FIRST, before any other wolfSSL header. Under the campaign's
 * --enable-usersettings builds it just defines WOLFSSL_USER_SETTINGS and
 * settings.h then reads user_settings.h; under the --enable-all smoke build it
 * is where every feature macro actually lives. Getting this wrong is silent in
 * the worst way: without it the smoke build compiled this driver with
 * WOLFSSL_CRL undefined, so it took the skip stub, exited 0, and was recorded
 * as a passing entry in smoke-expected.txt while testing nothing at all. */
#include <wolfssl/options.h>

#include <src/crl.c>

#include <stdio.h>
#include <string.h>

#if defined(HAVE_CRL) && !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS)

static int g_checks;
#define WB_NOTE(what) do { g_checks++; (void)(what); } while (0)

/* ------------------------------------------------ CheckCertCRLCm :607 */
/* `if ((serial == NULL || serialSz == 0) && serialHash == NULL)`
 *
 * Three operands, so four vectors. The inner OR short-circuits, so operand 1
 * (serialSz == 0) is only reachable with a non-NULL serial, and operand 2
 * (serialHash == NULL) is only reachable when the inner OR is true.
 *
 *   serial=NULL  sz=n  hash=set  -> op0 true,  op2 false          (op2 pair)
 *   serial=NULL  sz=n  hash=NULL -> op0 true,  op2 true           (op0 pair)
 *   serial=set   sz=0  hash=NULL -> op0 false, op1 true, op2 true (op1 pair)
 *   serial=set   sz=n  hash=NULL -> op0 false, op1 false          (accepting)
 *
 * No public caller can ask for this: wolfSSL_CertManagerCheckCRL and the
 * internal CheckCertCRL both derive serial and serialSz from a DecodedCert
 * that always has both, so the guard is dead from outside and its operands
 * have no independence pair there. */
static void wb_check_cert_crl_ex(WOLFSSL_CERT_MANAGER* cm)
{
    byte serial[] = { 0x01, 0x02, 0x03 };
    byte hash[SIGNER_DIGEST_SIZE];
    byte issuerHash[SIGNER_DIGEST_SIZE];

    XMEMSET(hash, 0x11, sizeof(hash));
    XMEMSET(issuerHash, 0x22, sizeof(issuerHash));

    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, NULL, (int)sizeof(serial),
                           hash, NULL, 0, NULL, cm));
    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, NULL, (int)sizeof(serial),
                           NULL, NULL, 0, NULL, cm));
    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, serial, 0,
                           NULL, NULL, 0, NULL, cm));
    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, serial, (int)sizeof(serial),
                           NULL, NULL, 0, NULL, cm));
}


/* --------------------------------------------- CheckCertCRLCm :668, :686 */
/* `if (cm != NULL && cm->cbMissingCRL)` and
 * `if (cm != NULL && cm->crlCb && cm->crlCb(ret, crl, cm, cm->crlCbCtx))`
 *
 * Reached only when foundEntry == 0, i.e. no CRL matched -- the CRL_MISSING
 * path, which is where a caller is told the check could not be completed.
 *
 * An earlier version of this driver passed cm == NULL and cm != NULL with no
 * callbacks installed, and gained nothing. Both evaluations take the decision
 * FALSE -- once by short-circuit and once because the callback pointer is
 * NULL -- so operand 0 changed value without changing the outcome, which is
 * not an independence pair. MC/DC needs the DECISION to flip, so at least one
 * vector has to install the callback and drive the decision true.
 *
 * The full set, per decision:
 *   cm == NULL                        -> op0 false, decision false
 *   cm != NULL, callback NULL         -> op0 true, op1 false, decision false
 *   cm != NULL, callback installed    -> op0 true, op1 true, decision TRUE
 *
 * and for :686 a third operand, the callback's own return value, needs one
 * vector returning zero and one returning non-zero.
 *
 * No public caller can produce the cm == NULL case: every path into this
 * function comes from a CertManager. */

static int g_missingCalled;
static int g_crlCbCalled;
static int g_crlCbResult;

static void wb_missing_crl_cb(const char* url)
{
    g_missingCalled++;
    (void)url;
}

static int wb_crl_err_cb(int ret, WOLFSSL_CRL* crl, WOLFSSL_CERT_MANAGER* cm,
                         void* ctx)
{
    g_crlCbCalled++;
    (void)ret; (void)crl; (void)cm; (void)ctx;
    return g_crlCbResult;   /* drives operand 2 of the :686 chain */
}

static void wb_missing_crl_callbacks(WOLFSSL_CERT_MANAGER* cm)
{
    byte serial[] = { 0x0a, 0x0b };
    byte issuerHash[SIGNER_DIGEST_SIZE];
    const char* url = "http://crl.example.com/root.crl";

    XMEMSET(issuerHash, 0x33, sizeof(issuerHash));

    /* 1. cm NULL: operand 0 false for both decisions. */
    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, serial, (int)sizeof(serial),
                           NULL, (const byte*)url, (int)XSTRLEN(url), NULL,
                           NULL));

    /* 2. real cm, no callbacks: operand 0 true, operand 1 false. */
    cm->cbMissingCRL = NULL;
    cm->crlCb = NULL;
    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, serial, (int)sizeof(serial),
                           NULL, (const byte*)url, (int)XSTRLEN(url), NULL,
                           cm));

    /* 3. both callbacks installed, error cb returns 0: takes :668 TRUE (the
     * partner that gives operands 0 and 1 their pairs) and :686 to its third
     * operand, false. */
    cm->cbMissingCRL = wb_missing_crl_cb;
    cm->crlCb = wb_crl_err_cb;
    g_crlCbResult = 0;
    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, serial, (int)sizeof(serial),
                           NULL, (const byte*)url, (int)XSTRLEN(url), NULL,
                           cm));

    /* 4. error cb returns non-zero: :686 operand 2 true, decision TRUE, which
     * is the override-the-CRL-error path. */
    g_crlCbResult = 1;
    WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, serial, (int)sizeof(serial),
                           NULL, (const byte*)url, (int)XSTRLEN(url), NULL,
                           cm));

    /* 5. a url longer than the 256-byte stack buffer takes the "CRL url too
     * long" arm of the copy guard inside the :668 body, which the short url
     * above leaves unexercised. */
    {
        char longUrl[300];
        XMEMSET(longUrl, 'u', sizeof(longUrl) - 1);
        longUrl[sizeof(longUrl) - 1] = '\0';
        WB_NOTE(CheckCertCRLCm(cm->crl, issuerHash, serial,
                               (int)sizeof(serial), NULL, (const byte*)longUrl,
                               (int)sizeof(longUrl) - 1, NULL, cm));
    }

    cm->cbMissingCRL = NULL;
    cm->crlCb = NULL;
}


/* ------------------------------- BufferLoadCRL :913 / BufferStoreCRL :1011,
 *                                 :1036, :1044, :1081, :1105, :1146 */
/* The load and store entry points are argument-validated with wide OR chains
 *
 *     if (crl == NULL || buff == NULL || sz <= 0)
 *     if (crl == NULL || inOutSz == NULL)
 *     if (ent == NULL || tbs == NULL || tbsSz == 0 || sig == NULL || sigSz == 0)
 *
 * and then branch on the encoding
 *
 *     if (ret == 0 && type == WOLFSSL_FILETYPE_ASN1)
 *     else if (ret == 0 && type == WOLFSSL_FILETYPE_PEM)
 *
 * Every in-tree caller passes a real CRL and a real type, so the rejecting
 * side of each operand is unreachable from outside, while the ACCEPTING side
 * needs a genuinely parsed CRL entry -- a hand-built one does not have
 * toBeSigned or signature populated, so it can only ever take the :1036 guard
 * true and would leave the whole store path uncovered.
 *
 * That is the lesson from the ocsp sibling: build the fixture with the real
 * loader and let the library own it, rather than assembling structs on the
 * stack and linking them into lists the library frees.
 *
 * Both encodings are driven because the type operand of :1081 and :1146 needs
 * a pair, and certs/crl carries both a DER and a PEM of the same CRL. */
static void wb_buffer_load_store(WOLFSSL_CERT_MANAGER* cm)
{
    static const char* kDer = "certs/crl/crl.der";
    static const char* kPem = "certs/crl/crl.pem";
    byte  der[4096];
    long  n = 0;
    int   loaded = 0;
    XFILE f;

    /* ---- BufferLoadCRL :913, one vector per operand plus the partner ---- */
    f = XFOPEN(kDer, "rb");
    if (f != XBADFILE) {
        n = (long)XFREAD(der, 1, sizeof(der), f);
        XFCLOSE(f);
    }
    if (n <= 0) {
        /* Without the file the accepting partner does not exist, so the
         * rejecting vectors below would prove nothing. Say so rather than
         * report a pass. */
        printf("crl white-box: %s unreadable, load/store vectors skipped\n",
               kDer);
        return;
    }

    WB_NOTE(BufferLoadCRL(NULL, der, n, WOLFSSL_FILETYPE_ASN1, 0));
    WB_NOTE(BufferLoadCRL(cm->crl, NULL, n, WOLFSSL_FILETYPE_ASN1, 0));
    WB_NOTE(BufferLoadCRL(cm->crl, der, 0, WOLFSSL_FILETYPE_ASN1, 0));
    /* the accepting partner: a real DER CRL, which also populates crl->crlList
     * so the store path below has an entry with toBeSigned and signature. */
    if (BufferLoadCRL(cm->crl, der, n, WOLFSSL_FILETYPE_ASN1, 0)
            == WOLFSSL_SUCCESS) {
        loaded = 1;
    }
    g_checks += 4;

    /* ---- BufferStoreCRL :1011 argument guard ---- */
    {
        long outSz = (long)sizeof(der);
        WB_NOTE(BufferStoreCRL(NULL, der, &outSz, WOLFSSL_FILETYPE_ASN1));
        WB_NOTE(BufferStoreCRL(cm->crl, der, NULL, WOLFSSL_FILETYPE_ASN1));
    }

    if (!loaded) {
        printf("crl white-box: DER CRL did not load, store vectors skipped\n");
        return;
    }

    /* ---- :1036, :1081, :1146 with a real entry in the list ---- */
    {
        byte out[8192];
        long outSz;

        /* size query: buff NULL takes the ASN1 branch and the size-only arm */
        outSz = 0;
        WB_NOTE(BufferStoreCRL(cm->crl, NULL, &outSz, WOLFSSL_FILETYPE_ASN1));

        /* real DER store: :1081 both operands true */
        outSz = (long)sizeof(out);
        WB_NOTE(BufferStoreCRL(cm->crl, out, &outSz, WOLFSSL_FILETYPE_ASN1));

        /* undersized buffer: the BUFFER_E arm inside the ASN1 branch */
        outSz = 4;
        WB_NOTE(BufferStoreCRL(cm->crl, out, &outSz, WOLFSSL_FILETYPE_ASN1));

        /* PEM store: :1081 type operand false, :1146 both true */
        outSz = (long)sizeof(out);
        WB_NOTE(BufferStoreCRL(cm->crl, out, &outSz, WOLFSSL_FILETYPE_PEM));

        /* a type that is neither: :1146 type operand false too */
        outSz = (long)sizeof(out);
        WB_NOTE(BufferStoreCRL(cm->crl, out, &outSz, 0x7f));
    }
}

/* ---------------------------------------------------------- main */

int main(void)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        printf("crl white-box: wolfSSL_Init failed\n");
        goto done;
    }
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        printf("crl white-box: CertManagerNew failed\n");
        goto done;
    }
    if (wolfSSL_CertManagerEnableCRL(cm, WOLFSSL_CRL_CHECK)
            != WOLFSSL_SUCCESS) {
        printf("crl white-box: EnableCRL failed\n");
        goto done;
    }
    if (cm->crl == NULL) {
        printf("crl white-box: no CRL context after EnableCRL\n");
        goto done;
    }

    wb_check_cert_crl_ex(cm);
    wb_missing_crl_callbacks(cm);
    wb_buffer_load_store(cm);

    printf("crl white-box: %d vectors driven\n", g_checks);

done:
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else /* !HAVE_CRL */

int main(void)
{
    printf("crl white-box: skipped (HAVE_CRL not built)\n");
    return 0;
}

#endif
