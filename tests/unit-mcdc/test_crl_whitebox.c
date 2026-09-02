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
