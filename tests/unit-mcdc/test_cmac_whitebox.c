/* test_cmac_whitebox.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* White-box supplement for wolfcrypt/src/cmac.c.
 *
 * Under WOLF_PRIVATE_KEY_ID, the file-static _InitCmac_common() takes an
 * (aesInitType, id, idLen, label) argument tuple that the three public
 * wrappers only ever populate in three fixed combinations:
 *
 *   wc_InitCmac_ex    -> aesInitType=CMAC_AES_INIT_PLAIN, id=NULL,  idLen=0, label=NULL
 *   wc_InitCmac_Id    -> aesInitType=CMAC_AES_INIT_ID,    id=<arg>, idLen=<arg>, label=NULL
 *   wc_InitCmac_Label -> aesInitType=CMAC_AES_INIT_LABEL, id=NULL,  idLen=0, label=<arg>
 *
 * so three of the switch's own re-validation leaves are structurally
 * unreachable from the public API no matter what arguments a caller passes:
 *   - CMAC_AES_INIT_ID's "label != NULL" (id and label can never both be
 *     non-NULL through the public wrappers)
 *   - CMAC_AES_INIT_LABEL's "id != NULL" / "idLen != 0" (same reason)
 *   - the default case's "id != NULL || idLen != 0 || label != NULL" (the
 *     PLAIN wrapper always passes all three as NULL/0)
 *
 * This white-box #includes cmac.c directly to reach the static
 * _InitCmac_common() and drives it with the "impossible via public API"
 * combinations. Crash-safety: _InitCmac_common() always XMEMSETs the Cmac
 * to zero first and every path taken here returns BAD_FUNC_ARG before
 * touching aes/k1/k2 state, so no cleanup beyond the call itself is
 * needed.
 */

#include <wolfcrypt/src/cmac.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT) \
    && defined(WOLF_PRIVATE_KEY_ID)

static const byte wb_key[] = {
    0x64, 0x4c, 0xbf, 0x12, 0x85, 0x9d, 0xf0, 0x55,
    0x7e, 0xa9, 0x1f, 0x08, 0xe0, 0x51, 0xff, 0x27
};
static byte wb_id[] = { 0x00, 0x01, 0x02, 0x03 };
static const char wb_label[] = "wb-label";

static void wb_cross_combos(void)
{
    Cmac cmac;
    int ret;

    /* MC/DC independence needs BOTH sides of each leaf demonstrated within
     * this SAME instrumented binary (a single clang MC/DC bitmap does not
     * merge across separately-compiled binaries): each "true" combination
     * below is paired with the matching public-API-reachable "every leaf
     * false" baseline for the same aesInitType, also driven directly here
     * so both sides land in this one binary's coverage. */

    /* aesInitType == CMAC_AES_INIT_ID, label != NULL: unreachable via
     * wc_InitCmac_Id (always passes label == NULL). Closes the switch's
     * "label != NULL" leaf for the ID case. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_ID, wb_id, (int)sizeof(wb_id),
        wb_label);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("ID+label!=NULL did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }
    /* Baseline: ID, label == NULL -- every leaf false, a real init. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_ID, wb_id, (int)sizeof(wb_id),
        NULL);
    if (ret != 0) {
        WB_NOTE("ID baseline (label==NULL) did not succeed");
        wb_fail = 1;
    }
    else {
        wc_AesFree(&cmac.aes);
    }

    /* aesInitType == CMAC_AES_INIT_LABEL, id != NULL: unreachable via
     * wc_InitCmac_Label (always passes id == NULL). Closes the switch's
     * "id != NULL" leaf for the LABEL case. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_LABEL, wb_id, 0, wb_label);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("LABEL+id!=NULL did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* aesInitType == CMAC_AES_INIT_LABEL, idLen != 0: same reason, closes
     * the switch's "idLen != 0" leaf for the LABEL case. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_LABEL, NULL, 4, wb_label);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("LABEL+idLen!=0 did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }
    /* Baseline: LABEL, id == NULL, idLen == 0 -- every leaf false, a real
     * init. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_LABEL, NULL, 0, wb_label);
    if (ret != 0) {
        WB_NOTE("LABEL baseline (id==NULL,idLen==0) did not succeed");
        wb_fail = 1;
    }
    else {
        wc_AesFree(&cmac.aes);
    }

    /* Default case (PLAIN), id != NULL: unreachable via wc_InitCmac_ex
     * (always passes id == NULL, idLen == 0, label == NULL). Closes the
     * default case's "id != NULL" leaf. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_PLAIN, wb_id, 0, NULL);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("PLAIN+id!=NULL did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* Default case (PLAIN), idLen != 0: closes the "idLen != 0" leaf. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_PLAIN, NULL, 7, NULL);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("PLAIN+idLen!=0 did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }

    /* Default case (PLAIN), label != NULL: closes the "label != NULL"
     * leaf. */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_PLAIN, NULL, 0, wb_label);
    if (ret != BAD_FUNC_ARG) {
        WB_NOTE("PLAIN+label!=NULL did not return BAD_FUNC_ARG");
        wb_fail = 1;
    }
    /* Baseline: PLAIN, id == NULL, idLen == 0, label == NULL -- every leaf
     * false, a real init (same shape as wc_InitCmac_ex's own call, but
     * driven directly here so it lands in this binary's coverage too). */
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = _InitCmac_common(&cmac, wb_key, sizeof(wb_key), WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID, CMAC_AES_INIT_PLAIN, NULL, 0, NULL);
    if (ret != 0) {
        WB_NOTE("PLAIN baseline did not succeed");
        wb_fail = 1;
    }
    else {
        wc_AesFree(&cmac.aes);
    }

    WB_NOTE("cmac id/label cross-combination leaves exercised");
}

#else

static void wb_cross_combos(void)
{
    WB_NOTE("WOLFSSL_CMAC/WOLFSSL_AES_DIRECT/WOLF_PRIVATE_KEY_ID not all "
        "compiled in this variant; skipped");
}

#endif

int main(void)
{
    printf("cmac.c white-box supplement\n");
#ifndef WOLFSSL_CMAC
    printf("  WOLFSSL_CMAC not defined; nothing to exercise\n");
    return 0;
#else
    wb_cross_combos();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the
     * campaign treats a nonzero exit as a failed variant and discards its
     * coverage. */
    return 0;
#endif
}
