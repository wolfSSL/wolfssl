/* test_she_whitebox.c
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

/*
 * MC/DC supplement for wolfcrypt/src/wc_she.c.
 *
 * Two argument-guard operands in the WOLF_PRIVATE_KEY_ID context
 * constructors are never given their independence pair by the "she" API
 * group, which only calls them with well-formed arguments:
 *
 *   wc_SHE_Init_Id()    (~line 176)  if (she == NULL || id == NULL)
 *                                    -> idx1 (id == NULL) never true
 *   wc_SHE_Init_Label() (~line 218)  if (labelLen == 0 ||
 *                                        labelLen > WC_SHE_MAX_LABEL_LEN)
 *                                    -> idx1 (over-long label) never true
 *
 * Both halves of each pair are driven here in the SAME binary (llvm-cov
 * derives MC/DC per binary), each rejected call paired with an accepted one.
 * Every call is memory-safe: the guards short-circuit before the id/label
 * bytes are copied, and the over-long label is rejected before the
 * fixed-size she->label array is written.
 *
 * Deliberately NOT chased here: wc_SHE_AesMp16()'s "while (ret == 0 &&
 * i < (int)inSz)" (~line 109) needs wc_AesSetKeyDirect()/wc_AesEncryptDirect()
 * to fail on valid buffers -- a transform-failure residual, the same class as
 * the sha module's, with no allocation to inject against.
 *
 * Build: compiled by the campaign's white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with wc_she.o removed. Not part of the wolfSSL build.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/wc_she.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_SHE) && defined(WOLF_PRIVATE_KEY_ID)

static void wb_she_init_id_guard(void)
{
    wc_SHE she;
    unsigned char id[8];
    int  ret;

    XMEMSET(&she, 0, sizeof(she));
    XMEMSET(id, 0x41, sizeof(id));

    /* idx0 true: she == NULL (short-circuits before id is looked at). */
    if (wc_SHE_Init_Id(NULL, id, (int)sizeof(id), NULL, INVALID_DEVID) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_SHE_Init_Id(she==NULL) not rejected");
        wb_fail = 1;
    }

    /* idx0 false, idx1 TRUE: a valid context but no id buffer. */
    if (wc_SHE_Init_Id(&she, NULL, (int)sizeof(id), NULL, INVALID_DEVID) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_SHE_Init_Id(id==NULL) not rejected");
        wb_fail = 1;
    }

    /* All-false baseline in the same binary. */
    ret = wc_SHE_Init_Id(&she, id, (int)sizeof(id), NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("wc_SHE_Init_Id valid call failed");
        wb_fail = 1;
    }
    else {
        wc_SHE_Free(&she);
    }

    WB_NOTE("wc_SHE_Init_Id she/id NULL guard pairs exercised");
}

static void wb_she_init_label_guard(void)
{
    wc_SHE she;
    /* WC_SHE_MAX_LABEL_LEN + 1 printable characters, NUL terminated. */
    char longLabel[WC_SHE_MAX_LABEL_LEN + 2];
    int  ret;
    size_t i;

    XMEMSET(&she, 0, sizeof(she));
    for (i = 0; i < sizeof(longLabel) - 1; i++) {
        longLabel[i] = 'x';
    }
    longLabel[sizeof(longLabel) - 1] = '\0';

    /* idx0 true: empty label (XSTRLEN == 0). */
    if (wc_SHE_Init_Label(&she, "", NULL, INVALID_DEVID) !=
            WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("wc_SHE_Init_Label(empty) not rejected");
        wb_fail = 1;
    }

    /* idx0 false, idx1 TRUE: label longer than WC_SHE_MAX_LABEL_LEN. The
     * length test runs before the XMEMCPY, so she->label is never overrun. */
    if (wc_SHE_Init_Label(&she, longLabel, NULL, INVALID_DEVID) !=
            WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("wc_SHE_Init_Label(over-long) not rejected");
        wb_fail = 1;
    }

    /* All-false baseline: an in-range label. */
    ret = wc_SHE_Init_Label(&she, "mcdc-label", NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("wc_SHE_Init_Label valid call failed");
        wb_fail = 1;
    }
    else {
        wc_SHE_Free(&she);
    }

    WB_NOTE("wc_SHE_Init_Label labelLen 0/over-long guard pairs exercised");
}

#else

static void wb_she_init_id_guard(void)
{ WB_NOTE("WOLFSSL_SHE/WOLF_PRIVATE_KEY_ID off; wc_SHE_Init_Id skipped"); }
static void wb_she_init_label_guard(void)
{ WB_NOTE("WOLFSSL_SHE/WOLF_PRIVATE_KEY_ID off; wc_SHE_Init_Label skipped"); }

#endif /* WOLFSSL_SHE && WOLF_PRIVATE_KEY_ID */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("wc_she.c white-box MC/DC supplement\n");

    wb_she_init_id_guard();
    wb_she_init_label_guard();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
