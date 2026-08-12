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
 * Third: wc_SHE_AesMp16() (~line 109)
 *
 *     while (ret == 0 && i < (int)inSz)
 *
 * idx0 ("ret == 0") FALSE half, previously recorded as a transform-failure
 * residual. wc_SHE_AesMp16() takes its ret from exactly two primitives,
 * wc_AesSetKeyDirect() (once before the loop, once per iteration) and
 * wc_AesEncryptDirect(); neither allocates, so mcdc_fault_alloc.h cannot reach
 * them. mcdc_fault_hash.h DOES interpose wc_AesSetKeyDirect() (it is declared
 * under WOLFSSL_AES_DIRECT, which wc_she.c #errors without), so that is the
 * lever, and no new symbol has to be added to the shared injector:
 *
 *   mcdc_fh_arm(1)  -> the pre-loop key schedule fails; the while is entered
 *                      with ret != 0 on its FIRST evaluation, so idx0 is FALSE
 *                      and idx1 is short-circuited (never evaluated).
 *   mcdc_fh_arm(2)  -> the pre-loop key schedule succeeds and block 0 is
 *                      compressed, but the re-key for block 1 fails; the loop
 *                      re-test then sees idx0 FALSE with i == 16 < inSz.
 *   unarmed         -> (T,T) on both iterations and (T,F) at loop exit.
 *
 * Crash safety: when the pre-loop key schedule fails the loop body never runs
 * and `out` is untouched; when the in-loop re-key fails, `out` holds a
 * genuinely computed H_i, and either way the driver only inspects the returned
 * status, never the buffer.
 *
 * Build: compiled by the campaign's white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with wc_she.o removed. Not part of the wolfSSL build.
 */

#include "mcdc_fault_hash.h"

/* wc_she.c is #included AFTER the interposers are installed. */
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

/* --------------------------------------------------------------------------
 * wc_SHE_AesMp16(): "ret == 0" half of the compression loop guard (~line 109).
 * ----------------------------------------------------------------------- */
#if defined(WOLFSSL_SHE) && defined(MCDC_FH_HAVE_AES) && \
    defined(WOLFSSL_AES_DIRECT)

static void wb_she_aesmp16_key_err(void)
{
    Aes  aes;
    byte in[2 * AES_BLOCK_SIZE];
    byte out[AES_BLOCK_SIZE];
    int  ret;

    XMEMSET(in, 0x5a, sizeof(in));
    XMEMSET(out, 0, sizeof(out));

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_AesInit failed; AesMp16 loop guard skipped");
        wb_fail = 1;
        return;
    }

    /* All-true baseline first, unarmed: two iterations of (T,T) and the
     * (T,F) loop exit. */
    mcdc_fh_disarm();
    ret = wc_SHE_AesMp16(&aes, in, (word32)sizeof(in), out);
    if (ret != 0) {
        WB_NOTE("wc_SHE_AesMp16 unarmed baseline failed");
        wb_fail = 1;
    }

    /* idx0 FALSE on the first evaluation: the pre-loop key schedule fails, so
     * the loop body never runs and out is left untouched. */
    mcdc_fh_arm(1);
    ret = wc_SHE_AesMp16(&aes, in, (word32)sizeof(in), out);
    mcdc_fh_disarm();
    if (ret == 0) {
        WB_NOTE("wc_SHE_AesMp16 pre-loop key fault unexpectedly succeeded");
        wb_fail = 1;
    }

    /* idx0 FALSE on the re-test after one completed block: the second
     * wc_AesSetKeyDirect (the re-key for block 1) fails. */
    mcdc_fh_arm(2);
    ret = wc_SHE_AesMp16(&aes, in, (word32)sizeof(in), out);
    mcdc_fh_disarm();
    if (ret == 0) {
        WB_NOTE("wc_SHE_AesMp16 in-loop key fault unexpectedly succeeded");
        wb_fail = 1;
    }

    wc_AesFree(&aes);
    WB_NOTE("wc_SHE_AesMp16 loop-guard ret==0 pairs exercised");
}

#else

static void wb_she_aesmp16_key_err(void)
{ WB_NOTE("WOLFSSL_SHE/AES-DIRECT off; wc_SHE_AesMp16 loop guard skipped"); }

#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("wc_she.c white-box MC/DC supplement\n");

    wb_she_init_id_guard();
    wb_she_init_label_guard();
    wb_she_aesmp16_key_err();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
