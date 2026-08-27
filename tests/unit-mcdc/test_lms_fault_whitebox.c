/* test_lms_fault_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/wc_lms.c's public wc_LmsKey_*
 * API. tests/unit-mcdc/test_wc_lms_impl_whitebox.c and
 * test_wc_lms_impl_whitebox_gap.c already concentrate on wc_lms_impl.c's
 * file-static WOTS/Merkle/HSS helpers; this file targets wc_lms.c's own
 * NULL/argument guards and state-machine checks, most of which are never
 * exercised by a valid-key roundtrip because that path always takes every
 * guard's FALSE side.
 *
 * This #includes wc_lms.c directly (HARD RULE 1) so its file-static
 * wc_lmskey_state_init/free and the wc_lms_map[] table are reachable, and so
 * this TU can reach directly into LmsKey/LmsParams fields to force states a
 * valid caller could never observe (e.g. state==WC_LMS_STATE_OK before a
 * write callback is set) without paying for a real keygen every time.
 *
 * Keygen cost: every real wc_LmsKey_MakeKey/Reload below uses the smallest
 * mapped parameter set, levels=1 height=5 width=8 (WC_LMS_PARM_L1_H5_W8, 32
 * leaves) -- the same set test_wc_lms_impl_whitebox.c uses for its per-family
 * roundtrip. WOLFSSL_LMS_MAX_LEVELS is pinned to 2 by this module's campaign
 * config, so no larger key is attempted here.
 *
 * VERIFY_ONLY: wc_LmsKey_SetLmsParm/SetParameters(_ex)/GetParameters(_ex),
 * GetPubLen/GetSigLen, ExportPub(_ex)/ExportPubRaw/ImportPubRaw and Verify
 * stay compiled and are exercised unconditionally -- none of their targeted
 * decisions need real key material, so a hand-forced state (direct field
 * write) stands in for it, working identically whether or not signing is
 * compiled in. wc_LmsKey_SetWriteCb/SetReadCb/SetContext/MakeKey/Reload and
 * wc_LmsKey_GetKid/GetKidFromPrivRaw are compiled out under
 * WOLFSSL_LMS_VERIFY_ONLY (they live inside the same source guards), so that
 * whole group is behind one #ifndef with a skip stub.
 *
 * No allocation-fault sweep here: every uncovered decision in
 * campaign/reports/lms/GAPS.md for wc_lms.c is a NULL/argument guard or a
 * state-machine check, not a post-XMALLOC error chain, so mcdc_fault_alloc.h
 * is not needed by this file.
 */

#include <wolfcrypt/src/wc_lms.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_LMS)

/* ------------------------------------------------------------------------
 * Shared private-key persistence for the MakeKey/Reload group (Group V).
 * Mirrors test_wc_lms_impl_whitebox.c's in-memory callbacks. */
static byte   wb_priv[HSS_MAX_PRIVATE_KEY_LEN];
static word32 wb_privSz = 0;

static int wb_write_key(const byte* priv, word32 privSz, void* context)
{
    (void)context;
    if (privSz > (word32)sizeof(wb_priv))
        return -1;
    XMEMCPY(wb_priv, priv, privSz);
    wb_privSz = privSz;
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int wb_read_key(byte* priv, word32 privSz, void* context)
{
    (void)context;
    if (privSz != wb_privSz)
        return -1;
    XMEMCPY(priv, wb_priv, privSz);
    return WC_LMS_RC_READ_TO_MEMORY;
}

/* Returns a private key whose Q counter already equals the total leaf count
 * for the levels=1 height=5 set (32), i.e. wc_hss_sigsleft() reads it as
 * exhausted. Only Q needs to be well-formed: wc_LmsKey_Reload() checks
 * SigsLeft() and bails out with BAD_STATE_E/NOSIGS before ever touching the
 * rest of the buffer (wc_lms.c:1359, ahead of the wc_hss_reload_key() call),
 * so the remaining bytes are left zeroed. */
static int wb_read_exhausted(byte* priv, word32 privSz, void* context)
{
    w64wrapper q;
    (void)context;
    if (privSz < HSS_Q_LEN)
        return -1;
    XMEMSET(priv, 0, privSz);
    q = w64From32(0, (word32)1U << 5); /* height 5 -> 32 leaves, all used */
    c64toa(&q, priv);
    return WC_LMS_RC_READ_TO_MEMORY;
}

/*******************************************************************
 * wc_LmsKey_InitId (665, 668, 674) / wc_LmsKey_InitLabel (698, 703).
 * Only compiled when WOLF_PRIVATE_KEY_ID is set; this campaign's base
 * enables HAVE_PK_CALLBACKS, which settings.h auto-derives it from.
 *
 * 665: if ((key == NULL) || ((id == NULL) && (len != 0)))
 *   T1 key==NULL                       -> A=T                    : true
 *   T2 key,id valid, len=0             -> A=F,B=F                : false (base)
 *   T3 key valid, id=NULL, len=4       -> A=F,B=T,C=T            : true
 *   T4 key valid, id=NULL, len=0       -> A=F,B=T,C=F            : false (C pair)
 *   T5 key,id valid, len=4             -> A=F,B=F,C=T            : false (B pair)
 *
 * 668: if ((ret==0) && ((len<0)||(len>LMS_MAX_ID_LEN)))
 *   A=F row reused from T1 (ret already BAD_FUNC_ARG there).
 *   len=-1   -> A=T,B=T : true
 *   len=0    -> A=T,B=F,C=F : false (reused from T2, baseline)
 *   len=MAX+1-> A=T,C=T : true
 *
 * 674: if ((ret==0) && (id != NULL) && (len != 0))
 *   All-true row reused from T5 (id valid, len=4, ret==0).
 *   A=F reused from T1. C=F (len==0) reused from T2.
 *   B=F (id==NULL, len!=0, ret==0) is UNREACHABLE: 665 already forces
 *   ret=BAD_FUNC_ARG whenever id==NULL && len!=0, so "ret==0 && id==NULL"
 *   can never coexist with len!=0. No test call issued for this row --
 *   DEATHNOTE candidate, see task report.
 ******************************************************************/
#ifdef WOLF_PRIVATE_KEY_ID
static void wb_initid(void)
{
    LmsKey key;
    byte id[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    int ret;

    /* T1 */
    ret = wc_LmsKey_InitId(NULL, id, 4, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("InitId key==NULL did not fail");
        wb_fail = 1;
    }

    /* T2 (baseline: id valid, len=0) */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitId(&key, id, 0, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("InitId(id!=NULL,len=0) baseline failed");
        wb_fail = 1;
    }

    /* T3 (id==NULL, len=4) */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitId(&key, NULL, 4, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("InitId(id==NULL,len!=0) did not fail");
        wb_fail = 1;
    }

    /* T4 (id==NULL, len=0) */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitId(&key, NULL, 0, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("InitId(id==NULL,len=0) unexpectedly failed");
        wb_fail = 1;
    }

    /* T5 (id!=NULL, len=4) -- also the 674 baseline all-true row */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitId(&key, id, 4, NULL, INVALID_DEVID);
    if (ret != 0 || key.idLen != 4) {
        WB_NOTE("InitId(id!=NULL,len!=0) baseline failed");
        wb_fail = 1;
    }

    /* 668: len<0 */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitId(&key, id, -1, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitId(len<0) did not report BUFFER_E");
        wb_fail = 1;
    }

    /* 668: len>LMS_MAX_ID_LEN */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitId(&key, id, LMS_MAX_ID_LEN + 1, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitId(len>MAX) did not report BUFFER_E");
        wb_fail = 1;
    }

    WB_NOTE("665/668/674 InitId leaves closed (674 id!=NULL-false is "
        "unreachable, see report)");
}

/*******************************************************************
 * wc_LmsKey_InitLabel: 698 (key==NULL||label==NULL), 703 (labelLen==0||
 * labelLen>LMS_MAX_LABEL_LEN).
 ******************************************************************/
static void wb_initlabel(void)
{
    LmsKey key;
    char label[8] = "abcdefg";
    char longlabel[LMS_MAX_LABEL_LEN + 8];
    int ret;
    int i;

    /* 698: key==NULL */
    ret = wc_LmsKey_InitLabel(NULL, label, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("InitLabel key==NULL did not fail");
        wb_fail = 1;
    }

    /* 698: label==NULL */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitLabel(&key, NULL, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("InitLabel label==NULL did not fail");
        wb_fail = 1;
    }

    /* 698/703 baseline: both valid, labelLen in range */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitLabel(&key, label, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("InitLabel baseline failed");
        wb_fail = 1;
    }

    /* 703: labelLen==0 */
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitLabel(&key, "", NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitLabel(\"\") did not report BUFFER_E");
        wb_fail = 1;
    }

    /* 703: labelLen>LMS_MAX_LABEL_LEN */
    for (i = 0; i < LMS_MAX_LABEL_LEN + 1; i++) {
        longlabel[i] = 'x';
    }
    longlabel[LMS_MAX_LABEL_LEN + 1] = '\0';
    XMEMSET(&key, 0, sizeof(key));
    ret = wc_LmsKey_InitLabel(&key, longlabel, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("InitLabel(too-long) did not report BUFFER_E");
        wb_fail = 1;
    }

    WB_NOTE("698/703 InitLabel leaves closed");
}
#else /* !WOLF_PRIVATE_KEY_ID */
static void wb_initid(void)
{
    WB_NOTE("WOLF_PRIVATE_KEY_ID not defined; InitId/InitLabel skipped");
}
static void wb_initlabel(void) {}
#endif /* WOLF_PRIVATE_KEY_ID */

/*******************************************************************
 * wc_LmsKey_SetLmsParm (766), wc_LmsKey_SetParameters (819),
 * wc_LmsKey_SetParameters_ex (879, only the ret==0 operand is uncovered).
 * All three share: if ((ret==0) && (key->state != WC_LMS_STATE_INITED)).
 ******************************************************************/
static void wb_setlmsparm_setparams(void)
{
    LmsKey key;
    int ret;

    /* --- 766 SetLmsParm --- */
    ret = wc_LmsKey_SetLmsParm(NULL, WC_LMS_PARM_L1_H5_W8);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetLmsParm key==NULL did not fail");
        wb_fail = 1;
    }
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L1_H5_W8);
    if (ret != 0) {
        WB_NOTE("SetLmsParm(INITED) baseline failed");
        wb_fail = 1;
    }
    /* key.state is now PARMSET: calling again hits the wrong-state row. */
    ret = wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L1_H5_W8);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("SetLmsParm(PARMSET) did not report BAD_STATE_E");
        wb_fail = 1;
    }
    WB_NOTE("766 SetLmsParm state leaves closed");

    /* --- 819 SetParameters --- */
    ret = wc_LmsKey_SetParameters(NULL, 1, 5, 8);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetParameters key==NULL did not fail");
        wb_fail = 1;
    }
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_SetParameters(&key, 1, 5, 8);
    if (ret != 0) {
        WB_NOTE("SetParameters(INITED) baseline failed");
        wb_fail = 1;
    }
    ret = wc_LmsKey_SetParameters(&key, 1, 5, 8);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("SetParameters(PARMSET) did not report BAD_STATE_E");
        wb_fail = 1;
    }
    WB_NOTE("819 SetParameters state leaves closed");

    /* --- 879 SetParameters_ex: only the ret==0 operand is flagged in
     * GAPS.md, but its independence pair still needs the *wrong-state* row
     * held alongside it: for (ret==0) && (state!=INITED), the ret==0
     * operand's own pair requires the OTHER operand pinned TRUE (masking
     * MC/DC on an AND chain -- pinning it FALSE, i.e. the plain success
     * case, makes the decision's outcome false regardless of ret, which
     * masks ret's effect and closes nothing). So: key==NULL (ret!=0) is
     * paired against a wrong-state call (ret==0, state!=INITED==true), not
     * against the plain success call. --- */
    ret = wc_LmsKey_SetParameters_ex(NULL, 1, 5, 8, LMS_SHA256);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetParameters_ex key==NULL did not fail");
        wb_fail = 1;
    }
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_SetParameters_ex(&key, 1, 5, 8, LMS_SHA256);
    if (ret != 0) {
        WB_NOTE("SetParameters_ex(INITED) baseline failed");
        wb_fail = 1;
    }
    /* key.state is now PARMSET (not INITED): ret==0 && state!=INITED==true,
     * the masking-consistent partner for the key==NULL row above. */
    ret = wc_LmsKey_SetParameters_ex(&key, 1, 5, 8, LMS_SHA256);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("SetParameters_ex(PARMSET) did not report BAD_STATE_E");
        wb_fail = 1;
    }
    WB_NOTE("879 SetParameters_ex ret-operand leaf closed");
}

/*******************************************************************
 * wc_LmsKey_GetParameters (929-930, 935), wc_LmsKey_GetParameters_ex
 * (968-969, 974).
 ******************************************************************/
static void wb_getparameters(void)
{
    LmsKey key, key2;
    int levels, height, winternitz, hash;
    int ret;

    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key, 1, 5, 8);
    XMEMSET(&key2, 0, sizeof(key2));
    wc_LmsKey_Init(&key2, NULL, INVALID_DEVID); /* params left NULL */

    /* 929-930 row0: key==NULL */
    ret = wc_LmsKey_GetParameters(NULL, &levels, &height, &winternitz);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters key==NULL did not fail");
        wb_fail = 1;
    }
    /* baseline success: also the 935 (ret==0, params!=NULL) false row */
    ret = wc_LmsKey_GetParameters(&key, &levels, &height, &winternitz);
    if (ret != 0) {
        WB_NOTE("GetParameters baseline failed");
        wb_fail = 1;
    }
    /* 935: params==NULL, ret==0 up to that point */
    ret = wc_LmsKey_GetParameters(&key2, &levels, &height, &winternitz);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters(params==NULL) did not fail");
        wb_fail = 1;
    }
    WB_NOTE("929-930/935 GetParameters leaves closed");

    /* 968-969: 5-operand OR, baseline + one flip per operand. */
    ret = wc_LmsKey_GetParameters_ex(&key, &levels, &height, &winternitz,
        &hash);
    if (ret != 0) {
        WB_NOTE("GetParameters_ex baseline failed");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetParameters_ex(NULL, &levels, &height, &winternitz,
        &hash);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters_ex key==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetParameters_ex(&key, NULL, &height, &winternitz, &hash);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters_ex levels==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetParameters_ex(&key, &levels, NULL, &winternitz, &hash);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters_ex height==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetParameters_ex(&key, &levels, &height, NULL, &hash);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters_ex winternitz==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetParameters_ex(&key, &levels, &height, &winternitz,
        NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters_ex hash==NULL did not fail");
        wb_fail = 1;
    }
    /* 974: params==NULL, ret==0 up to that point */
    ret = wc_LmsKey_GetParameters_ex(&key2, &levels, &height, &winternitz,
        &hash);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetParameters_ex(params==NULL) did not fail");
        wb_fail = 1;
    }
    WB_NOTE("968-969/974 GetParameters_ex leaves closed");
}

/*******************************************************************
 * wc_LmsKey_GetPubLen (1592: 3-operand OR) and wc_LmsKey_GetSigLen
 * (1857: only the key==NULL row is uncovered).
 ******************************************************************/
static void wb_getpublen_getsiglen(void)
{
    LmsKey key, key2;
    word32 len;
    int ret;

    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key, 1, 5, 8);
    XMEMSET(&key2, 0, sizeof(key2));
    wc_LmsKey_Init(&key2, NULL, INVALID_DEVID); /* params left NULL */

    ret = wc_LmsKey_GetPubLen(&key, &len);
    if (ret != 0) {
        WB_NOTE("GetPubLen baseline failed");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetPubLen(NULL, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPubLen key==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetPubLen(&key, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPubLen len==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetPubLen(&key2, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPubLen(params==NULL) did not fail");
        wb_fail = 1;
    }
    WB_NOTE("1592 GetPubLen leaves closed");

    ret = wc_LmsKey_GetSigLen(&key, &len);
    if (ret != 0) {
        WB_NOTE("GetSigLen baseline failed");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetSigLen(NULL, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetSigLen key==NULL did not fail");
        wb_fail = 1;
    }
    WB_NOTE("1857 GetSigLen key==NULL leaf closed");
}

/*******************************************************************
 * wc_LmsKey_ExportPub_ex: 1623 (keyDst==NULL||keySrc==NULL), 1626-1628
 * (4-operand AND chain guarding the state check). No real key material is
 * needed: the function only reads keySrc->state/params and keyDst is
 * re-inited internally, so a directly-forced state stands in for a real
 * MakeKey for every row this line needs.
 ******************************************************************/
static void wb_exportpub_ex(void)
{
    LmsKey dst, src;
    int ret;

    XMEMSET(&src, 0, sizeof(src));
    wc_LmsKey_Init(&src, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&src, 1, 5, 8); /* state PARMSET */

    ret = wc_LmsKey_ExportPub_ex(NULL, &src, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPub_ex keyDst==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_ExportPub_ex(&dst, NULL, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPub_ex keySrc==NULL did not fail");
        wb_fail = 1;
    }

    /* baseline all-true: PARMSET is none of OK/VERIFYONLY/NOSIGS. */
    ret = wc_LmsKey_ExportPub_ex(&dst, &src, NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("ExportPub_ex(PARMSET) did not report BAD_STATE_E");
        wb_fail = 1;
    }

    src.state = WC_LMS_STATE_OK;
    ret = wc_LmsKey_ExportPub_ex(&dst, &src, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("ExportPub_ex(OK) unexpectedly failed");
        wb_fail = 1;
    }

    src.state = WC_LMS_STATE_VERIFYONLY;
    ret = wc_LmsKey_ExportPub_ex(&dst, &src, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("ExportPub_ex(VERIFYONLY) unexpectedly failed");
        wb_fail = 1;
    }

    src.state = WC_LMS_STATE_NOSIGS;
    ret = wc_LmsKey_ExportPub_ex(&dst, &src, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("ExportPub_ex(NOSIGS) unexpectedly failed");
        wb_fail = 1;
    }

    wc_LmsKey_Free(&dst);
    wc_LmsKey_Free(&src);
    WB_NOTE("1623/1626-1628 ExportPub_ex leaves closed");
}

/*******************************************************************
 * wc_LmsKey_ExportPubRaw: 1693-1694 (4-operand OR), 1698-1699 (buffer size).
 ******************************************************************/
static void wb_exportpubraw(void)
{
    LmsKey key, key2;
    byte pub[HSS_PUBLIC_KEY_LEN(WC_SHA256_DIGEST_SIZE)];
    word32 outLen;
    int ret;

    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key, 1, 5, 8);
    XMEMSET(&key2, 0, sizeof(key2));
    wc_LmsKey_Init(&key2, NULL, INVALID_DEVID); /* params left NULL */

    outLen = (word32)sizeof(pub);
    ret = wc_LmsKey_ExportPubRaw(&key, pub, &outLen);
    if (ret != 0) {
        WB_NOTE("ExportPubRaw baseline failed");
        wb_fail = 1;
    }

    ret = wc_LmsKey_ExportPubRaw(NULL, pub, &outLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPubRaw key==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_ExportPubRaw(&key, NULL, &outLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPubRaw out==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_ExportPubRaw(&key, pub, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPubRaw outLen==NULL did not fail");
        wb_fail = 1;
    }
    outLen = (word32)sizeof(pub);
    ret = wc_LmsKey_ExportPubRaw(&key2, pub, &outLen);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ExportPubRaw(params==NULL) did not fail");
        wb_fail = 1;
    }

    /* buffer too small */
    outLen = 1;
    ret = wc_LmsKey_ExportPubRaw(&key, pub, &outLen);
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("ExportPubRaw(small buffer) did not report BUFFER_E");
        wb_fail = 1;
    }

    WB_NOTE("1693-1699 ExportPubRaw leaves closed");
}

/*******************************************************************
 * wc_LmsKey_ImportPubRaw: 1749 (key==NULL||in==NULL), 1759-1762 (4-operand
 * AND-of-negatives state guard), 1767 (inLen too short), 1812-1814 (rows 0
 * and 2 only -- levels and lmOtsType mismatch against pre-set params; row 1,
 * lmsType mismatch, is already covered elsewhere but included here too for a
 * self-contained group).
 ******************************************************************/
static void wb_importpubraw(void)
{
    LmsKey key, key2, key3, keyM;
    byte buf[HSS_PUBLIC_KEY_LEN(WC_SHA256_DIGEST_SIZE)];
    byte badbuf[LMS_L_LEN + 2 * LMS_TYPE_LEN];
    int ret;

    /* 1749 */
    ret = wc_LmsKey_ImportPubRaw(NULL, buf, (word32)sizeof(buf));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ImportPubRaw key==NULL did not fail");
        wb_fail = 1;
    }
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_ImportPubRaw(&key, NULL, (word32)sizeof(buf));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ImportPubRaw in==NULL did not fail");
        wb_fail = 1;
    }

    /* 1759-1762 baseline all-true: state forced to OK (unreachable via a
     * real caller without signing, but safe: only the enum is read here). */
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    key.state = WC_LMS_STATE_OK;
    XMEMSET(buf, 0, sizeof(buf));
    ret = wc_LmsKey_ImportPubRaw(&key, buf, (word32)sizeof(buf));
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("ImportPubRaw(state==OK) did not report BAD_STATE_E");
        wb_fail = 1;
    }

    /* A valid L1_H5_W8 pub header (levels/lmsType/lmOtsType) for the
     * INITED-state (auto-derive) run below. */
    XMEMSET(buf, 0, sizeof(buf));
    c32toa(1, buf);
    c32toa((word32)(LMS_SHA256_M32_H5 & LMS_H_W_MASK), buf + LMS_L_LEN);
    c32toa((word32)(LMOTS_SHA256_N32_W8 & LMS_H_W_MASK),
        buf + LMS_L_LEN + LMS_TYPE_LEN);

    /* flip state!=INITED to false */
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_ImportPubRaw(&key, buf, (word32)sizeof(buf));
    if (ret != 0) {
        WB_NOTE("ImportPubRaw(state==INITED) baseline failed");
        wb_fail = 1;
    }

    /* flip state!=PARMSET to false (params pre-set and matching buf). */
    XMEMSET(&key2, 0, sizeof(key2));
    wc_LmsKey_Init(&key2, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key2, 1, 5, 8);
    ret = wc_LmsKey_ImportPubRaw(&key2, buf, (word32)sizeof(buf));
    if (ret != 0) {
        WB_NOTE("ImportPubRaw(state==PARMSET) failed");
        wb_fail = 1;
    }
    /* Import above promoted key2 to VERIFYONLY: reuse it to flip
     * state!=VERIFYONLY to false too. */
    ret = wc_LmsKey_ImportPubRaw(&key2, buf, (word32)sizeof(buf));
    if (ret != 0) {
        WB_NOTE("ImportPubRaw(state==VERIFYONLY) failed");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&key2);
    WB_NOTE("1759-1762 ImportPubRaw state leaves closed");

    /* 1767: inLen too short, using a fresh INITED key (state check false). */
    XMEMSET(&key3, 0, sizeof(key3));
    wc_LmsKey_Init(&key3, NULL, INVALID_DEVID);
    ret = wc_LmsKey_ImportPubRaw(&key3, buf,
        (word32)(LMS_L_LEN + 2 * LMS_TYPE_LEN - 1));
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("ImportPubRaw(inLen too short) did not report BUFFER_E");
        wb_fail = 1;
    }
    WB_NOTE("1767 ImportPubRaw inLen leaf closed");

    /* 1812-1814: pre-set-params mismatch, one field wrong at a time. */
    XMEMSET(&keyM, 0, sizeof(keyM));
    wc_LmsKey_Init(&keyM, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&keyM, 1, 5, 8); /* state PARMSET, real params */

    /* row0: levels mismatch only */
    c32toa(2, badbuf);
    c32toa((word32)(LMS_SHA256_M32_H5 & LMS_H_W_MASK), badbuf + LMS_L_LEN);
    c32toa((word32)(LMOTS_SHA256_N32_W8 & LMS_H_W_MASK),
        badbuf + LMS_L_LEN + LMS_TYPE_LEN);
    ret = wc_LmsKey_ImportPubRaw(&keyM, badbuf, (word32)sizeof(badbuf));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ImportPubRaw levels-mismatch did not fail");
        wb_fail = 1;
    }

    /* row1 (already covered elsewhere; added for a self-contained group):
     * lmsType mismatch only */
    c32toa(1, badbuf);
    c32toa((word32)((LMS_SHA256_M32_H5 & LMS_H_W_MASK) + 1U),
        badbuf + LMS_L_LEN);
    c32toa((word32)(LMOTS_SHA256_N32_W8 & LMS_H_W_MASK),
        badbuf + LMS_L_LEN + LMS_TYPE_LEN);
    ret = wc_LmsKey_ImportPubRaw(&keyM, badbuf, (word32)sizeof(badbuf));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ImportPubRaw lmsType-mismatch did not fail");
        wb_fail = 1;
    }

    /* row2: lmOtsType mismatch only */
    c32toa(1, badbuf);
    c32toa((word32)(LMS_SHA256_M32_H5 & LMS_H_W_MASK), badbuf + LMS_L_LEN);
    c32toa((word32)((LMOTS_SHA256_N32_W8 & LMS_H_W_MASK) + 1U),
        badbuf + LMS_L_LEN + LMS_TYPE_LEN);
    ret = wc_LmsKey_ImportPubRaw(&keyM, badbuf, (word32)sizeof(badbuf));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("ImportPubRaw lmOtsType-mismatch did not fail");
        wb_fail = 1;
    }

    wc_LmsKey_Free(&keyM);
    WB_NOTE("1812-1814 ImportPubRaw mismatch leaves closed");
}

/*******************************************************************
 * wc_LmsKey_Verify: 1888-1889 (only the key->params==NULL row is
 * uncovered), 1896-1897 (3-operand AND: ret==0 && state!=OK &&
 * state!=VERIFYONLY -- all 3 rows), 1904 (sigSz != sig_len). No real
 * signing is needed: OK/VERIFYONLY/PARMSET states are forced directly, and
 * the sigSz check runs before any hashing; a "correct length" row proceeds
 * into wc_hss_verify() on an all-zero signature, which safely reports
 * SIG_VERIFY_E (no crash) -- that is all those decisions' FALSE sides need
 * to demonstrate.
 *
 * 1896-1897 independence: baseline all-true is state==PARMSET (neither OK
 * nor VERIFYONLY); state==OK flips the middle operand false (masks the
 * third, still-unevaluated by short-circuit); state==VERIFYONLY flips the
 * third operand false while holding the middle true. key->params==NULL
 * (row 1888/1889) gives the ret==0-false row.
 ******************************************************************/
static void wb_verify_checks(void)
{
    LmsKey key, key2, key3;
    byte sig[2048];
    byte msg[4] = { 1, 2, 3, 4 };
    word32 wrongSigSz;
    int ret;

    /* 1888-1889: key->params==NULL, all other operands false */
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    XMEMSET(sig, 0, sizeof(sig));
    ret = wc_LmsKey_Verify(&key, sig, (word32)sizeof(sig), msg,
        (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Verify(params==NULL) did not fail");
        wb_fail = 1;
    }

    /* 1896-1897 baseline all-true: state PARMSET is neither OK nor
     * VERIFYONLY. */
    XMEMSET(&key3, 0, sizeof(key3));
    wc_LmsKey_Init(&key3, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key3, 1, 5, 8);
    ret = wc_LmsKey_Verify(&key3, sig, key3.params->sig_len, msg,
        (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("Verify(state==PARMSET) did not report BAD_STATE_E");
        wb_fail = 1;
    }

    /* 1896-1897: state==OK flips the "state!=OK" operand false. */
    key3.state = WC_LMS_STATE_OK;
    ret = wc_LmsKey_Verify(&key3, sig, key3.params->sig_len, msg,
        (int)sizeof(msg));
    if (ret == 0) {
        WB_NOTE("Verify(state==OK,zero sig) unexpectedly succeeded");
        wb_fail = 1;
    }

    /* 1904: sigSz mismatch, key forced to VERIFYONLY with real params --
     * also flips 1896-1897's "state!=VERIFYONLY" operand false. */
    XMEMSET(&key2, 0, sizeof(key2));
    wc_LmsKey_Init(&key2, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key2, 1, 5, 8);
    key2.state = WC_LMS_STATE_VERIFYONLY;

    wrongSigSz = key2.params->sig_len + 1U;
    ret = wc_LmsKey_Verify(&key2, sig, wrongSigSz, msg, (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BUFFER_E)) {
        WB_NOTE("Verify(wrong sigSz) did not report BUFFER_E");
        wb_fail = 1;
    }

    ret = wc_LmsKey_Verify(&key2, sig, key2.params->sig_len, msg,
        (int)sizeof(msg));
    if (ret == 0) {
        WB_NOTE("Verify unexpectedly accepted an all-zero signature");
        wb_fail = 1;
    }

    WB_NOTE("1888-1889/1896-1897/1904 Verify leaves closed");
}

/*******************************************************************
 * wc_LmsKey_GetKidFromPrivRaw: 2005-2006 (priv==NULL||privSz too short),
 * 2012-2013 (seedSz matches neither known digest size). Pure buffer/length
 * function, no LmsKey needed. Compiled under !WOLFSSL_LMS_VERIFY_ONLY only.
 ******************************************************************/
#ifndef WOLFSSL_LMS_VERIFY_ONLY
static void wb_getkid_from_privraw(void)
{
    byte priv[128];
    const byte* kid;

    XMEMSET(priv, 0x55, sizeof(priv));

    if (wc_LmsKey_GetKidFromPrivRaw(NULL, 64) != NULL) {
        WB_NOTE("GetKidFromPrivRaw(priv==NULL) did not return NULL");
        wb_fail = 1;
    }
    if (wc_LmsKey_GetKidFromPrivRaw(priv,
            HSS_Q_LEN + HSS_PRIV_KEY_PARAM_SET_LEN + LMS_I_LEN - 1) != NULL) {
        WB_NOTE("GetKidFromPrivRaw(privSz too short) did not return NULL");
        wb_fail = 1;
    }

    /* seedSz garbage (matches neither known digest size): all-true row. */
    kid = wc_LmsKey_GetKidFromPrivRaw(priv,
        HSS_Q_LEN + HSS_PRIV_KEY_PARAM_SET_LEN + 16U + LMS_I_LEN);
    if (kid != NULL) {
        WB_NOTE("GetKidFromPrivRaw(bad seedSz) unexpectedly succeeded");
        wb_fail = 1;
    }

    /* seedSz == WC_SHA256_192_DIGEST_SIZE: first inequality false. */
    kid = wc_LmsKey_GetKidFromPrivRaw(priv,
        HSS_Q_LEN + HSS_PRIV_KEY_PARAM_SET_LEN +
        WC_SHA256_192_DIGEST_SIZE + LMS_I_LEN);
    if (kid == NULL) {
        WB_NOTE("GetKidFromPrivRaw(seedSz=192) unexpectedly failed");
        wb_fail = 1;
    }

    /* seedSz == WC_SHA256_DIGEST_SIZE: second inequality false. */
    kid = wc_LmsKey_GetKidFromPrivRaw(priv,
        HSS_Q_LEN + HSS_PRIV_KEY_PARAM_SET_LEN +
        WC_SHA256_DIGEST_SIZE + LMS_I_LEN);
    if (kid == NULL) {
        WB_NOTE("GetKidFromPrivRaw(seedSz=256) unexpectedly failed");
        wb_fail = 1;
    }

    WB_NOTE("2005-2006/2012-2013 GetKidFromPrivRaw leaves closed");
}

/*******************************************************************
 * wc_LmsKey_GetKid: only the key->params==NULL row (1965) is uncovered, but
 * its independence pair still needs the all-valid baseline row alongside it
 * (masking MC/DC on an OR chain: the operand's pair is baseline-all-false
 * vs only-that-operand-true, not two different-failure rows). No real
 * keygen needed -- GetKid does not check state, only key/params/kid/kidSz,
 * and reads a zeroed priv_raw harmlessly.
 ******************************************************************/
static void wb_getkid(void)
{
    LmsKey key;
    const byte* kid;
    word32 kidSz;
    int ret;

    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key, 1, 5, 8); /* baseline: all operands false */
    ret = wc_LmsKey_GetKid(&key, &kid, &kidSz);
    if (ret != 0) {
        WB_NOTE("GetKid baseline failed");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&key);

    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID); /* params left NULL */
    ret = wc_LmsKey_GetKid(&key, &kid, &kidSz);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetKid(params==NULL) did not fail");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&key);
    WB_NOTE("1965 GetKid params==NULL leaf closed");
}

/*******************************************************************
 * wc_LmsKey_GetPrivLen (1406: 3-operand OR key==NULL||len==NULL||
 * key->params==NULL). Compiled under !WOLFSSL_LMS_VERIFY_ONLY only (it
 * reports the raw private-key length, meaningless on a verify-only key).
 ******************************************************************/
static void wb_getprivlen(void)
{
    LmsKey key, key2;
    word32 len;
    int ret;

    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key, 1, 5, 8);
    XMEMSET(&key2, 0, sizeof(key2));
    wc_LmsKey_Init(&key2, NULL, INVALID_DEVID); /* params left NULL */

    ret = wc_LmsKey_GetPrivLen(&key, &len);
    if (ret != 0) {
        WB_NOTE("GetPrivLen baseline failed");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetPrivLen(NULL, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPrivLen key==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetPrivLen(&key, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPrivLen len==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_GetPrivLen(&key2, &len);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("GetPrivLen(params==NULL) did not fail");
        wb_fail = 1;
    }

    wc_LmsKey_Free(&key);
    wc_LmsKey_Free(&key2);
    WB_NOTE("1406 GetPrivLen leaves closed");
}

/*******************************************************************
 * wc_LmsKey_SetWriteCb (1059), SetReadCb (1092), SetContext (1126): all
 * share if ((ret==0) && (key->state == WC_LMS_STATE_OK)). No real key
 * material needed -- state is forced directly to WC_LMS_STATE_OK, which a
 * real caller could only reach after a full MakeKey/Reload, to reach the
 * "in use" rejection cheaply.
 ******************************************************************/
static void wb_cb_setters(void)
{
    LmsKey key;
    int ret;

    /* SetWriteCb */
    ret = wc_LmsKey_SetWriteCb(NULL, wb_write_key);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetWriteCb key==NULL did not fail");
        wb_fail = 1;
    }
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_SetWriteCb(&key, wb_write_key);
    if (ret != 0) {
        WB_NOTE("SetWriteCb baseline failed");
        wb_fail = 1;
    }
    key.state = WC_LMS_STATE_OK;
    ret = wc_LmsKey_SetWriteCb(&key, wb_write_key);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("SetWriteCb(state==OK) did not report BAD_STATE_E");
        wb_fail = 1;
    }

    /* SetReadCb */
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_SetReadCb(NULL, wb_read_key);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetReadCb key==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_SetReadCb(&key, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetReadCb read_cb==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_SetReadCb(&key, wb_read_key);
    if (ret != 0) {
        WB_NOTE("SetReadCb baseline failed");
        wb_fail = 1;
    }
    key.state = WC_LMS_STATE_OK;
    ret = wc_LmsKey_SetReadCb(&key, wb_read_key);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("SetReadCb(state==OK) did not report BAD_STATE_E");
        wb_fail = 1;
    }

    /* SetContext */
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_SetContext(NULL, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("SetContext key==NULL did not fail");
        wb_fail = 1;
    }
    ret = wc_LmsKey_SetContext(&key, NULL);
    if (ret != 0) {
        WB_NOTE("SetContext baseline (NULL context allowed) failed");
        wb_fail = 1;
    }
    key.state = WC_LMS_STATE_OK;
    ret = wc_LmsKey_SetContext(&key, NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("SetContext(state==OK) did not report BAD_STATE_E");
        wb_fail = 1;
    }

    WB_NOTE("1059/1092/1126 SetWriteCb/SetReadCb/SetContext leaves closed");
}

/*******************************************************************
 * wc_LmsKey_Sign: 1441-1442 (only the key->params==NULL row of the
 * 5-operand OR is uncovered), 1449 (ret==0 && state!=OK, both rows).
 * 1449's ret==0 operand needs its OWN masking pair too (AND chain: the
 * OTHER operand, state!=OK, must be held TRUE alongside it, i.e. paired
 * against a wrong-state call, not the plain success call -- see the 879
 * SetParameters_ex fix above for the same pitfall). A real MakeKey is
 * needed for the one baseline success call (state==OK is unreachable any
 * other way); the wrong-state and params==NULL rows need no keygen.
 ******************************************************************/
static void wb_sign_checks(WC_RNG* rng)
{
    LmsKey key, keyNoParams, keyWrongState;
    byte sig[2048];
    word32 sigSz;
    byte msg[4] = { 1, 2, 3, 4 };
    int ret;

    /* 1441-1442: key->params==NULL */
    XMEMSET(&keyNoParams, 0, sizeof(keyNoParams));
    wc_LmsKey_Init(&keyNoParams, NULL, INVALID_DEVID);
    XMEMSET(sig, 0, sizeof(sig));
    sigSz = (word32)sizeof(sig);
    ret = wc_LmsKey_Sign(&keyNoParams, sig, &sigSz, msg, (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Sign(params==NULL) did not fail");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&keyNoParams);

    /* 1449 (ret==0 true, state!=OK true): params set, state PARMSET (not
     * OK). Also state's own true-side. */
    XMEMSET(&keyWrongState, 0, sizeof(keyWrongState));
    wc_LmsKey_Init(&keyWrongState, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&keyWrongState, 1, 5, 8);
    sigSz = (word32)sizeof(sig);
    ret = wc_LmsKey_Sign(&keyWrongState, sig, &sigSz, msg, (int)sizeof(msg));
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("Sign(state!=OK) did not report BAD_STATE_E");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&keyWrongState);

    /* 1449 baseline (ret==0 true, state!=OK false): real Sign after a real
     * MakeKey -- the only way to reach state==OK. */
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key, 1, 5, 8);
    wc_LmsKey_SetWriteCb(&key, wb_write_key);
    ret = wc_LmsKey_MakeKey(&key, rng);
    if (ret != 0) {
        WB_NOTE("Sign group: MakeKey setup failed");
        wb_fail = 1;
    }
    else {
        sigSz = (word32)sizeof(sig);
        ret = wc_LmsKey_Sign(&key, sig, &sigSz, msg, (int)sizeof(msg));
        if (ret != 0) {
            WB_NOTE("Sign baseline failed");
            wb_fail = 1;
        }
    }
    wc_LmsKey_Free(&key);

    WB_NOTE("1441-1442/1449 Sign leaves closed");
}

/*******************************************************************
 * wc_LmsKey_MakeKey: 1163 (state!=PARMSET), 1195 (write_private_key==NULL),
 * 1208 (priv_data==NULL, only the FALSE/reuse row is uncovered).
 *
 * 1261 if ((ret==0) && (wc_LmsKey_SigsLeft(key)==0)) -- PROVEN UNREACHABLE:
 * wc_hss_make_key() (wc_lms_impl.c) always starts by zeroing Q via
 * wc_lms_idx_zero() before it can fail, and wc_hss_sigsleft() (same file)
 * with Q==0 is true for any params -- either the "levels*height>=64"
 * shortcut forces ret=1 outright, or w64LT(0, 1<<(levels*height)) is true
 * for any levels*height>=0. So SigsLeft()==0 can never hold directly after
 * a successful wc_hss_make_key(), for any parameter set. No test call is
 * possible; DEATHNOTE candidate (see task report), not closed here.
 ******************************************************************/
static void wb_makekey_checks(WC_RNG* rng)
{
    LmsKey keyBadState, keyNoWriteCb, key;
    int ret;

    /* 1163: state != PARMSET */
    ret = wc_LmsKey_MakeKey(NULL, rng);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("MakeKey key==NULL did not fail");
        wb_fail = 1;
    }
    XMEMSET(&keyBadState, 0, sizeof(keyBadState));
    wc_LmsKey_Init(&keyBadState, NULL, INVALID_DEVID); /* state INITED */
    ret = wc_LmsKey_MakeKey(&keyBadState, rng);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("MakeKey(state!=PARMSET) did not report BAD_STATE_E");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&keyBadState);

    /* 1195: write_private_key==NULL, state PARMSET (so 1163 is false). */
    XMEMSET(&keyNoWriteCb, 0, sizeof(keyNoWriteCb));
    wc_LmsKey_Init(&keyNoWriteCb, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&keyNoWriteCb, 1, 5, 8);
    ret = wc_LmsKey_MakeKey(&keyNoWriteCb, rng);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("MakeKey(no write cb) did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&keyNoWriteCb);

    /* Baseline real MakeKey: 1163/1195 false rows, 1208's (ret==0,
     * priv_data==NULL) true row, the only reachable side of 1261. */
    XMEMSET(&key, 0, sizeof(key));
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&key, 1, 5, 8);
    wc_LmsKey_SetWriteCb(&key, wb_write_key);
    ret = wc_LmsKey_MakeKey(&key, rng);
    if (ret != 0) {
        WB_NOTE("MakeKey baseline failed");
        wb_fail = 1;
    }
    else {
        /* 1208's uncovered row: priv_data!=NULL, ret==0 -- skip the
         * allocation on a second MakeKey. State is forced back to PARMSET
         * (a real caller cannot re-enter MakeKey with priv_data already
         * populated any other way once state has advanced to OK). */
        key.state = WC_LMS_STATE_PARMSET;
        ret = wc_LmsKey_MakeKey(&key, rng);
        if (ret != 0) {
            WB_NOTE("MakeKey(priv_data reuse) failed");
            wb_fail = 1;
        }
    }
    wc_LmsKey_Free(&key);

    WB_NOTE("1163/1195/1208 MakeKey leaves closed (1261 unreachable, see "
        "report)");
}

/*******************************************************************
 * wc_LmsKey_Reload: 1296 (state!=PARMSET), 1311 (read_private_key==NULL),
 * 1325 (priv_data==NULL, both rows), 1359 (SigsLeft()==0, both rows --
 * unlike MakeKey's 1261, Reload reads Q from caller-supplied storage via
 * the read callback, so an exhausted Q is a legitimate crafted input, not
 * an invariant violation).
 ******************************************************************/
static void wb_reload_checks(WC_RNG* rng)
{
    LmsKey keyA, keyBadState, keyNoReadCb, keyB, keyExhausted;
    int ret;

    /* Produce real, well-formed raw private key bytes for Reload to read
     * (saved into wb_priv/wb_privSz by wb_write_key). */
    XMEMSET(&keyA, 0, sizeof(keyA));
    wc_LmsKey_Init(&keyA, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&keyA, 1, 5, 8);
    wc_LmsKey_SetWriteCb(&keyA, wb_write_key);
    ret = wc_LmsKey_MakeKey(&keyA, rng);
    wc_LmsKey_Free(&keyA);
    if (ret != 0) {
        WB_NOTE("keyA MakeKey failed; Reload group skipped");
        wb_fail = 1;
        return;
    }

    /* 1296: state != PARMSET */
    ret = wc_LmsKey_Reload(NULL);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Reload key==NULL did not fail");
        wb_fail = 1;
    }
    XMEMSET(&keyBadState, 0, sizeof(keyBadState));
    wc_LmsKey_Init(&keyBadState, NULL, INVALID_DEVID); /* state INITED */
    ret = wc_LmsKey_Reload(&keyBadState);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("Reload(state!=PARMSET) did not report BAD_STATE_E");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&keyBadState);

    /* 1311: read_private_key==NULL, state PARMSET (1296 false). */
    XMEMSET(&keyNoReadCb, 0, sizeof(keyNoReadCb));
    wc_LmsKey_Init(&keyNoReadCb, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&keyNoReadCb, 1, 5, 8);
    ret = wc_LmsKey_Reload(&keyNoReadCb);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Reload(no read cb) did not report BAD_FUNC_ARG");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&keyNoReadCb);

    /* Baseline real Reload: 1296/1311 false rows, 1325's (ret==0,
     * priv_data==NULL) true row, 1359's (ret==0, SigsLeft()==0) false row. */
    XMEMSET(&keyB, 0, sizeof(keyB));
    wc_LmsKey_Init(&keyB, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&keyB, 1, 5, 8);
    wc_LmsKey_SetReadCb(&keyB, wb_read_key);
    ret = wc_LmsKey_Reload(&keyB);
    if (ret != 0) {
        WB_NOTE("Reload baseline failed");
        wb_fail = 1;
    }
    else {
        /* 1325's uncovered row: priv_data!=NULL, ret==0 -- skip the
         * allocation on a second Reload. */
        keyB.state = WC_LMS_STATE_PARMSET;
        ret = wc_LmsKey_Reload(&keyB);
        if (ret != 0) {
            WB_NOTE("Reload(priv_data reuse) failed");
            wb_fail = 1;
        }
    }
    wc_LmsKey_Free(&keyB);

    /* 1359's uncovered row: SigsLeft()==0 via a crafted exhausted Q. */
    XMEMSET(&keyExhausted, 0, sizeof(keyExhausted));
    wc_LmsKey_Init(&keyExhausted, NULL, INVALID_DEVID);
    wc_LmsKey_SetParameters(&keyExhausted, 1, 5, 8);
    wc_LmsKey_SetReadCb(&keyExhausted, wb_read_exhausted);
    ret = wc_LmsKey_Reload(&keyExhausted);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) {
        WB_NOTE("Reload(exhausted Q) did not report BAD_STATE_E");
        wb_fail = 1;
    }
    if (keyExhausted.state != WC_LMS_STATE_NOSIGS) {
        WB_NOTE("Reload(exhausted Q) did not set NOSIGS state");
        wb_fail = 1;
    }
    wc_LmsKey_Free(&keyExhausted);

    WB_NOTE("1296/1311/1325/1359 Reload leaves closed");
}

#else /* WOLFSSL_LMS_VERIFY_ONLY */
static void wb_getkid_from_privraw(void)
{
    WB_NOTE("WOLFSSL_LMS_VERIFY_ONLY: GetKidFromPrivRaw not compiled");
}
static void wb_getkid(void)
{
    WB_NOTE("WOLFSSL_LMS_VERIFY_ONLY: GetKid not compiled");
}
static void wb_getprivlen(void)
{
    WB_NOTE("WOLFSSL_LMS_VERIFY_ONLY: GetPrivLen not compiled");
}
static void wb_cb_setters(void)
{
    WB_NOTE("WOLFSSL_LMS_VERIFY_ONLY: SetWriteCb/SetReadCb/SetContext not "
        "compiled");
}
static void wb_sign_checks(WC_RNG* rng)
{
    (void)rng;
    WB_NOTE("WOLFSSL_LMS_VERIFY_ONLY: Sign not compiled");
}
static void wb_makekey_checks(WC_RNG* rng)
{
    (void)rng;
    WB_NOTE("WOLFSSL_LMS_VERIFY_ONLY: MakeKey not compiled");
}
static void wb_reload_checks(WC_RNG* rng)
{
    (void)rng;
    WB_NOTE("WOLFSSL_LMS_VERIFY_ONLY: Reload not compiled");
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

int main(void)
{
    WC_RNG rng;

    /* Unbuffered: a SIGKILL on timeout must not lose notes already
     * printed. */
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_lms.c fault/argument-guard white-box supplement\n");

    wb_initid();
    wb_initlabel();
    wb_setlmsparm_setparams();
    wb_getparameters();
    wb_getpublen_getsiglen();
    wb_exportpub_ex();
    wb_exportpubraw();
    wb_importpubraw();
    wb_verify_checks();
    wb_getkid_from_privraw();
    wb_getkid();
    wb_getprivlen();
    wb_cb_setters();

    XMEMSET(&rng, 0, sizeof(rng));
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; Sign/MakeKey/Reload groups skipped");
        wb_fail = 1;
    }
    else {
        wb_sign_checks(&rng);
        wb_makekey_checks(&rng);
        wb_reload_checks(&rng);
        wc_FreeRng(&rng);
    }

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Setup/skip conditions are surfaced as notes, not process failures:
     * the campaign discards a variant's whole coverage on non-zero exit. */
    return 0;
}

#else /* !WOLFSSL_HAVE_LMS */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_lms.c fault white-box: WOLFSSL_HAVE_LMS not defined, "
        "nothing to do\n");
    return 0;
}

#endif /* WOLFSSL_HAVE_LMS */
