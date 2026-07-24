/* test_async.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/async.h>
#include <wolfssl/wolfcrypt/wolfevent.h>
#include <tests/api/api.h>
#include <tests/api/test_async.h>
#include <tests/utils.h>

/*
 * Crypto callback async "poll to fill output" completion
 * (WOLF_CRYPTO_CB_ASYNC_POLL).
 *
 * A crypto callback that returns WC_PENDING_E for a TLS record cipher is
 * completed at poll time: wolfSSL keeps the async event queued and re-enters
 * the callback with WC_ALGO_TYPE_ASYNC_POLL so it can finish the job and fill
 * the output buffer. These tests exercise the completion mechanism directly
 * with a fake HSM that offloads the record ciphers (AES-GCM, AES-CBC,
 * AES-CCM, 3DES-CBC) and declines everything else.
 *
 * The tests only run when the feature is compiled in; otherwise they skip.
 */

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL)

#define TEST_ASYNC_HSM_DEVID 0x00005150
#define TEST_ASYNC_HSM_DEVID2 0x00005151  /* second device, per-peer TLS test */
#define TEST_ASYNC_MAX_POLLS 16

/* Offloading tests run at pend depths 0..TEST_ASYNC_MAX_PEND. Depth N returns
 * WC_PENDING_E on submit and N more times at poll before completing (N+1 polls
 * total). Must stay below TEST_ASYNC_MAX_POLLS. */
#define TEST_ASYNC_MAX_PEND 5

/* One in-flight offloaded job. */
typedef struct TestHsmJob {
    int         active;
    int         type;        /* wc_CipherType */
    int         dec;         /* 0 = encrypt, 1 = decrypt */
    int         pendRemaining; /* polls still returning WC_PENDING_E */
    void*       obj;         /* Aes* or Des3* */
    byte*       out;
    const byte* in;
    word32      sz;
    const byte* iv;
    word32      ivSz;
    byte*       authTag;     /* encrypt: output tag */
    const byte* authTagDec;  /* decrypt: input tag to verify */
    word32      authTagSz;
    const byte* authIn;
    word32      authInSz;
} TestHsmJob;

typedef struct TestHsm {
    TestHsmJob job;
    int        pendPolls;    /* polls to stay in-flight before completing */
    int        offloadDec;   /* also offload decrypt (single-op tests only) */
    int        invocations;  /* callback entered at all (any algo/type) */
    int        submits;      /* offloaded (pended) op count */
    int        decSubmits;   /* offloaded decrypt op count */
    int        polls;
} TestHsm;

/* Run the software cipher into the saved output, with routing disabled so the
 * completion does not re-enter this callback. */
static int test_hsm_complete(TestHsmJob* j)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    switch (j->type) {
#ifdef HAVE_AESGCM
    case WC_CIPHER_AES_GCM: {
        Aes* aes = (Aes*)j->obj;
        int save = aes->devId;
        aes->devId = INVALID_DEVID;
        if (j->dec)
            ret = wc_AesGcmDecrypt(aes, j->out, j->in, j->sz, j->iv, j->ivSz,
                                   j->authTagDec, j->authTagSz, j->authIn,
                                   j->authInSz);
        else
            ret = wc_AesGcmEncrypt(aes, j->out, j->in, j->sz, j->iv, j->ivSz,
                                   j->authTag, j->authTagSz, j->authIn,
                                   j->authInSz);
        aes->devId = save;
        break;
    }
#endif
#ifdef HAVE_AESCCM
    case WC_CIPHER_AES_CCM: {
        Aes* aes = (Aes*)j->obj;
        int save = aes->devId;
        aes->devId = INVALID_DEVID;
        if (j->dec)
            ret = wc_AesCcmDecrypt(aes, j->out, j->in, j->sz, j->iv, j->ivSz,
                                   j->authTagDec, j->authTagSz, j->authIn,
                                   j->authInSz);
        else
            ret = wc_AesCcmEncrypt(aes, j->out, j->in, j->sz, j->iv, j->ivSz,
                                   j->authTag, j->authTagSz, j->authIn,
                                   j->authInSz);
        aes->devId = save;
        break;
    }
#endif
#ifdef HAVE_AES_CBC
    case WC_CIPHER_AES_CBC: {
        Aes* aes = (Aes*)j->obj;
        int save = aes->devId;
        aes->devId = INVALID_DEVID;
        if (j->dec)
            ret = wc_AesCbcDecrypt(aes, j->out, j->in, j->sz);
        else
            ret = wc_AesCbcEncrypt(aes, j->out, j->in, j->sz);
        aes->devId = save;
        break;
    }
#endif
#ifndef NO_DES3
    case WC_CIPHER_DES3: {
        Des3* des = (Des3*)j->obj;
        int save = des->devId;
        des->devId = INVALID_DEVID;
        if (j->dec)
            ret = wc_Des3_CbcDecrypt(des, j->out, j->in, j->sz);
        else
            ret = wc_Des3_CbcEncrypt(des, j->out, j->in, j->sz);
        des->devId = save;
        break;
    }
#endif
    default:
        break;
    }
    return ret;
}

/* Fake HSM: pend and poll-complete the record ciphers, decline everything
 * else so it falls back to software. */
static int test_hsm_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    TestHsm* hsm = (TestHsm*)ctx;
    (void)devId;

    if (info == NULL)
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    hsm->invocations++;

    if (info->algo_type == WC_ALGO_TYPE_CIPHER) {
        TestHsmJob* j = &hsm->job;

        /* Offload decrypt only when asked. The single job slot cannot hold a
         * client decrypt and a server encrypt at once, which collides in the
         * TLS half-duplex flow; the direct single-op tests drive decrypt on
         * its own instead. */
        if (info->cipher.enc == 0 && !hsm->offloadDec)
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

        XMEMSET(j, 0, sizeof(*j));
        j->dec = (info->cipher.enc == 0);

        switch (info->cipher.type) {
    #ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            if (j->dec) {
                wc_CryptoCb_AesAuthDec* e = &info->cipher.aesgcm_dec;
                j->obj = e->aes; j->out = e->out; j->in = e->in; j->sz = e->sz;
                j->iv = e->iv; j->ivSz = e->ivSz;
                j->authTagDec = e->authTag; j->authTagSz = e->authTagSz;
                j->authIn = e->authIn; j->authInSz = e->authInSz;
            }
            else {
                wc_CryptoCb_AesAuthEnc* e = &info->cipher.aesgcm_enc;
                j->obj = e->aes; j->out = e->out; j->in = e->in; j->sz = e->sz;
                j->iv = e->iv; j->ivSz = e->ivSz;
                j->authTag = e->authTag; j->authTagSz = e->authTagSz;
                j->authIn = e->authIn; j->authInSz = e->authInSz;
            }
            break;
    #endif
    #ifdef HAVE_AESCCM
        case WC_CIPHER_AES_CCM:  /* CCM uses the nonce field */
            if (j->dec) {
                wc_CryptoCb_AesAuthDec* e = &info->cipher.aesccm_dec;
                j->obj = e->aes; j->out = e->out; j->in = e->in; j->sz = e->sz;
                j->iv = e->nonce; j->ivSz = e->nonceSz;
                j->authTagDec = e->authTag; j->authTagSz = e->authTagSz;
                j->authIn = e->authIn; j->authInSz = e->authInSz;
            }
            else {
                wc_CryptoCb_AesAuthEnc* e = &info->cipher.aesccm_enc;
                j->obj = e->aes; j->out = e->out; j->in = e->in; j->sz = e->sz;
                j->iv = e->nonce; j->ivSz = e->nonceSz;
                j->authTag = e->authTag; j->authTagSz = e->authTagSz;
                j->authIn = e->authIn; j->authInSz = e->authInSz;
            }
            break;
    #endif
    #ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            j->obj = info->cipher.aescbc.aes; j->out = info->cipher.aescbc.out;
            j->in = info->cipher.aescbc.in;   j->sz = info->cipher.aescbc.sz;
            break;
    #endif
    #ifndef NO_DES3
        case WC_CIPHER_DES3:
            j->obj = info->cipher.des3.des;   j->out = info->cipher.des3.out;
            j->in = info->cipher.des3.in;     j->sz = info->cipher.des3.sz;
            break;
    #endif
        default:
            /* not a record cipher this HSM offloads: run in software */
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }

        j->active = 1;
        j->type = info->cipher.type;
        j->pendRemaining = hsm->pendPolls;
        hsm->submits++;
        if (j->dec)
            hsm->decSubmits++;
        return WC_PENDING_E;
    }

    if (info->algo_type == WC_ALGO_TYPE_ASYNC_POLL) {
        TestHsmJob* j = &hsm->job;
        hsm->polls++;
        if (!j->active)
            return WC_NO_ERR_TRACE(WC_NO_PENDING_E);
        if (j->pendRemaining > 0) {
            j->pendRemaining--;      /* still in-flight this poll */
            return WC_PENDING_E;
        }
        j->active = 0;
        return test_hsm_complete(j);
    }

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

/* Reset the device counters and in-flight job for another run, and set how
 * many polls the next op stays in-flight (pendPolls) before completing. */
static void test_hsm_reset(TestHsm* hsm, int pendPolls)
{
    XMEMSET(&hsm->job, 0, sizeof(hsm->job));
    hsm->pendPolls = pendPolls;
    hsm->invocations = 0;
    hsm->submits = 0;
    hsm->decSubmits = 0;
    hsm->polls = 0;
}

/* Init the event and drive the poll to completion, bounded so a missing poll
 * path fails instead of hanging. Returns the event result. */
static int test_async_drive_poll(WC_ASYNC_DEV* dev, int ret)
{
    if (ret == WC_NO_ERR_TRACE(WC_PENDING_E)) {
        WOLF_EVENT* ev = &dev->event;
        int i;
        (void)wolfAsync_EventInit(ev, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT, dev,
                                  WC_ASYNC_FLAG_NONE);
        for (i = 0; i < TEST_ASYNC_MAX_POLLS &&
                    ev->ret == WC_NO_ERR_TRACE(WC_PENDING_E); i++) {
            (void)wolfAsync_EventPoll(ev, WOLF_POLL_FLAG_CHECK_HW);
        }
        ret = ev->ret;
    }
    return ret;
}

static WC_INLINE const byte* test_async_key32(void)
{
    static const byte k[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    return k;
}
static WC_INLINE const byte* test_async_iv12(void)
{
    static const byte v[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
    };
    return v;
}
static WC_INLINE const byte* test_async_iv16(void)
{
    static const byte v[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    return v;
}
static WC_INLINE const byte* test_async_plain32(void)
{
    static const byte p[32] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
        0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
        0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72
    };
    return p;
}
static WC_INLINE const byte* test_async_aad12(void)
{
    static const byte a[12] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce
    };
    return a;
}

#endif /* feature macros */

/*
 * AES-GCM record cipher: pends, poll-completes, and produces the same
 * ciphertext and tag as a pure software encrypt.
 */
int test_wc_CryptoCb_AsyncPollAesGcm(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && defined(HAVE_AESGCM)
    TestHsm hsm;
    Aes hw, sw;
    byte out[32], ref[32], tag[16], rtag[16];
    int registered = 0;
    int pend;

    XMEMSET(&hsm, 0, sizeof(hsm));
    XMEMSET(&hw, 0, sizeof(hw));
    XMEMSET(&sw, 0, sizeof(sw));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm), 0);
    if (EXPECT_SUCCESS())
        registered = 1;

    ExpectIntEQ(wc_AesInit(&hw, NULL, TEST_ASYNC_HSM_DEVID), 0);
    ExpectIntEQ(wc_AesInit(&sw, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesGcmSetKey(&hw, test_async_key32(), 32), 0);
    ExpectIntEQ(wc_AesGcmSetKey(&sw, test_async_key32(), 32), 0);

    /* software reference */
    ExpectIntEQ(wc_AesGcmEncrypt(&sw, ref, test_async_plain32(), 32,
        test_async_iv12(), 12, rtag, 16, test_async_aad12(), 12), 0);

    /* pend depth 0..TEST_ASYNC_MAX_PEND: op completes on poll number pend+1 */
    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        ExpectIntEQ(test_async_drive_poll(&hw.asyncDev,
            wc_AesGcmEncrypt(&hw, out, test_async_plain32(), 32,
                test_async_iv12(), 12, tag, 16, test_async_aad12(), 12)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, ref, 32);
        ExpectBufEQ(tag, rtag, 16);
    }

    /* decrypt side: poll-complete recovers the plaintext (same GCM key) */
    hsm.offloadDec = 1;
    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        ExpectIntEQ(test_async_drive_poll(&hw.asyncDev,
            wc_AesGcmDecrypt(&hw, out, ref, 32,
                test_async_iv12(), 12, rtag, 16, test_async_aad12(), 12)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, test_async_plain32(), 32);
    }

    wc_AesFree(&hw);
    wc_AesFree(&sw);
    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
#endif
    return EXPECT_RESULT();
}

/*
 * AES-CBC record cipher: pends, poll-completes, matches software.
 */
int test_wc_CryptoCb_AsyncPollAesCbc(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && defined(HAVE_AES_CBC)
    TestHsm hsm;
    Aes hw, sw, hwd;
    byte out[32], ref[32];
    int registered = 0;
    int pend;

    XMEMSET(&hsm, 0, sizeof(hsm));
    XMEMSET(&hw, 0, sizeof(hw));
    XMEMSET(&sw, 0, sizeof(sw));
    XMEMSET(&hwd, 0, sizeof(hwd));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm), 0);
    if (EXPECT_SUCCESS())
        registered = 1;

    ExpectIntEQ(wc_AesInit(&hw, NULL, TEST_ASYNC_HSM_DEVID), 0);
    ExpectIntEQ(wc_AesInit(&sw, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesInit(&hwd, NULL, TEST_ASYNC_HSM_DEVID), 0);
    ExpectIntEQ(wc_AesSetKey(&hw, test_async_key32(), 32, test_async_iv16(),
                             AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesSetKey(&sw, test_async_key32(), 32, test_async_iv16(),
                             AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesSetKey(&hwd, test_async_key32(), 32, test_async_iv16(),
                             AES_DECRYPTION), 0);

    ExpectIntEQ(wc_AesCbcEncrypt(&sw, ref, test_async_plain32(), 32), 0);

    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        /* CBC chains, so re-set the IV before each encrypt */
        ExpectIntEQ(wc_AesSetIV(&hw, test_async_iv16()), 0);
        ExpectIntEQ(test_async_drive_poll(&hw.asyncDev,
            wc_AesCbcEncrypt(&hw, out, test_async_plain32(), 32)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, ref, 32);
    }

    /* decrypt side: poll-complete recovers the plaintext from ref */
    hsm.offloadDec = 1;
    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        ExpectIntEQ(wc_AesSetIV(&hwd, test_async_iv16()), 0);
        ExpectIntEQ(test_async_drive_poll(&hwd.asyncDev,
            wc_AesCbcDecrypt(&hwd, out, ref, 32)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, test_async_plain32(), 32);
    }

    wc_AesFree(&hw);
    wc_AesFree(&sw);
    wc_AesFree(&hwd);
    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
#endif
    return EXPECT_RESULT();
}

/*
 * AES-CCM record cipher: pends, poll-completes, matches software.
 */
int test_wc_CryptoCb_AsyncPollAesCcm(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && defined(HAVE_AESCCM)
    TestHsm hsm;
    Aes hw, sw;
    byte out[32], ref[32], tag[16], rtag[16];
    int registered = 0;
    int pend;

    XMEMSET(&hsm, 0, sizeof(hsm));
    XMEMSET(&hw, 0, sizeof(hw));
    XMEMSET(&sw, 0, sizeof(sw));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm), 0);
    if (EXPECT_SUCCESS())
        registered = 1;

    ExpectIntEQ(wc_AesInit(&hw, NULL, TEST_ASYNC_HSM_DEVID), 0);
    ExpectIntEQ(wc_AesInit(&sw, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesCcmSetKey(&hw, test_async_key32(), 16), 0);
    ExpectIntEQ(wc_AesCcmSetKey(&sw, test_async_key32(), 16), 0);

    ExpectIntEQ(wc_AesCcmEncrypt(&sw, ref, test_async_plain32(), 32,
        test_async_iv12(), 12, rtag, 16, test_async_aad12(), 12), 0);

    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        ExpectIntEQ(test_async_drive_poll(&hw.asyncDev,
            wc_AesCcmEncrypt(&hw, out, test_async_plain32(), 32,
                test_async_iv12(), 12, tag, 16, test_async_aad12(), 12)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, ref, 32);
        ExpectBufEQ(tag, rtag, 16);
    }

    /* decrypt side: poll-complete recovers the plaintext (same CCM key) */
    hsm.offloadDec = 1;
    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        ExpectIntEQ(test_async_drive_poll(&hw.asyncDev,
            wc_AesCcmDecrypt(&hw, out, ref, 32,
                test_async_iv12(), 12, rtag, 16, test_async_aad12(), 12)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, test_async_plain32(), 32);
    }

    wc_AesFree(&hw);
    wc_AesFree(&sw);
    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
#endif
    return EXPECT_RESULT();
}

/*
 * 3DES-CBC record cipher: pends, poll-completes, matches software. Covers the
 * WOLFSSL_ASYNC_MARKER_3DES routing (not just AES).
 */
int test_wc_CryptoCb_AsyncPollDes3(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && !defined(NO_DES3)
    TestHsm hsm;
    Des3 hw, sw, hwd;
    byte out[32], ref[32];
    static const byte key24[24] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,
        0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23
    };
    static const byte iv8[8] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
    };
    int registered = 0;
    int pend;

    XMEMSET(&hsm, 0, sizeof(hsm));
    XMEMSET(&hw, 0, sizeof(hw));
    XMEMSET(&sw, 0, sizeof(sw));
    XMEMSET(&hwd, 0, sizeof(hwd));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm), 0);
    if (EXPECT_SUCCESS())
        registered = 1;

    ExpectIntEQ(wc_Des3Init(&hw, NULL, TEST_ASYNC_HSM_DEVID), 0);
    ExpectIntEQ(wc_Des3Init(&sw, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Des3Init(&hwd, NULL, TEST_ASYNC_HSM_DEVID), 0);
    ExpectIntEQ(wc_Des3_SetKey(&hw, key24, iv8, DES_ENCRYPTION), 0);
    ExpectIntEQ(wc_Des3_SetKey(&sw, key24, iv8, DES_ENCRYPTION), 0);
    ExpectIntEQ(wc_Des3_SetKey(&hwd, key24, iv8, DES_DECRYPTION), 0);

    ExpectIntEQ(wc_Des3_CbcEncrypt(&sw, ref, test_async_plain32(), 32), 0);

    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        /* CBC chains, so re-set the IV before each encrypt */
        ExpectIntEQ(wc_Des3_SetIV(&hw, iv8), 0);
        ExpectIntEQ(test_async_drive_poll(&hw.asyncDev,
            wc_Des3_CbcEncrypt(&hw, out, test_async_plain32(), 32)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, ref, 32);
    }

    /* decrypt side: poll-complete recovers the plaintext from ref */
    hsm.offloadDec = 1;
    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_hsm_reset(&hsm, pend);
        ExpectIntEQ(wc_Des3_SetIV(&hwd, iv8), 0);
        ExpectIntEQ(test_async_drive_poll(&hwd.asyncDev,
            wc_Des3_CbcDecrypt(&hwd, out, ref, 32)), 0);
        ExpectIntEQ(hsm.submits, 1);
        ExpectIntEQ(hsm.polls, pend + 1);
        ExpectBufEQ(out, test_async_plain32(), 32);
    }

    wc_Des3Free(&hw);
    wc_Des3Free(&sw);
    wc_Des3Free(&hwd);
    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
#endif
    return EXPECT_RESULT();
}

/*
 * A cipher with a crypto callback dispatch that the HSM declines (AES-CTR):
 * the callback IS entered (it has a dispatch) but returns unavailable, so the
 * op falls back to software with no pend and no poll. Contrast with the
 * unimplemented ciphers below, where the callback is never entered.
 */
int test_wc_CryptoCb_AsyncPollUnsupported(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && defined(WOLFSSL_AES_COUNTER)
    TestHsm hsm;
    Aes hw, sw;
    byte out[32], ref[32];
    int registered = 0;

    XMEMSET(&hsm, 0, sizeof(hsm));
    XMEMSET(&hw, 0, sizeof(hw));
    XMEMSET(&sw, 0, sizeof(sw));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm), 0);
    if (EXPECT_SUCCESS())
        registered = 1;

    ExpectIntEQ(wc_AesInit(&hw, NULL, TEST_ASYNC_HSM_DEVID), 0);
    ExpectIntEQ(wc_AesInit(&sw, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesSetKey(&hw, test_async_key32(), 32, test_async_iv16(),
                             AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesSetKey(&sw, test_async_key32(), 32, test_async_iv16(),
                             AES_ENCRYPTION), 0);

    /* declined by the HSM -> software fallback, completes synchronously */
    ExpectIntEQ(wc_AesCtrEncrypt(&hw, out, test_async_plain32(), 32), 0);
    ExpectIntGE(hsm.invocations, 1); /* dispatch exists: callback was entered */
    ExpectIntEQ(hsm.submits, 0);     /* but declined: not offloaded */
    ExpectIntEQ(hsm.polls, 0);

    ExpectIntEQ(wc_AesCtrEncrypt(&sw, ref, test_async_plain32(), 32), 0);
    ExpectBufEQ(out, ref, 32);

    wc_AesFree(&hw);
    wc_AesFree(&sw);
    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
#endif
    return EXPECT_RESULT();
}

/*
 * Negative test: ChaCha20-Poly1305 is named in the crypto callback cipher type
 * table (WC_CIPHER_CHACHA) but has no dispatch, so it is NOT offloadable. With
 * a device registered, a ChaCha20-Poly1305 encrypt must never enter the
 * callback and must run entirely in software. If crypto callback ChaCha
 * support is ever added, this test will fail and must be updated.
 */
int test_wc_CryptoCb_AsyncPollChachaUnimpl(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && defined(HAVE_CHACHA) && \
    defined(HAVE_POLY1305)
    TestHsm hsm;
    byte out[32], tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    static const byte iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
    };
    int registered = 0;

    XMEMSET(&hsm, 0, sizeof(hsm));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm), 0);
    if (EXPECT_SUCCESS())
        registered = 1;

    /* no crypto callback dispatch for ChaCha: runs in software, cb untouched */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv,
        test_async_aad12(), 12, test_async_plain32(), 32, out, tag), 0);
    ExpectIntEQ(hsm.invocations, 0);
    ExpectIntEQ(hsm.submits, 0);
    ExpectIntEQ(hsm.polls, 0);

    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
#endif
    return EXPECT_RESULT();
}

/*
 * Negative test: single DES is named in the crypto callback cipher type table
 * (WC_CIPHER_DES) but has no dispatch, so a DES-CBC encrypt with a device
 * registered must never enter the callback and run entirely in software.
 */
int test_wc_CryptoCb_AsyncPollDesUnimpl(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && !defined(NO_DES3)
    TestHsm hsm;
    Des des;
    byte out[32];
    static const byte key8[8] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    static const byte iv8[8] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
    };
    int registered = 0;

    XMEMSET(&hsm, 0, sizeof(hsm));
    XMEMSET(&des, 0, sizeof(des));

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm), 0);
    if (EXPECT_SUCCESS())
        registered = 1;

    ExpectIntEQ(wc_Des_SetKey(&des, key8, iv8, DES_ENCRYPTION), 0);
    /* no crypto callback dispatch for single DES: cb untouched */
    ExpectIntEQ(wc_Des_CbcEncrypt(&des, out, test_async_plain32(), 32), 0);
    ExpectIntEQ(hsm.invocations, 0);
    ExpectIntEQ(hsm.submits, 0);
    ExpectIntEQ(hsm.polls, 0);

    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
#endif
    return EXPECT_RESULT();
}

/*
 * Full-stack TLS 1.3 tests. One generic harness drives an in-memory
 * client/server handshake and an application-data echo through the crypto
 * callback record cipher; only the callback implementation and the pinned
 * ciphersuite are swapped per test.
 */
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLF_CRYPTO_CB_ASYNC_POLL) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_AESGCM) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)

#define TEST_ASYNC_TLS

/* A device that offloads the AES-GCM record cipher but does NOT implement the
 * poll completion (returns unavailable for WC_ALGO_TYPE_ASYNC_POLL). The op
 * pends and can never finish, so the record layer must fail rather than ship
 * an unencrypted record. */
static int test_hsm_nopoll_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    TestHsm* hsm = (TestHsm*)ctx;
    (void)devId;

    if (info == NULL)
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    hsm->invocations++;

    if (info->algo_type == WC_ALGO_TYPE_CIPHER && info->cipher.enc == 1 &&
            info->cipher.type == WC_CIPHER_AES_GCM) {
        hsm->submits++;
        return WC_PENDING_E;         /* pended, but no poll support */
    }
    if (info->algo_type == WC_ALGO_TYPE_ASYNC_POLL) {
        hsm->polls++;
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

/* Drive one wolfSSL_write/read through, servicing async pends. Returns 1 if
 * the message round-trips, 0 on failure. */
static int test_async_tls_echo(WOLFSSL* ssl_c, WOLFSSL* ssl_s)
{
    const char msg[] = "hello async record layer";
    byte buf[64];
    int ret, err, i;

    for (i = 0, ret = -1; i < 40; i++) {
        ret = wolfSSL_write(ssl_c, msg, (int)sizeof(msg));
        if (ret == (int)sizeof(msg))
            break;
        err = wolfSSL_get_error(ssl_c, ret);
        if (err == WC_NO_ERR_TRACE(WC_PENDING_E))
            (void)wolfSSL_AsyncPoll(ssl_c, WOLF_POLL_FLAG_CHECK_HW);
        else if (err != WOLFSSL_ERROR_WANT_READ &&
                 err != WOLFSSL_ERROR_WANT_WRITE)
            return 0;
    }
    if (ret != (int)sizeof(msg))
        return 0;

    for (i = 0, ret = -1; i < 40; i++) {
        ret = wolfSSL_read(ssl_s, buf, (int)sizeof(buf));
        if (ret > 0)
            break;
        err = wolfSSL_get_error(ssl_s, ret);
        if (err == WC_NO_ERR_TRACE(WC_PENDING_E))
            (void)wolfSSL_AsyncPoll(ssl_s, WOLF_POLL_FLAG_CHECK_HW);
        else if (err != WOLFSSL_ERROR_WANT_READ &&
                 err != WOLFSSL_ERROR_WANT_WRITE)
            return 0;
    }
    return (ret == (int)sizeof(msg) && XMEMCMP(buf, msg, sizeof(msg)) == 0);
}

typedef struct TlsAsyncResult {
    int handshake;     /* 0 = handshake completed */
    int dataOk;        /* 1 = echo round-tripped */
    int cipherSubmits; /* record ciphers offloaded to the device */
} TlsAsyncResult;

/* Generic harness: register the given callback, run a TLS 1.3 handshake and
 * echo over memio with the given ciphersuite pinned, and report the outcome
 * plus how many record ciphers were offloaded. */
static void test_async_tls_run(CryptoDevCallbackFunc cb, const char* cipherList,
                               int pendPolls, TlsAsyncResult* res)
{
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    TestHsm hsm;
    int registered = 0;

    res->handshake = -1;
    res->dataOk = 0;
    res->cipherSubmits = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&hsm, 0, sizeof(hsm));
    hsm.pendPolls = pendPolls;   /* polls each record cipher stays in-flight */

    if (wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, cb, &hsm) != 0)
        return;
    registered = 1;

    if (test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method) != 0)
        goto cleanup;

    (void)wolfSSL_CTX_SetDevId(ctx_c, TEST_ASYNC_HSM_DEVID);
    (void)wolfSSL_CTX_SetDevId(ctx_s, TEST_ASYNC_HSM_DEVID);
    (void)wolfSSL_SetDevId(ssl_c, TEST_ASYNC_HSM_DEVID);
    (void)wolfSSL_SetDevId(ssl_s, TEST_ASYNC_HSM_DEVID);

    if (cipherList != NULL) {
        if (wolfSSL_set_cipher_list(ssl_c, cipherList) != WOLFSSL_SUCCESS ||
            wolfSSL_set_cipher_list(ssl_s, cipherList) != WOLFSSL_SUCCESS)
            goto cleanup;
    }

    res->handshake = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);
    if (res->handshake == 0)
        res->dataOk = test_async_tls_echo(ssl_c, ssl_s);
    res->cipherSubmits = hsm.submits;

cleanup:
    if (ssl_c != NULL)
        wolfSSL_free(ssl_c);
    if (ssl_s != NULL)
        wolfSSL_free(ssl_s);
    if (ctx_c != NULL)
        wolfSSL_CTX_free(ctx_c);
    if (ctx_s != NULL)
        wolfSSL_CTX_free(ctx_s);
    if (registered)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
}

#endif /* TEST_ASYNC_TLS */

/*
 * Full TLS 1.3 with AES-GCM offloaded to a poll-completing device: the
 * handshake and an application-data echo both succeed, and the record cipher
 * is offloaded (poll completion drives the encrypted records).
 */
int test_wc_CryptoCb_AsyncPollTlsAesGcm(void)
{
    EXPECT_DECLS;
#ifdef TEST_ASYNC_TLS
    TlsAsyncResult res;
    int pend;

    /* pend depth 0..TEST_ASYNC_MAX_PEND: each record cipher stays in-flight for
     * that many extra polls before completing. */
    for (pend = 0; pend <= TEST_ASYNC_MAX_PEND; pend++) {
        test_async_tls_run(test_hsm_cb,
            "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384", pend, &res);

        ExpectIntEQ(res.handshake, 0);
        ExpectIntEQ(res.dataOk, 1);
        ExpectIntGT(res.cipherSubmits, 0);
    }
#endif
    return EXPECT_RESULT();
}

/*
 * Full TLS 1.3 with ChaCha20-Poly1305: ChaCha has no crypto callback dispatch,
 * so the record cipher runs in software. The handshake and echo still succeed
 * and the device is never asked to offload a record cipher.
 */
int test_wc_CryptoCb_AsyncPollTlsChachaNotOffloaded(void)
{
    EXPECT_DECLS;
#if defined(TEST_ASYNC_TLS) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    TlsAsyncResult res;

    test_async_tls_run(test_hsm_cb, "TLS13-CHACHA20-POLY1305-SHA256", 1, &res);

    ExpectIntEQ(res.handshake, 0);
    ExpectIntEQ(res.dataOk, 1);
    ExpectIntEQ(res.cipherSubmits, 0); /* ChaCha not dispatched to the device */
#endif
    return EXPECT_RESULT();
}

/*
 * Full TLS 1.3 with AES-GCM offloaded to a device that pends the record cipher
 * but does NOT implement poll completion: the handshake must fail rather than
 * transmit an unencrypted record.
 */
int test_wc_CryptoCb_AsyncPollTlsNoPollFails(void)
{
    EXPECT_DECLS;
#ifdef TEST_ASYNC_TLS
    TlsAsyncResult res;

    test_async_tls_run(test_hsm_nopoll_cb,
        "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384", 1, &res);

    ExpectIntNE(res.handshake, 0);     /* expected failure */
    ExpectIntEQ(res.dataOk, 0);
    ExpectIntGT(res.cipherSubmits, 0); /* it did pend a record cipher */
#endif
    return EXPECT_RESULT();
}

/*
 * Full TLS 1.3 with AES-GCM offloaded on BOTH the encrypt and decrypt record
 * paths. Each peer uses its own poll-completing device, so a client decrypt and
 * a server encrypt never share one job slot. The handshake and echo succeed and
 * both peers offload at least one decrypt through poll completion, confirming
 * the poll model drives the receive (decrypt) side, not just send.
 */
int test_wc_CryptoCb_AsyncPollTlsBothDirections(void)
{
    EXPECT_DECLS;
#ifdef TEST_ASYNC_TLS
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    TestHsm hsm_c, hsm_s;
    int reg_c = 0, reg_s = 0;
    int handshake = -1, dataOk = 0;
    const char* ciphers = "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&hsm_c, 0, sizeof(hsm_c));
    XMEMSET(&hsm_s, 0, sizeof(hsm_s));
    hsm_c.pendPolls = 1; hsm_c.offloadDec = 1;
    hsm_s.pendPolls = 1; hsm_s.offloadDec = 1;

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID, test_hsm_cb,
                                           &hsm_c), 0);
    if (EXPECT_SUCCESS())
        reg_c = 1;
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_ASYNC_HSM_DEVID2, test_hsm_cb,
                                           &hsm_s), 0);
    if (EXPECT_SUCCESS())
        reg_s = 1;

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    if (ssl_c != NULL && ssl_s != NULL) {
        (void)wolfSSL_CTX_SetDevId(ctx_c, TEST_ASYNC_HSM_DEVID);
        (void)wolfSSL_CTX_SetDevId(ctx_s, TEST_ASYNC_HSM_DEVID2);
        (void)wolfSSL_SetDevId(ssl_c, TEST_ASYNC_HSM_DEVID);
        (void)wolfSSL_SetDevId(ssl_s, TEST_ASYNC_HSM_DEVID2);

        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, ciphers), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, ciphers), WOLFSSL_SUCCESS);

        /* Both directions offloaded on both peers means many more poll cycles
         * than the encrypt-only tests, so allow more handshake rounds. */
        handshake = test_memio_do_handshake(ssl_c, ssl_s, 64, NULL);
        ExpectIntEQ(handshake, 0);
        if (handshake == 0)
            dataOk = test_async_tls_echo(ssl_c, ssl_s);
        ExpectIntEQ(dataOk, 1);

        /* both peers offloaded record ciphers, including >=1 decrypt each */
        ExpectIntGT(hsm_c.submits, 0);
        ExpectIntGT(hsm_s.submits, 0);
        ExpectIntGT(hsm_c.decSubmits, 0);
        ExpectIntGT(hsm_s.decSubmits, 0);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    if (reg_c)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID);
    if (reg_s)
        wc_CryptoCb_UnRegisterDevice(TEST_ASYNC_HSM_DEVID2);
#endif
    return EXPECT_RESULT();
}
