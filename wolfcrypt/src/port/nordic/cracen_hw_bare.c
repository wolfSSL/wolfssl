/* cracen_hw_bare.c
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

/* Register-level driver for the nRF54L CRACEN Cryptomaster (AES, hash) and
 * TRNG. No vendor SDK is used: everything is programmed through the register
 * map in cracen_regs.h.
 *
 * The Cryptomaster has no CPU-visible engine registers. Engine configuration
 * (mode word, key, IV, saved state) and data alike are fetched by DMA from a
 * chain of descriptors, each tagged with the target engine and whether the
 * block is a register write or data. Results come back through a second
 * descriptor chain driven by the pusher DMA. Every operation here builds the
 * two chains on the stack, starts both DMAs and polls for completion.
 *
 * Buffers handed to the DMA must be in RAM (the pusher cannot write RRAM).
 * The Cortex-M33 on this device has no data cache, so only barriers are
 * needed around the start of a transfer.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NRF54L_CRACEN) && !defined(WOLFSSL_CRACEN_HOST_TEST)

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_regs.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_hw.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef WOLFSSL_CRACEN_TIMEOUT
    #define WOLFSSL_CRACEN_TIMEOUT      0x400000UL
#endif
#ifndef WOLFSSL_CRACEN_TRNG_CLKDIV
    #define WOLFSSL_CRACEN_TRNG_CLKDIV  241
#endif
#ifndef WOLFSSL_CRACEN_TRNG_INITWAIT
    #define WOLFSSL_CRACEN_TRNG_INITWAIT 512
#endif
#ifndef WOLFSSL_CRACEN_TRNG_OFFTIMER
    #define WOLFSSL_CRACEN_TRNG_OFFTIMER 0
#endif
#ifndef WOLFSSL_CRACEN_TRNG_MAX_RECOVERIES
    #define WOLFSSL_CRACEN_TRNG_MAX_RECOVERIES 3
#endif
#define WC_CRACEN_TRNG_NB128            4
#define WC_CRACEN_TRNG_COND_KEY_WORDS   4
#define WC_CRACEN_RESET_SPIN            256

#if defined(__GNUC__) && (defined(__arm__) || defined(__thumb__))
    #define CRACEN_DSB()      __asm__ __volatile__ ("dsb" ::: "memory")
#elif defined(__GNUC__)
    #define CRACEN_DSB()      __asm__ __volatile__ ("" ::: "memory")
#else
    #define CRACEN_DSB()      WC_DO_NOTHING
#endif

static struct {
    byte               init;
    byte               trngReady;
    byte               trngKeySet;
    word32             trngPrevStatus;
    wc_CracenHwInfo    info;
    wc_CracenTrngStats trng;
} gCracen;

static WC_INLINE void cracen_wr(word32 base, word32 off, word32 val)
{
    *(volatile word32*)(wc_ptr_t)(base + off) = val;
}

static WC_INLINE word32 cracen_rd(word32 base, word32 off)
{
    return *(volatile word32*)(wc_ptr_t)(base + off);
}

#define CM_WR(off, v)  cracen_wr(WC_CRACENCORE_BASE, (off), (v))
#define CM_RD(off)     cracen_rd(WC_CRACENCORE_BASE, (off))
#define CR_WR(off, v)  cracen_wr(WC_CRACEN_BASE, (off), (v))
#define CR_RD(off)     cracen_rd(WC_CRACEN_BASE, (off))

static WC_INLINE void desc_set(wc_CracenDesc* d, const void* addr, word32 len,
    word32 tag)
{
    d->addr = (word32)(wc_ptr_t)addr;
    d->next = WC_CM_DESC_STOP;
    d->len  = len;
    d->tag  = tag;
}

static WC_INLINE void desc_discard(wc_CracenDesc* d, word32 len)
{
    desc_set(d, NULL, len | WC_CM_LEN_DISCARD, 0);
}

static WC_INLINE word32 align16(word32 n)
{
    return (n + 15UL) & ~15UL;
}

static WC_INLINE void put_be32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

/* Cryptomaster -------------------------------------------------------------*/

static void cm_softreset(void)
{
    volatile word32 spin = WC_CRACEN_RESET_SPIN;
    word32 timeout = WOLFSSL_CRACEN_TIMEOUT;

    CM_WR(WC_CM_CONFIG, WC_CM_CONFIG_SOFTRST);
    /* Hold the pulse: a short one can leave an active transfer wedged. */
    while (spin-- != 0) {
    }
    CM_WR(WC_CM_CONFIG, 0);
    while ((CM_RD(WC_CM_STATUS) & WC_CM_STATUS_SOFTRST_BUSY) != 0) {
        if (--timeout == 0)
            break;
    }
    CM_WR(WC_CM_INTSTATCLR, 0xFFFFFFFFUL);
}

/* Link the chains, start both DMAs and wait. in/out are arrays of nIn/nOut
 * descriptors in RAM; they are modified in place. */
static int cm_run(wc_CracenDesc* in, int nIn, wc_CracenDesc* out, int nOut)
{
    int i;
    word32 status;
    word32 timeout = WOLFSSL_CRACEN_TIMEOUT;

    if (nIn < 1 || nOut < 1)
        return BAD_FUNC_ARG;

    for (i = 0; i < nIn - 1; i++)
        in[i].next = (word32)(wc_ptr_t)&in[i + 1];
    in[nIn - 1].next = WC_CM_DESC_STOP;
    in[nIn - 1].tag |= WC_CM_TAG_LAST;
    in[nIn - 1].len |= WC_CM_LEN_REALIGN;

    for (i = 0; i < nOut - 1; i++)
        out[i].next = (word32)(wc_ptr_t)&out[i + 1];
    out[nOut - 1].next = WC_CM_DESC_STOP;
    out[nOut - 1].tag |= WC_CM_TAG_LAST;
    out[nOut - 1].len |= WC_CM_LEN_REALIGN;

    if ((CM_RD(WC_CM_STATUS) & WC_CM_STATUS_BUSY_MASK) != 0)
        cm_softreset();

    CRACEN_DSB();
    CM_WR(WC_CM_FETCHADDR, (word32)(wc_ptr_t)in);
    CM_WR(WC_CM_PUSHADDR, (word32)(wc_ptr_t)out);
    CM_WR(WC_CM_CONFIG, WC_CM_CONFIG_FETCH_INDIRECT | WC_CM_CONFIG_PUSH_INDIRECT);
    CM_WR(WC_CM_START, WC_CM_START_FETCH | WC_CM_START_PUSH);

    while ((CM_RD(WC_CM_STATUS) & WC_CM_STATUS_BUSY_MASK) != 0) {
        if (--timeout == 0) {
            cm_softreset();
            return WC_HW_E;
        }
    }
    status = CM_RD(WC_CM_INTSTATRAW);
    CM_WR(WC_CM_INTSTATCLR, 0xFFFFFFFFUL);
    CRACEN_DSB();

    if ((status & (WC_CM_INT_FETCH_ERROR | WC_CM_INT_PUSH_ERROR)) != 0) {
        cm_softreset();
        return WC_HW_E;
    }
    return 0;
}

/* Seed the AES masking countermeasure. */
static int cm_load_mask(word32 rnd)
{
    wc_CracenDesc in[1];
    wc_CracenDesc out[1];

    desc_set(&in[0], &rnd, sizeof(rnd) | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_MASK));
    desc_set(&out[0], NULL, 0, 0);
    return cm_run(in, 1, out, 1);
}

/* TRNG -------------------------------------------------------------------- */

/* The BA431 samples free running ring oscillators, runs the NIST SP 800-90B
 * repetition count and adaptive proportion tests and the AIS31 tests on the
 * samples, conditions them with AES-CBC-MAC (NB128BITBLOCKS raw blocks per
 * output block) and queues the result in a 16-word FIFO. The ring oscillators
 * stop once the FIFO is full and restart, with the start-up test, when a read
 * takes the level below the threshold. A failed test puts the FSM in ERROR,
 * from which only a restart recovers. */

static void trng_power(int on)
{
    word32 en = CR_RD(WC_CRACEN_ENABLE);

    if (on)
        CR_WR(WC_CRACEN_ENABLE, en | WC_CRACEN_ENABLE_RNG);
    else
        CR_WR(WC_CRACEN_ENABLE, en & ~WC_CRACEN_ENABLE_RNG);
    gCracen.trngReady  = 0;
    gCracen.trngKeySet = 0;
}

static void trng_init(void)
{
    word32 depth;

    /* SOFTRST clears the tests, the conditioner and the FIFO; ENABLE low
     * resets the FSM */
    CM_WR(WC_RNG_CONTROL, WC_RNG_CONTROL_SOFTRST);
    CM_WR(WC_RNG_CONTROL, 0);

    depth = CM_RD(WC_RNG_FIFODEPTH);
    if (depth >= 4)
        CM_WR(WC_RNG_FIFOTHRESHOLD, depth / 4 - 1);
    CM_WR(WC_RNG_SWOFFTMRVAL, WOLFSSL_CRACEN_TRNG_OFFTIMER);
    CM_WR(WC_RNG_CLKDIV, WOLFSSL_CRACEN_TRNG_CLKDIV);
    CM_WR(WC_RNG_INITWAITVAL, WOLFSSL_CRACEN_TRNG_INITWAIT);

    CM_WR(WC_RNG_CONTROL, WC_RNG_CONTROL_ENABLE |
        WC_RNG_CONTROL_NB128(WC_CRACEN_TRNG_NB128));
    gCracen.trngKeySet     = 0;
    gCracen.trngReady      = 1;
    gCracen.trngPrevStatus = 0;
    gCracen.trng.starts++;
}

/* Count alarm flags on their rising edge; they stay set until a restart. */
static void trng_note_status(word32 status)
{
    word32 rose = status & ~gCracen.trngPrevStatus;

    gCracen.trngPrevStatus = status;
    gCracen.trng.lastStatus = status;
    if (rose & WC_RNG_STATUS_REPFAIL)
        gCracen.trng.repFail++;
    if (rose & WC_RNG_STATUS_PROPFAIL)
        gCracen.trng.propFail++;
    if (rose & WC_RNG_STATUS_PREINT)
        gCracen.trng.ais31Prelim++;
    if (rose & WC_RNG_STATUS_ALMINT)
        gCracen.trng.ais31Alarm++;
}

/* Load the AES-CBC-MAC conditioning key from the first FIFO words, then
 * restart so nothing produced under the default key is handed out. */
static void trng_set_cond_key(void)
{
    word32 i;
    word32 ctrl;

    for (i = 0; i < WC_CRACEN_TRNG_COND_KEY_WORDS; i++)
        CM_WR(WC_RNG_KEY0 + 4 * i, CM_RD(WC_RNG_FIFO));

    ctrl = CM_RD(WC_RNG_CONTROL);
    CM_WR(WC_RNG_CONTROL, ctrl | WC_RNG_CONTROL_SOFTRST);
    CM_WR(WC_RNG_CONTROL, ctrl & ~WC_RNG_CONTROL_SOFTRST);
    gCracen.trngKeySet = 1;
}

static int trng_read(byte* out, word32 sz)
{
    word32 timeout = WOLFSSL_CRACEN_TIMEOUT;
    int    recoveries = 0;

    if ((CR_RD(WC_CRACEN_ENABLE) & WC_CRACEN_ENABLE_RNG) == 0)
        trng_power(1);
    if (!gCracen.trngReady)
        trng_init();

    while (sz > 0) {
        word32 status = CM_RD(WC_RNG_STATUS);
        word32 state  = (status >> WC_RNG_STATUS_STATE_SHIFT) &
                        WC_RNG_STATUS_STATE_MASK;
        word32 word;
        word32 n;

        trng_note_status(status);

        if (state == WC_RNG_STATE_ERROR ||
                (status & WC_RNG_STATUS_STARTUPFAIL) != 0) {
            gCracen.trng.errors++;
            if (++recoveries > WOLFSSL_CRACEN_TRNG_MAX_RECOVERIES)
                return RNG_FAILURE_E;
            trng_init();
            timeout = WOLFSSL_CRACEN_TIMEOUT;
            continue;
        }
        if (state == WC_RNG_STATE_RESET || state == WC_RNG_STATE_STARTUP) {
            if (--timeout == 0)
                return RNG_FAILURE_E;
            continue;
        }
        if (!gCracen.trngKeySet) {
            if (CM_RD(WC_RNG_FIFOLEVEL) < WC_CRACEN_TRNG_COND_KEY_WORDS) {
                if (--timeout == 0)
                    return RNG_FAILURE_E;
                continue;
            }
            trng_set_cond_key();
            timeout = WOLFSSL_CRACEN_TIMEOUT;
            continue;
        }
        if (CM_RD(WC_RNG_FIFOLEVEL) == 0) {
            if (--timeout == 0)
                return RNG_FAILURE_E;
            continue;
        }

        word = CM_RD(WC_RNG_FIFO);
        for (n = 0; n < 4 && sz > 0; n++, sz--) {
            *out++ = (byte)(word & 0xFF);
            word >>= 8;
            gCracen.trng.bytes++;
        }
        timeout = WOLFSSL_CRACEN_TIMEOUT;
    }
    return 0;
}

/* Public --------------------------------------------------------------------*/

int wc_CracenHw_Init(void)
{
    int ret = 0;

    if (gCracen.init)
        return 0;

    ret = wolfSSL_CryptHwMutexInit();
    if (ret != 0)
        return ret;
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;

    XMEMSET(&gCracen, 0, sizeof(gCracen));
    CR_WR(WC_CRACEN_ENABLE, CR_RD(WC_CRACEN_ENABLE) |
        WC_CRACEN_ENABLE_CRYPTOMASTER);
    cm_softreset();

    gCracen.info.engines  = CM_RD(WC_CM_HW_INCLIPS);
    gCracen.info.aesModes = CM_RD(WC_CM_HW_BA411_CFG1);
    gCracen.info.aesCtrSz = CM_RD(WC_CM_HW_BA411_CFG2);
    gCracen.info.hashCfg  = CM_RD(WC_CM_HW_BA413_CFG);
    gCracen.init = 1;

#ifdef WOLFSSL_CRACEN_TRNG
    if ((gCracen.info.engines & WC_CM_HW_BA431_NDRNG) != 0) {
        word32 rnd = 0;
        trng_power(1);
        gCracen.info.rngCfg = CM_RD(WC_RNG_HWCONFIG);
        if (trng_read((byte*)&rnd, sizeof(rnd)) == 0 &&
                (gCracen.info.engines & WC_CM_HW_BA411_AES) != 0) {
            (void)cm_load_mask(rnd);
        }
    #ifdef WOLFSSL_CRACEN_TRNG_ON_DEMAND
        trng_power(0);
    #endif
    }
#endif

    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

void wc_CracenHw_Cleanup(void)
{
    if (!gCracen.init)
        return;
    if (wolfSSL_CryptHwMutexLock() == 0) {
        CR_WR(WC_CRACEN_ENABLE, CR_RD(WC_CRACEN_ENABLE) &
            ~(WC_CRACEN_ENABLE_CRYPTOMASTER | WC_CRACEN_ENABLE_RNG));
        XMEMSET(&gCracen, 0, sizeof(gCracen));
        wolfSSL_CryptHwMutexUnLock();
    }
}

int wc_CracenHw_GetInfo(wc_CracenHwInfo* info)
{
    if (info == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;
    *info = gCracen.info;
    return 0;
}

int wc_CracenHw_Hash(word32 algo, const byte* state, word32 stateSz,
    const byte* data, word32 dataSz, byte* out, word32 outSz, int final)
{
    wc_CracenDesc in[3];
    wc_CracenDesc outd[1];
    int    n = 0;
    int    ret;
    word32 cfg;

    if (!gCracen.init)
        return BAD_STATE_E;
    if ((gCracen.info.engines & WC_CM_HW_BA413_HASH) == 0 ||
            (gCracen.info.hashCfg & algo) == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (out == NULL || outSz == 0 || (dataSz == 0 && state == NULL) ||
            (dataSz & 3) != 0 || dataSz >= WC_CM_MAX_LEN) {
        return BAD_FUNC_ARG;
    }

    cfg = algo;
    if (final)
        cfg |= WC_CM_HASH_CFG_FINAL;

    desc_set(&in[n++], &cfg, sizeof(cfg) | WC_CM_LEN_REALIGN,
        WC_CM_HASH_TAG_CFG);
    if (state != NULL) {
        desc_set(&in[n++], state, stateSz | WC_CM_LEN_REALIGN,
            WC_CM_HASH_TAG_INIT_STATE | WC_CM_TAG_LAST);
    }
    if (dataSz > 0)
        desc_set(&in[n++], data, dataSz, WC_CM_HASH_TAG_MESSAGE);
    desc_set(&outd[0], out, outSz, 0);

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = cm_run(in, n, outd, 1);
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_CracenHw_AesCrypt(word32 mode, int decrypt, const byte* key,
    word32 keySz, const byte* iv, const wc_CracenSeg* segs, int nSegs)
{
    wc_CracenDesc in[3 + WC_CRACEN_MAX_SEGS];
    wc_CracenDesc outd[WC_CRACEN_MAX_SEGS];
    int    n = 0;
    int    i;
    int    ret;
    word32 cfg;

    if (!gCracen.init)
        return BAD_STATE_E;
    if ((gCracen.info.engines & WC_CM_HW_BA411_AES) == 0 ||
            (gCracen.info.aesModes & (mode >> WC_CM_AES_CFG_MODE_SHIFT)) == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (key == NULL || segs == NULL || nSegs < 1 || nSegs > WC_CRACEN_MAX_SEGS)
        return BAD_FUNC_ARG;
    for (i = 0; i < nSegs; i++) {
        if (segs[i].in == NULL || segs[i].out == NULL || segs[i].sz == 0 ||
                (segs[i].sz & 15) != 0 || segs[i].sz >= WC_CM_MAX_LEN) {
            return BAD_FUNC_ARG;
        }
    }

    cfg = mode | (decrypt ? WC_CM_AES_CFG_DECRYPT : 0);
    desc_set(&in[n++], &cfg, sizeof(cfg) | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_CONFIG));
    desc_set(&in[n++], key, keySz | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_KEY));
    if (iv != NULL) {
        desc_set(&in[n++], iv, 16 | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_CFG(WC_CM_AES_REG_IV));
    }
    for (i = 0; i < nSegs; i++) {
        desc_set(&in[n++], segs[i].in, segs[i].sz | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_PAYLOAD);
        desc_set(&outd[i], segs[i].out, segs[i].sz, 0);
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = cm_run(in, n, outd, nSegs);
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_CracenHw_AesGcm(int decrypt, const byte* key, word32 keySz,
    const byte* iv, const byte* aad, word32 aadSz, const byte* in, word32 sz,
    byte* out, byte* tag, word32 tagSz)
{
    wc_CracenDesc ind[8];
    wc_CracenDesc outd[6];
    byte   aadTail[16];
    byte   dataTail[16];
    byte   lenBlock[16];
    word32 aadFull  = aadSz & ~15UL;
    word32 aadRem   = aadSz & 15UL;
    word32 dataFull = sz & ~15UL;
    word32 dataRem  = sz & 15UL;
    int    ni = 0;
    int    no = 0;
    int    ret;
    word32 cfg;

    if (!gCracen.init)
        return BAD_STATE_E;
    if ((gCracen.info.engines & WC_CM_HW_BA411_AES) == 0 ||
            (gCracen.info.aesModes &
             (WC_CM_AES_MODE_GCM >> WC_CM_AES_CFG_MODE_SHIFT)) == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (key == NULL || iv == NULL || tag == NULL || tagSz < 4 || tagSz > 16 ||
            sz >= WC_CM_MAX_LEN || aadSz >= WC_CM_MAX_LEN ||
            (sz > 0 && (in == NULL || out == NULL)) ||
            (aadSz > 0 && aad == NULL)) {
        return BAD_FUNC_ARG;
    }

    cfg = WC_CM_AES_MODE_GCM | (decrypt ? WC_CM_AES_CFG_DECRYPT : 0);
    desc_set(&ind[ni++], &cfg, sizeof(cfg) | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_CONFIG));
    desc_set(&ind[ni++], key, keySz | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_KEY));
    desc_set(&ind[ni++], iv, 12 | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_IV));

    if (aadFull > 0) {
        desc_set(&ind[ni++], aad, aadFull | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_HEADER);
    }
    if (aadRem > 0) {
        XMEMSET(aadTail, 0, sizeof(aadTail));
        XMEMCPY(aadTail, aad + aadFull, aadRem);
        desc_set(&ind[ni++], aadTail, 16 | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_HEADER | WC_CM_TAG_IGN(16 - aadRem));
    }
    if (dataFull > 0) {
        desc_set(&ind[ni++], in, dataFull | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_PAYLOAD);
    }
    if (dataRem > 0) {
        XMEMSET(dataTail, 0, sizeof(dataTail));
        XMEMCPY(dataTail, in + dataFull, dataRem);
        desc_set(&ind[ni++], dataTail, 16 | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_PAYLOAD | WC_CM_TAG_IGN(16 - dataRem));
    }
    /* len(A) || len(C) in bits, big endian */
    XMEMSET(lenBlock, 0, sizeof(lenBlock));
    put_be32(lenBlock, aadSz >> 29);
    put_be32(lenBlock + 4, aadSz << 3);
    put_be32(lenBlock + 8, sz >> 29);
    put_be32(lenBlock + 12, sz << 3);
    desc_set(&ind[ni++], lenBlock, 16 | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_PAYLOAD);

    /* The engine echoes the header, then the text, then the tag. */
    if (aadSz > 0)
        desc_discard(&outd[no++], align16(aadSz));
    if (sz > 0)
        desc_set(&outd[no++], out, sz, 0);
    if (dataRem > 0)
        desc_discard(&outd[no++], 16 - dataRem);
    desc_set(&outd[no++], tag, tagSz, 0);
    if (tagSz < 16)
        desc_discard(&outd[no++], 16 - tagSz);

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = cm_run(ind, ni, outd, no);
        wolfSSL_CryptHwMutexUnLock();
    }
    ForceZero(aadTail, sizeof(aadTail));
    ForceZero(dataTail, sizeof(dataTail));
    return ret;
}

int wc_CracenHw_AesCmac(const byte* key, word32 keySz, const byte* state,
    const byte* data, word32 dataSz, const byte* tail, word32 tailSz,
    byte* out, int final)
{
    wc_CracenDesc in[5];
    wc_CracenDesc outd[1];
    byte   tailBuf[16];
    int    n = 0;
    int    ret;
    word32 cfg;

    if (!gCracen.init)
        return BAD_STATE_E;
    if ((gCracen.info.engines & WC_CM_HW_BA411_AES) == 0 ||
            (gCracen.info.aesModes &
             (WC_CM_AES_MODE_CMAC >> WC_CM_AES_CFG_MODE_SHIFT)) == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (key == NULL || out == NULL || (dataSz & 15) != 0 ||
            dataSz >= WC_CM_MAX_LEN || tailSz > 16 ||
            (dataSz > 0 && data == NULL) || (tailSz > 0 && tail == NULL) ||
            (!final && (dataSz == 0 || tailSz != 0)) ||
            (final && tailSz == 0 && (state != NULL || dataSz != 0))) {
        return BAD_FUNC_ARG;
    }

    cfg = WC_CM_AES_MODE_CMAC;
    if (state != NULL)
        cfg |= WC_CM_AES_CFG_CTX_LOAD;
    if (!final)
        cfg |= WC_CM_AES_CFG_CTX_SAVE;

    desc_set(&in[n++], &cfg, sizeof(cfg) | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_CONFIG));
    desc_set(&in[n++], key, keySz | WC_CM_LEN_REALIGN,
        WC_CM_AES_TAG_CFG(WC_CM_AES_REG_KEY));
    if (state != NULL) {
        desc_set(&in[n++], state, 16 | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_CFG(WC_CM_AES_REG_IV));
    }
    if (dataSz > 0)
        desc_set(&in[n++], data, dataSz, WC_CM_AES_TAG_PAYLOAD);
    if (final) {
        XMEMSET(tailBuf, 0, sizeof(tailBuf));
        if (tailSz > 0)
            XMEMCPY(tailBuf, tail, tailSz);
        /* An empty message is one all-invalid block. */
        desc_set(&in[n++], tailBuf, 16 | WC_CM_LEN_REALIGN,
            WC_CM_AES_TAG_PAYLOAD | WC_CM_TAG_IGN(16 - tailSz));
    }
    desc_set(&outd[0], out, 16, 0);

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = cm_run(in, n, outd, 1);
        wolfSSL_CryptHwMutexUnLock();
    }
    ForceZero(tailBuf, sizeof(tailBuf));
    return ret;
}

int wc_CracenHw_TrngRead(byte* out, word32 sz)
{
    int ret;

    if (out == NULL && sz > 0)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;
    if ((gCracen.info.engines & WC_CM_HW_BA431_NDRNG) == 0)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = trng_read(out, sz);
    #ifdef WOLFSSL_CRACEN_TRNG_ON_DEMAND
        trng_power(0);
    #endif
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

void wc_CracenHw_TrngOff(void)
{
    if (!gCracen.init)
        return;
    if (wolfSSL_CryptHwMutexLock() == 0) {
        trng_power(0);
        wolfSSL_CryptHwMutexUnLock();
    }
}

int wc_CracenHw_TrngGetStats(wc_CracenTrngStats* stats)
{
    if (stats == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;
    *stats = gCracen.trng;
    return 0;
}

#endif /* WOLFSSL_NRF54L_CRACEN && !WOLFSSL_CRACEN_HOST_TEST */
