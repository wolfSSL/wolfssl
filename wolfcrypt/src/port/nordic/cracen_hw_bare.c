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
#ifndef WOLFSSL_CRACEN_PK_TIMEOUT
    #define WOLFSSL_CRACEN_PK_TIMEOUT   0x4000000UL
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
    byte               pkReady;
    word32             trngPrevStatus;
    word32             pkSlotSz;
    word32             pkMaxOpSz;
    word32             pkHwCfg;
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
            ~(WC_CRACEN_ENABLE_CRYPTOMASTER | WC_CRACEN_ENABLE_RNG |
              WC_CRACEN_ENABLE_PKEIKG));
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


/* Public key engine ---------------------------------------------------------*/

#ifdef WOLFSSL_CRACEN_PK

#if defined(WOLFSSL_CRACEN_PK_CM) && defined(WOLFSSL_CRACEN_TRNG)
    #define WC_CRACEN_PK_HAVE_CM
#endif

#define PK_WR(off, v)  CM_WR((off), (v))
#define PK_RD(off)     CM_RD(off)

#define WC_ED25519_SZ  32

static int pk_wait_idle(void)
{
    word32 timeout = WOLFSSL_CRACEN_PK_TIMEOUT;

    while ((PK_RD(WC_PK_STATUS) & WC_PK_STATUS_BUSY) != 0) {
        if (--timeout == 0)
            return WC_HW_E;
    }
    return 0;
}

/* The operand RAM is accessed in whole aligned words. src == NULL clears. */
static void pkmem_fill(word32 addr, const byte* src, word32 sz)
{
    while (sz > 0) {
        word32 base = addr & ~3UL;
        word32 off  = addr & 3UL;
        word32 n    = 4UL - off;
        word32 w    = 0;
        word32 i;

        if (n > sz)
            n = sz;
        if (n != 4) {
            w = cracen_rd(base, 0);
            for (i = 0; i < n; i++)
                w &= ~(0xFFUL << (8 * (off + i)));
        }
        if (src != NULL) {
            for (i = 0; i < n; i++)
                w |= (word32)src[i] << (8 * (off + i));
            src += n;
        }
        cracen_wr(base, 0, w);
        addr += n;
        sz   -= n;
    }
}

static void pkmem_read(word32 addr, byte* dst, word32 sz)
{
    while (sz > 0) {
        word32 base = addr & ~3UL;
        word32 off  = addr & 3UL;
        word32 n    = 4UL - off;
        word32 w    = cracen_rd(base, 0);
        word32 i;

        if (n > sz)
            n = sz;
        for (i = 0; i < n; i++)
            dst[i] = (byte)(w >> (8 * (off + i)));
        dst  += n;
        addr += n;
        sz   -= n;
    }
}

/* Big-endian operands end at the end of their slot, little-endian ones start
 * at its beginning. */
static WC_INLINE word32 pk_operand(int slot, word32 opsz, int be)
{
    word32 a = WC_PK_DATA_RAM + (word32)slot * gCracen.pkSlotSz;
    return be ? a + gCracen.pkSlotSz - opsz : a;
}

/* Place a sz-byte value as an opsz-byte operand, zero padded. */
static void pk_put(int slot, word32 opsz, int be, const byte* v, word32 sz)
{
    word32 a = pk_operand(slot, opsz, be);

    if (be) {
        pkmem_fill(a, NULL, opsz - sz);
        pkmem_fill(a + opsz - sz, v, sz);
    }
    else {
        pkmem_fill(a, v, sz);
        pkmem_fill(a + sz, NULL, opsz - sz);
    }
}

static WC_INLINE void pk_get(int slot, word32 opsz, int be, byte* out)
{
    pkmem_read(pk_operand(slot, opsz, be), out, opsz);
}

static WC_INLINE void pk_clear(int slot, word32 opsz, int be)
{
    pkmem_fill(pk_operand(slot, opsz, be), NULL, opsz);
}

static int pk_is_zero(const byte* p, word32 sz)
{
    byte acc = 0;
    while (sz-- > 0)
        acc |= *p++;
    return acc == 0;
}

static int pk_map_status(word32 status)
{
    word32 err = status & WC_PK_STATUS_ERR_MASK;

    if (err == 0)
        return 0;
    if (err & WC_PK_STATUS_NOT_IMPLEMENTED)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    if (err & WC_PK_STATUS_INVALID_SIGNATURE)
        return SIG_VERIFY_E;
    if (err & WC_PK_STATUS_NOT_ON_CURVE)
        return IS_POINT_E;
    if (err & WC_PK_STATUS_BAD_ORDER)
        return ECC_INF_E;
    if (err & WC_PK_STATUS_OUT_OF_RANGE)
        return ECC_OUT_OF_RANGE_E;
    if (err & (WC_PK_STATUS_INVALID_MODULUS | WC_PK_STATUS_NOT_INVERTIBLE |
               WC_PK_STATUS_COMPOSITE | WC_PK_STATUS_NOT_QUAD_RESIDUE))
        return MP_VAL;
    return WC_HW_E;
}

/* A negative verdict from the engine, as opposed to a failure to run. */
static int pk_is_verdict(int ret)
{
    return ret == SIG_VERIFY_E || ret == IS_POINT_E || ret == ECC_INF_E ||
           ret == ECC_OUT_OF_RANGE_E || ret == MP_VAL;
}

/* Countermeasures need a TRNG blinding factor and 64 bits of head room. */
static int pk_cm_ok(int cm, word32 opsz)
{
#ifdef WC_CRACEN_PK_HAVE_CM
    return cm != 0 &&
        (gCracen.pkHwCfg & WC_PK_HWCONFIG_CM_DISABLED) == 0 &&
        (gCracen.info.engines & WC_CM_HW_BA431_NDRNG) != 0 &&
        opsz + 8 <= gCracen.pkSlotSz;
#else
    (void)cm;
    (void)opsz;
    return 0;
#endif
}

#ifdef WC_CRACEN_PK_HAVE_CM
/* Odd 62-bit blinding factor in the last slot. */
static int pk_blind(word32 opsz, int be)
{
    byte f[8];
    int  ret = trng_read(f, sizeof(f));

    if (ret == 0) {
        if (be) {
            f[0] &= 0x3F;
            f[0] |= 0x20;
            f[7] |= 1;
        }
        else {
            f[0] |= 1;
            f[7] &= 0x3F;
            f[7] |= 0x20;
        }
        pk_put(WC_PK_SLOT_BLIND, opsz, be, f, sizeof(f));
    }
    ForceZero(f, sizeof(f));
    return ret;
}
#endif

/* Write the command register; the operand placement and byte order it
 * selects apply to every RAM access that follows. */
static int pk_begin(word32 cmd, word32 opsz)
{
    int ret;

    if (!gCracen.pkReady)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    if (opsz == 0 || opsz > gCracen.pkMaxOpSz)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    ret = pk_wait_idle();
    if (ret == 0)
        PK_WR(WC_PK_COMMAND, cmd | WC_PK_CMD_OPSIZE(opsz));
    return ret;
}

/* Start the operation and wait for it. ptrA != 0 selects the operand
 * pointer set (A, B = slot 8, C = slot 10) for operations that use it. */
static int pk_run(int ptrA)
{
    word32 timeout = WOLFSSL_CRACEN_PK_TIMEOUT;
    word32 status;

    if (ptrA != 0) {
        PK_WR(WC_PK_POINTERS,
            WC_PK_POINTERS_SET(ptrA, WC_PK_SLOT_PTR_B, WC_PK_SLOT_PTR_C));
    }
    CRACEN_DSB();
    PK_WR(WC_PK_CONTROL, WC_PK_CONTROL_START | WC_PK_CONTROL_CLEARIRQ);
    do {
        status = PK_RD(WC_PK_STATUS);
        if (--timeout == 0)
            return WC_HW_E;
    } while ((status & WC_PK_STATUS_BUSY) != 0);

    return pk_map_status(status);
}

static int pk_curve_accel(word32 selCurve)
{
    word32 bit;

    switch (selCurve) {
        case WC_PK_CURVE_P256:    bit = WC_PK_HWCONFIG_P256;   break;
        case WC_PK_CURVE_P384:    bit = WC_PK_HWCONFIG_P384;   break;
        case WC_PK_CURVE_P521:    bit = WC_PK_HWCONFIG_P521;   break;
        case WC_PK_CURVE_P192:    bit = WC_PK_HWCONFIG_P192;   break;
        case WC_PK_CURVE_X25519:
        case WC_PK_CURVE_ED25519: bit = WC_PK_HWCONFIG_X25519; break;
        default:                  return 0;
    }
    return (gCracen.pkHwCfg & bit) != 0;
}

/* Command, curve parameters (for a curve the engine does not hold itself)
 * and blinding factor for a short Weierstrass curve operation. */
static int pk_ecc_begin(const wc_CracenEcCurve* c, word32 op, word32 flags,
    int cm)
{
    word32 sel = c->selCurve;
    word32 cmd;
    int    ret;

    if (c->sz > WC_CRACEN_ECC_MAX_SZ)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    if (sel != 0 && !pk_curve_accel(sel))
        sel = 0;
    if (sel == 0 && (c->p == NULL || c->n == NULL || c->gx == NULL ||
            c->gy == NULL || c->a == NULL || c->b == NULL)) {
        return BAD_FUNC_ARG;
    }

    cmd = op | WC_PK_CMD_BIGENDIAN | WC_PK_CMD_SELCURVE(sel) | flags;
    cm  = pk_cm_ok(cm, c->sz);
    if (cm)
        cmd |= WC_PK_CMD_RANDKE | WC_PK_CMD_RANDPROJ;

    ret = pk_begin(cmd, c->sz);
    if (ret == 0 && sel == 0) {
        pk_put(WC_PK_SLOT_ECC_P,  c->sz, 1, c->p,  c->sz);
        pk_put(WC_PK_SLOT_ECC_N,  c->sz, 1, c->n,  c->sz);
        pk_put(WC_PK_SLOT_ECC_GX, c->sz, 1, c->gx, c->sz);
        pk_put(WC_PK_SLOT_ECC_GY, c->sz, 1, c->gy, c->sz);
        pk_put(WC_PK_SLOT_ECC_A,  c->sz, 1, c->a,  c->sz);
        pk_put(WC_PK_SLOT_ECC_B,  c->sz, 1, c->b,  c->sz);
    }
#ifdef WC_CRACEN_PK_HAVE_CM
    if (ret == 0 && cm)
        ret = pk_blind(c->sz, 1);
#endif
    return ret;
}

int wc_CracenHw_PkLoadMicrocode(const word32* ucode, word32 words)
{
    volatile word32* dst = (volatile word32*)(wc_ptr_t)WC_PK_UCODE_RAM;
    word32 cfg   = 0;
    word32 maxOp = 0;
    word32 i;
    int    ret;

    if (ucode == NULL || words == 0 || words * 4UL > WC_PK_UCODE_MAX_BYTES)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;

    gCracen.pkReady = 0;
    CR_WR(WC_CRACEN_ENABLE, CR_RD(WC_CRACEN_ENABLE) | WC_CRACEN_ENABLE_PKEIKG);
    CRACEN_DSB();
    /* the engine zeroises its operand RAM after enable */
    ret = pk_wait_idle();
    if (ret == 0) {
        cfg   = PK_RD(WC_PK_HWCONFIG);
        maxOp = WC_PK_HWCONFIG_MAXOPSZ(cfg);
        if (maxOp < WC_ED25519_SZ)
            ret = WC_HW_E;
    }
    if (ret == 0) {
        gCracen.pkHwCfg    = cfg;
        gCracen.info.pkCfg = cfg;
        gCracen.pkMaxOpSz  = maxOp;
        gCracen.pkSlotSz   = (maxOp > 0x200UL) ? 0x400UL : 0x200UL;
        for (i = 0; i < words; i++)
            dst[i] = ucode[i];
        CRACEN_DSB();
        gCracen.pkReady = 1;
    }

    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_PkReady(void)
{
    return gCracen.init && gCracen.pkReady;
}

int wc_CracenHw_EccPtMul(const wc_CracenEcCurve* c, const byte* k,
    const byte* px, const byte* py, byte* rx, byte* ry, int cm)
{
    int ret;

    if (c == NULL || k == NULL || px == NULL || py == NULL || rx == NULL ||
            ry == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!gCracen.init)
        return BAD_STATE_E;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ecc_begin(c, WC_PK_OP_ECC_PTMUL, 0, cm);
    if (ret == 0) {
        pk_put(WC_PK_SLOT_PTMUL_K,  c->sz, 1, k,  c->sz);
        pk_put(WC_PK_SLOT_PTMUL_PX, c->sz, 1, px, c->sz);
        pk_put(WC_PK_SLOT_PTMUL_PY, c->sz, 1, py, c->sz);
        ret = pk_run(WC_PK_SLOT_PTMUL_PX);
        if (ret == 0) {
            pk_get(WC_PK_SLOT_PTMUL_RX, c->sz, 1, rx);
            pk_get(WC_PK_SLOT_PTMUL_RY, c->sz, 1, ry);
            if (pk_is_zero(rx, c->sz) && pk_is_zero(ry, c->sz))
                ret = ECC_INF_E;
        }
        pk_clear(WC_PK_SLOT_PTMUL_K,  c->sz, 1);
        pk_clear(WC_PK_SLOT_PTMUL_RX, c->sz, 1);
        pk_clear(WC_PK_SLOT_PTMUL_RY, c->sz, 1);
        pk_clear(WC_PK_SLOT_BLIND,    c->sz, 1);
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_EccPtOnCurve(const wc_CracenEcCurve* c, const byte* px,
    const byte* py)
{
    int ret;

    if (c == NULL || px == NULL || py == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ecc_begin(c, WC_PK_OP_ECC_PTONCURVE, 0, 0);
    if (ret == 0) {
        pk_put(WC_PK_SLOT_PTMUL_PX, c->sz, 1, px, c->sz);
        pk_put(WC_PK_SLOT_PTMUL_PY, c->sz, 1, py, c->sz);
        ret = pk_run(WC_PK_SLOT_PTMUL_PX);
        if (pk_is_verdict(ret) && ret != ECC_OUT_OF_RANGE_E)
            ret = IS_POINT_E;
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_EccPtOrder(const wc_CracenEcCurve* c, const byte* px,
    const byte* py)
{
    int ret;

    if (c == NULL || px == NULL || py == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ecc_begin(c, WC_PK_OP_ECC_CHECK_ORDER, 0, 0);
    if (ret == 0) {
        pk_put(WC_PK_SLOT_PTR_A,     c->sz, 1, px, c->sz);
        pk_put(WC_PK_SLOT_PTR_A + 1, c->sz, 1, py, c->sz);
        ret = pk_run(WC_PK_SLOT_PTR_A);
        if (pk_is_verdict(ret))
            ret = ECC_INF_E;
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_EcdsaSign(const wc_CracenEcCurve* c, const byte* d,
    const byte* k, const byte* h, byte* r, byte* s)
{
    int ret;

    if (c == NULL || d == NULL || k == NULL || h == NULL || r == NULL ||
            s == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!gCracen.init)
        return BAD_STATE_E;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ecc_begin(c, WC_PK_OP_ECDSA_SIGN, 0, 1);
    if (ret == 0) {
        pk_put(WC_PK_SLOT_ECDSA_D, c->sz, 1, d, c->sz);
        pk_put(WC_PK_SLOT_ECDSA_K, c->sz, 1, k, c->sz);
        pk_put(WC_PK_SLOT_ECDSA_H, c->sz, 1, h, c->sz);
        ret = pk_run(0);
        if (ret == 0) {
            pk_get(WC_PK_SLOT_ECDSA_R, c->sz, 1, r);
            pk_get(WC_PK_SLOT_ECDSA_S, c->sz, 1, s);
            if (pk_is_zero(r, c->sz) || pk_is_zero(s, c->sz))
                ret = MP_ZERO_E;
        }
        pk_clear(WC_PK_SLOT_ECDSA_D, c->sz, 1);
        pk_clear(WC_PK_SLOT_ECDSA_K, c->sz, 1);
        pk_clear(WC_PK_SLOT_BLIND,   c->sz, 1);
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_EcdsaVerify(const wc_CracenEcCurve* c, const byte* qx,
    const byte* qy, const byte* r, const byte* s, const byte* h, int* res)
{
    int ret;

    if (c == NULL || qx == NULL || qy == NULL || r == NULL || s == NULL ||
            h == NULL || res == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!gCracen.init)
        return BAD_STATE_E;
    *res = 0;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ecc_begin(c, WC_PK_OP_ECDSA_VERIFY, 0, 0);
    if (ret == 0) {
        pk_put(WC_PK_SLOT_ECDSA_QX, c->sz, 1, qx, c->sz);
        pk_put(WC_PK_SLOT_ECDSA_QY, c->sz, 1, qy, c->sz);
        pk_put(WC_PK_SLOT_ECDSA_R,  c->sz, 1, r,  c->sz);
        pk_put(WC_PK_SLOT_ECDSA_S,  c->sz, 1, s,  c->sz);
        pk_put(WC_PK_SLOT_ECDSA_H,  c->sz, 1, h,  c->sz);
        ret = pk_run(0);
        if (ret == 0)
            *res = 1;
        else if (pk_is_verdict(ret))
            ret = 0;
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_ModExp(const byte* base, word32 baseSz, const byte* exp,
    word32 expSz, const byte* mod, word32 modSz, byte* out, int cm)
{
    word32 cmd = WC_PK_OP_MODEXP | WC_PK_CMD_BIGENDIAN | WC_PK_CMD_CALCR2;
    int    ret;

    if (base == NULL || exp == NULL || mod == NULL || out == NULL)
        return BAD_FUNC_ARG;
    if (modSz == 0 || baseSz > modSz || expSz > modSz)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    if (!gCracen.init)
        return BAD_STATE_E;

    cm = pk_cm_ok(cm, modSz);
    if (cm)
        cmd |= WC_PK_CMD_RANDMOD;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_begin(cmd, modSz);
    if (ret == 0) {
        pk_put(WC_PK_SLOT_MODEXP_M,   modSz, 1, mod,  modSz);
        pk_put(WC_PK_SLOT_MODEXP_IN,  modSz, 1, base, baseSz);
        pk_put(WC_PK_SLOT_MODEXP_EXP, modSz, 1, exp,  expSz);
    #ifdef WC_CRACEN_PK_HAVE_CM
        if (cm)
            ret = pk_blind(modSz, 1);
    #endif
        if (ret == 0)
            ret = pk_run(WC_PK_SLOT_MODEXP_IN);
        if (ret == 0)
            pk_get(WC_PK_SLOT_MODEXP_OUT, modSz, 1, out);
        pk_clear(WC_PK_SLOT_MODEXP_IN,  modSz, 1);
        pk_clear(WC_PK_SLOT_MODEXP_EXP, modSz, 1);
        pk_clear(WC_PK_SLOT_MODEXP_OUT, modSz, 1);
        pk_clear(WC_PK_SLOT_BLIND,      modSz, 1);
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_RsaCrt(const byte* in, word32 inSz, const byte* p, word32 pSz,
    const byte* q, word32 qSz, const byte* dP, word32 dPSz, const byte* dQ,
    word32 dQSz, const byte* qInv, word32 qInvSz, byte* out, word32 outSz,
    int cm)
{
    word32 cmd  = WC_PK_OP_RSA_CRT | WC_PK_CMD_BIGENDIAN;
    word32 opsz = outSz;
    int    ret;

    if (in == NULL || p == NULL || q == NULL || dP == NULL || dQ == NULL ||
            qInv == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (pSz + qSz > opsz)
        opsz = pSz + qSz;
    if (outSz == 0 || inSz > outSz || dPSz > opsz || dQSz > opsz ||
            qInvSz > opsz) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (!gCracen.init)
        return BAD_STATE_E;

    cm = pk_cm_ok(cm, opsz);
    if (cm)
        cmd |= WC_PK_CMD_RANDKE | WC_PK_CMD_RANDMOD;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_begin(cmd, opsz);
    if (ret == 0) {
        pk_put(WC_PK_SLOT_CRT_IN,   opsz, 1, in,   inSz);
        pk_put(WC_PK_SLOT_CRT_P,    opsz, 1, p,    pSz);
        pk_put(WC_PK_SLOT_CRT_Q,    opsz, 1, q,    qSz);
        pk_put(WC_PK_SLOT_CRT_DP,   opsz, 1, dP,   dPSz);
        pk_put(WC_PK_SLOT_CRT_DQ,   opsz, 1, dQ,   dQSz);
        pk_put(WC_PK_SLOT_CRT_QINV, opsz, 1, qInv, qInvSz);
    #ifdef WC_CRACEN_PK_HAVE_CM
        if (cm)
            ret = pk_blind(opsz, 1);
    #endif
        if (ret == 0)
            ret = pk_run(0);
        if (ret == 0) {
            pkmem_read(pk_operand(WC_PK_SLOT_CRT_OUT, opsz, 1) + opsz - outSz,
                out, outSz);
        }
        pk_clear(WC_PK_SLOT_CRT_IN,   opsz, 1);
        pk_clear(WC_PK_SLOT_CRT_P,    opsz, 1);
        pk_clear(WC_PK_SLOT_CRT_Q,    opsz, 1);
        pk_clear(WC_PK_SLOT_CRT_OUT,  opsz, 1);
        pk_clear(WC_PK_SLOT_CRT_DP,   opsz, 1);
        pk_clear(WC_PK_SLOT_CRT_DQ,   opsz, 1);
        pk_clear(WC_PK_SLOT_CRT_QINV, opsz, 1);
        pk_clear(WC_PK_SLOT_BLIND,    opsz, 1);
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_X25519(const byte* k, const byte* u, byte* out)
{
    byte kk[WC_ED25519_SZ];
    byte uu[WC_ED25519_SZ];
    int  ret;

    if (k == NULL || u == NULL || out == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;
    if (!pk_curve_accel(WC_PK_CURVE_X25519))
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    XMEMCPY(kk, k, sizeof(kk));
    XMEMCPY(uu, u, sizeof(uu));
    kk[0]  &= 0xF8;
    kk[31]  = (byte)((kk[31] | 0x40) & 0x7F);
    uu[31] &= 0x7F;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = pk_begin(WC_PK_OP_MG_PTMUL |
            WC_PK_CMD_SELCURVE(WC_PK_CURVE_X25519), WC_ED25519_SZ);
        if (ret == 0) {
            pk_put(WC_PK_SLOT_MG_P, WC_ED25519_SZ, 0, uu, WC_ED25519_SZ);
            pk_put(WC_PK_SLOT_MG_K, WC_ED25519_SZ, 0, kk, WC_ED25519_SZ);
            ret = pk_run(WC_PK_SLOT_MG_P);
            if (ret == 0)
                pk_get(WC_PK_SLOT_MG_R, WC_ED25519_SZ, 0, out);
            pk_clear(WC_PK_SLOT_MG_K, WC_ED25519_SZ, 0);
            pk_clear(WC_PK_SLOT_MG_R, WC_ED25519_SZ, 0);
        }
        wolfSSL_CryptHwMutexUnLock();
    }
    ForceZero(kk, sizeof(kk));
    return ret;
}

static int pk_ed25519_begin(word32 op, word32 flags)
{
    if (!pk_curve_accel(WC_PK_CURVE_ED25519))
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    return pk_begin(op | WC_PK_CMD_SELCURVE(WC_PK_CURVE_ED25519) | flags,
        WC_ED25519_SZ);
}

/* A 64-byte scalar occupies two consecutive slots, low half first. */
static void pk_put_dbl(int slot, const byte* v64)
{
    pk_put(slot,     WC_ED25519_SZ, 0, v64,                WC_ED25519_SZ);
    pk_put(slot + 1, WC_ED25519_SZ, 0, v64 + WC_ED25519_SZ, WC_ED25519_SZ);
}

static void pk_clear_dbl(int slot)
{
    pk_clear(slot,     WC_ED25519_SZ, 0);
    pk_clear(slot + 1, WC_ED25519_SZ, 0);
}

int wc_CracenHw_Ed25519PtMul(const byte* scalar64, byte* pt32)
{
    byte x[WC_ED25519_SZ];
    int  ret;

    if (scalar64 == NULL || pt32 == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ed25519_begin(WC_PK_OP_EDDSA_PTMUL, 0);
    if (ret == 0) {
        pk_put_dbl(WC_PK_SLOT_EDDSA_R0, scalar64);
        ret = pk_run(0);
        if (ret == 0) {
            pk_get(WC_PK_SLOT_EDDSA_RX, WC_ED25519_SZ, 0, x);
            pk_get(WC_PK_SLOT_EDDSA_RY, WC_ED25519_SZ, 0, pt32);
            pt32[31] |= (byte)((x[0] & 1) << 7);
        }
        pk_clear_dbl(WC_PK_SLOT_EDDSA_R0);
        pk_clear(WC_PK_SLOT_EDDSA_RX, WC_ED25519_SZ, 0);
        pk_clear(WC_PK_SLOT_EDDSA_RY, WC_ED25519_SZ, 0);
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_Ed25519Sign(const byte* k64, const byte* r64, const byte* s32,
    byte* sigS32)
{
    int ret;

    if (k64 == NULL || r64 == NULL || s32 == NULL || sigS32 == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ed25519_begin(WC_PK_OP_EDDSA_SIGN, 0);
    if (ret == 0) {
        pk_put_dbl(WC_PK_SLOT_EDDSA_K0, k64);
        pk_put_dbl(WC_PK_SLOT_EDDSA_R0, r64);
        pk_put(WC_PK_SLOT_EDDSA_S, WC_ED25519_SZ, 0, s32, WC_ED25519_SZ);
        ret = pk_run(0);
        if (ret == 0)
            pk_get(WC_PK_SLOT_EDDSA_SIGS, WC_ED25519_SZ, 0, sigS32);
        pk_clear_dbl(WC_PK_SLOT_EDDSA_K0);
        pk_clear_dbl(WC_PK_SLOT_EDDSA_R0);
        pk_clear(WC_PK_SLOT_EDDSA_SIGS, WC_ED25519_SZ, 0);
        pk_clear(WC_PK_SLOT_EDDSA_S,    WC_ED25519_SZ, 0);
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_CracenHw_Ed25519Verify(const byte* k64, const byte* a32,
    const byte* sigS32, const byte* r32)
{
    byte   y[WC_ED25519_SZ];
    word32 flags = 0;
    int    ret;

    if (k64 == NULL || a32 == NULL || sigS32 == NULL || r32 == NULL)
        return BAD_FUNC_ARG;
    if (!gCracen.init)
        return BAD_STATE_E;

    /* the sign bits of the x coordinates travel in the command flags */
    if (a32[31] & 0x80)
        flags |= WC_PK_CMD_FLAGA;
    if (r32[31] & 0x80)
        flags |= WC_PK_CMD_FLAGB;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0)
        return ret;
    ret = pk_ed25519_begin(WC_PK_OP_EDDSA_VERIFY, flags);
    if (ret == 0) {
        pk_put_dbl(WC_PK_SLOT_EDDSA_K0, k64);
        XMEMCPY(y, a32, sizeof(y));
        y[31] &= 0x7F;
        pk_put(WC_PK_SLOT_EDDSA_AY, WC_ED25519_SZ, 0, y, WC_ED25519_SZ);
        pk_put(WC_PK_SLOT_EDDSA_SIGS, WC_ED25519_SZ, 0, sigS32, WC_ED25519_SZ);
        XMEMCPY(y, r32, sizeof(y));
        y[31] &= 0x7F;
        pk_put(WC_PK_SLOT_EDDSA_RY, WC_ED25519_SZ, 0, y, WC_ED25519_SZ);
        ret = pk_run(0);
        if (pk_is_verdict(ret))
            ret = SIG_VERIFY_E;
    }
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

#endif /* WOLFSSL_CRACEN_PK */

#endif /* WOLFSSL_NRF54L_CRACEN && !WOLFSSL_CRACEN_HOST_TEST */
