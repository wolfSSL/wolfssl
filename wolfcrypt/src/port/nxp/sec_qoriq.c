/* sec_qoriq.c
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
 * Core of the QorIQ SEC driver: bring-up, job ring management, descriptor
 * assembly and submission. Platform specifics live behind the seam declared
 * at the bottom of sec_qoriq.h.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SEC_QORIQ

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* The one device this driver manages; a second would need its own ring. */
static SecQoriqDev secQoriqDev;

/* Every job's descriptor is copied here before submission, so the engine is
 * never handed the address of a caller's stack frame: if a job hangs and
 * survives every reset, the memory it can still read has static lifetime.
 * One job is in flight at a time (the hardware mutex), so one slot
 * suffices. */
static word32 secDescStage[SEC_QORIQ_DESC_MAX_WORDS]
#if defined(__GNUC__)
    __attribute__((aligned(64)))
#endif
    ;

/******************************************************************************
  Register access. CCSR registers are big endian and so is the CPU, so no
  swap is needed; the swap path exists for a little endian QorIQ host.
  ****************************************************************************/

#ifdef WOLFSSL_SEC_QORIQ_SWAP_REGS
    #define SEC_SWAP32(x) \
        ((((x) & 0x000000FFU) << 24) | (((x) & 0x0000FF00U) <<  8) | \
         (((x) & 0x00FF0000U) >>  8) | (((x) & 0xFF000000U) >> 24))
#else
    #define SEC_SWAP32(x) (x)
#endif

/* The simulated backend models the registers itself. */
#ifndef WOLFSSL_SEC_QORIQ_SIM
word32 wc_SecQoriqRead(const byte* base, word32 off)
{
    return SEC_SWAP32(*(volatile const word32*)(base + off));
}

void wc_SecQoriqWrite(byte* base, word32 off, word32 val)
{
    *(volatile word32*)(base + off) = SEC_SWAP32(val);
}
#endif /* !WOLFSSL_SEC_QORIQ_SIM */

#define secRead  wc_SecQoriqRead
#define secWrite wc_SecQoriqWrite

SecQoriqDev* wc_SecQoriqGetDev(void)
{
    if (secQoriqDev.initialized == 0) {
        return NULL;
    }
    return &secQoriqDev;
}

/******************************************************************************
  Descriptor assembly
  ****************************************************************************/

int wc_SecQoriqDescInit(SecQoriqDesc* desc)
{
    if (desc == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(desc, 0, sizeof(SecQoriqDesc));
    desc->desc[0] = SEC_QORIQ_CMD_HEAD;
    desc->idx = 1;
    desc->startIdx = 1;

    return 0;
}

int wc_SecQoriqDescAddWord(SecQoriqDesc* desc, word32 in)
{
    if (desc == NULL) {
        return BAD_FUNC_ARG;
    }
    if (desc->idx >= SEC_QORIQ_DESC_MAX_WORDS) {
        WOLFSSL_MSG("sec_qoriq: descriptor full");
        return BUFFER_E;
    }

    desc->desc[desc->idx++] = in;
    return 0;
}

/* Record one buffer and reserve the descriptor word for its address. The
 * word is filled in at submission, when the platform maps the buffer for
 * DMA; nothing appends a raw physical address. */
static int secDescRecordBuf(SecQoriqDesc* desc, const byte* buf, word32 bufSz,
    byte dir)
{
    if (desc->bufCnt >= SEC_QORIQ_DESC_MAX_BUFS) {
        WOLFSSL_MSG("sec_qoriq: descriptor references too many buffers");
        return BUFFER_E;
    }

    desc->bufs[desc->bufCnt].virt    = (void*)buf;
    desc->bufs[desc->bufCnt].sz      = bufSz;
    desc->bufs[desc->bufCnt].wordIdx = desc->idx;
    desc->bufs[desc->bufCnt].dir     = dir;
    desc->bufCnt++;

    return wc_SecQoriqDescAddWord(desc, 0);
}

/* Append a command word carrying a length, followed by the buffer address.
 * FIFO STORE and STORE commands are engine writes; everything else (KEY,
 * LOAD, FIFO LOAD) is an engine read. */
int wc_SecQoriqDescAddBuf(SecQoriqDesc* desc, word32 cmd, const byte* buf,
    word32 bufSz)
{
    word32 ctype;
    int ret;

    if (desc == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (bufSz > SEC_QORIQ_MAX_XFER_SZ) {
        WOLFSSL_MSG("sec_qoriq: buffer too large for a single command");
        return BUFFER_E;
    }

    ret = wc_SecQoriqDescAddWord(desc, cmd | bufSz);
    if (ret != 0) {
        return ret;
    }

    ctype = cmd & 0xF8000000U;
    return secDescRecordBuf(desc, buf, bufSz,
        (ctype == SEC_QORIQ_CMD_FIFO_S || ctype == SEC_QORIQ_CMD_STORE) ?
            SEC_QORIQ_DIR_OUT : SEC_QORIQ_DIR_IN);
}

/* Append a bare PDB pointer word. The protocol data block carries no
 * per-pointer command, so the direction comes from the caller. */
int wc_SecQoriqDescAddPdbPtr(SecQoriqDesc* desc, const byte* buf,
    word32 bufSz, int isOut)
{
    if (desc == NULL || buf == NULL || bufSz == 0) {
        return BAD_FUNC_ARG;
    }

    return secDescRecordBuf(desc, buf, bufSz,
        isOut ? SEC_QORIQ_DIR_OUT : SEC_QORIQ_DIR_IN);
}

/* Patch the header with the final length. Low 7 bits are the total word
 * count, bits 22:16 the index at which the job descriptor proper starts. */
static void secDescFinalize(SecQoriqDesc* desc)
{
    desc->desc[0] &= 0xFFFFFF80U;
    desc->desc[0] |= (desc->idx & 0x7FU) | ((desc->startIdx & 0x7FU) << 16);
}

/******************************************************************************
  Error decoding
  ****************************************************************************/

int wc_SecQoriqParseError(word32 status)
{
    word32 src = (status & SEC_QORIQ_SSRC_MASK) >> SEC_QORIQ_SSRC_SHIFT;

    if (status == 0) {
        return 0;
    }

    /* A CCB error with error id ICVCHK is the AEAD integrity check failing:
     * an authentication failure, not a hardware fault. */
    if (src == SEC_QORIQ_SSRC_CCB &&
            (status & SEC_QORIQ_CCBERR_ERRID_MASK) ==
                SEC_QORIQ_CCBERR_ERRID_ICV) {
        WOLFSSL_MSG("sec_qoriq: ICV check failed");
        return AES_GCM_AUTH_E;
    }

#ifdef DEBUG_WOLFSSL
    {
        const char* srcStr;

        switch (src) {
            case SEC_QORIQ_SSRC_CCB:     srcStr = "CCB";   break;
            case SEC_QORIQ_SSRC_JUMP:    srcStr = "jump halt, user"; break;
            case SEC_QORIQ_SSRC_DECO:    srcStr = "DECO";  break;
            case SEC_QORIQ_SSRC_QI:      srcStr = "queue interface"; break;
            case SEC_QORIQ_SSRC_JR:      srcStr = "job ring"; break;
            case SEC_QORIQ_SSRC_JUMP_CC: srcStr = "jump halt, condition";
                                         break;
            default:                     srcStr = "unknown"; break;
        }
        WOLFSSL_MSG_EX("sec_qoriq: job failed, status 0x%08x, source %s",
            status, srcStr);
    }
#endif

    return WC_HW_E;
}

/******************************************************************************
  Job submission
  ****************************************************************************/

/* One job ring, one descriptor in flight. Without this mutex two threads
 * racing through the callback overwrite each other's ring slot and
 * desynchronise the index mirrors. */
static int  secRunLocked(SecQoriqDev* dev, SecQoriqDesc* desc);
static int  secJrReset(SecQoriqDev* dev);
static void secRingsProgram(SecQoriqDev* dev);

int wc_SecQoriqRun(SecQoriqDev* dev, SecQoriqDesc* desc)
{
    return wc_SecQoriqRunEx(dev, desc, NULL);
}

int wc_SecQoriqRunEx(SecQoriqDev* dev, SecQoriqDesc* desc, word32* statusOut)
{
    int ret;

    if (dev == NULL || desc == NULL) {
        return BAD_FUNC_ARG;
    }

    if (statusOut != NULL) {
        *statusOut = 0;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    ret = secRunLocked(dev, desc);

    /* Read the status while still holding the lock: dev->lastStatus belongs
     * to whichever job retired most recently, which under concurrency is not
     * necessarily this one. */
    if (statusOut != NULL) {
        *statusOut = dev->lastStatus;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void wc_SecQoriqForceZeroDma(void* buf, word32 sz)
{
    if (buf == NULL || sz == 0) {
        return;
    }

    ForceZero(buf, sz);
    (void)wc_SecQoriqCacheFlush(buf, sz);
}

/* Halt the SEC's DMA engine. Controller wide, so it disturbs any other job
 * ring too; only used when a hung job already survived the ring reset and
 * the alternative is the engine writing through stale physical addresses. */
static int secDmaHalt(SecQoriqDev* dev)
{
    word32 waited = 0;
    word32 mcfgr = secRead(dev->regs, SEC_QORIQ_MCFGR);

    secWrite(dev->regs, SEC_QORIQ_MCFGR, mcfgr | SEC_QORIQ_MCFGR_DMA_RESET);
    while (secRead(dev->regs, SEC_QORIQ_MCFGR) & SEC_QORIQ_MCFGR_DMA_RESET) {
        if (++waited > SEC_QORIQ_POLL_MAX) {
            WOLFSSL_MSG("sec_qoriq: DMA reset did not complete");
            return WC_HW_E;
        }
        wc_SecQoriqCpuRelax();
    }

    return 0;
}

static int secRunLocked(SecQoriqDev* dev, SecQoriqDesc* desc)
{
    word64 descPhys;
    word64 phys;
    word32 descBytes;
    word32 status;
    word32 waited;
    word32 slot;
    word32 i;
    int ret;

    if (dev == NULL || desc == NULL) {
        return BAD_FUNC_ARG;
    }
    if (dev->initialized == 0) {
        return WC_HW_E;
    }

    /* The failure paths below return before a new status is read, so a
     * caller classifying the outcome must not see a stale one. */
    dev->lastStatus = 0;

    secDescFinalize(desc);
    descBytes = desc->idx * (word32)sizeof(word32);

    ret = wc_SecQoriqDmaJobBegin();
    if (ret != 0) {
        return ret;
    }

    /* Resolve every recorded buffer through the platform's DMA staging, and
     * patch its descriptor word. Only 32-bit pointer mode is supported, so
     * an address above 4 GB is refused rather than silently truncated. */
    for (i = 0; i < desc->bufCnt; i++) {
        phys = wc_SecQoriqDmaMapBuf(desc->bufs[i].virt, desc->bufs[i].sz,
            desc->bufs[i].dir);
        if (phys == 0 || (phys >> 32) != 0) {
            WOLFSSL_MSG("sec_qoriq: buffer not mappable for DMA");
            wc_SecQoriqDmaJobEnd(0, 0);
            return BAD_FUNC_ARG;
        }
        desc->desc[desc->bufs[i].wordIdx] = (word32)phys;
    }

    /* Stage the finalized descriptor in static storage, push it out to
     * memory, then map it like any other engine-read buffer. */
    XMEMCPY(secDescStage, desc->desc, descBytes);
    ret = wc_SecQoriqCacheFlush(secDescStage, descBytes);
    if (ret != 0) {
        wc_SecQoriqDmaJobEnd(0, 0);
        return ret;
    }
    descPhys = wc_SecQoriqDmaMapBuf(secDescStage, descBytes,
        SEC_QORIQ_DIR_IN);
    if (descPhys == 0 || (descPhys >> 32) != 0) {
        WOLFSSL_MSG("sec_qoriq: descriptor not reachable by the engine");
        wc_SecQoriqDmaJobEnd(0, 0);
        return BAD_FUNC_ARG;
    }

    /* Cannot occur while the mutex serialises one job at a time, so it is
     * treated as a hardware fault rather than a software fallback. */
    if (secRead(dev->jr, SEC_QORIQ_IRSA) == 0) {
        WOLFSSL_MSG("sec_qoriq: no room on the input ring");
        wc_SecQoriqDmaJobEnd(0, 0);
        return WC_HW_E;
    }

    dev->inRing[dev->inIdx] = (word32)descPhys;
    ret = wc_SecQoriqCacheFlush(&dev->inRing[dev->inIdx], sizeof(word32));
    if (ret != 0) {
        wc_SecQoriqDmaJobEnd(0, 0);
        return ret;
    }

    /* Publish the entry, then tell the engine one job was added. Everything
     * before this point provably never reached the engine; everything after
     * it may have, which is what the error contract in sec_qoriq.h hangs
     * on. */
    secWrite(dev->jr, SEC_QORIQ_IRJA, 1);
    dev->jobCount++;
    dev->inIdx = (dev->inIdx + 1) % SEC_QORIQ_RING_SIZE;

    waited = 0;
    while (secRead(dev->jr, SEC_QORIQ_ORSF) == 0) {
        if (++waited > SEC_QORIQ_POLL_MAX) {
            /* The engine may still hold this job's addresses (the static
             * descriptor stage, the rings, and - on a flat-mapped backend -
             * the caller's data buffers), and the index mirrors no longer
             * track it. Escalate until the DMA provably cannot touch
             * reusable memory again:
             * 1. ring reset - drains or halts this ring; device stays up.
             * 2. controller DMA reset - halts every ring's DMA; the device
             *    is dead but memory is safe to reuse.
             * 3. neither completed - the engine may still master the bus,
             *    so poison the device and retire everything driver-owned it
             *    could reach: wc_SecQoriqFree() leaks it deliberately, and
             *    a staged backend's arena is abandoned via JobEnd. On a
             *    flat-mapped backend the caller's own buffers remain the
             *    one residual risk only a board reset removes. */
            WOLFSSL_MSG("sec_qoriq: timed out waiting for job completion");
            if (secJrReset(dev) == 0) {
                secRingsProgram(dev);
            }
            else if (secDmaHalt(dev) == 0) {
                dev->initialized = 0;
            }
            else {
                dev->initialized = 0;
                dev->quiesceFailed = 1;
            }
            wc_SecQoriqDmaJobEnd(0, dev->quiesceFailed);
            return WC_HW_E;
        }
        wc_SecQoriqCpuRelax();
    }

    /* Output entries are two words wide: {descriptor address, status}. */
    slot = dev->outIdx * 2;

    ret = wc_SecQoriqCacheInval(&dev->outRing[slot], 2 * sizeof(word32));
    if (ret != 0) {
        wc_SecQoriqDmaJobEnd(0, 0);
        return ret;
    }

    /* Confirm the engine retired our descriptor before trusting its
     * status. */
    if (dev->outRing[slot] != (word32)descPhys) {
        WOLFSSL_MSG("sec_qoriq: output ring returned an unexpected job");
        secWrite(dev->jr, SEC_QORIQ_ORJR, 1);
        dev->outIdx = (dev->outIdx + 1) % SEC_QORIQ_RING_SIZE;
        wc_SecQoriqDmaJobEnd(0, 0);
        return WC_HW_E;
    }
    status = dev->outRing[slot + 1];
    dev->lastStatus = status;

    /* Release the slot back to the engine. */
    secWrite(dev->jr, SEC_QORIQ_ORJR, 1);
    dev->outIdx = (dev->outIdx + 1) % SEC_QORIQ_RING_SIZE;

    ret = wc_SecQoriqParseError(status);

    /* Copy engine output back to the callers only on a clean job; staging
     * memory is scrubbed and reclaimed either way. */
    wc_SecQoriqDmaJobEnd(ret == 0, 0);

    return ret;
}

/******************************************************************************
  Bring-up
  ****************************************************************************/

/* Reset the job ring; the engine clears JRCR[RESET] once drained. */
static int secJrReset(SecQoriqDev* dev)
{
    word32 waited = 0;

    secWrite(dev->jr, SEC_QORIQ_JRCR, SEC_QORIQ_JRCR_RESET);
    while (secRead(dev->jr, SEC_QORIQ_JRCR) & SEC_QORIQ_JRCR_RESET) {
        if (++waited > SEC_QORIQ_POLL_MAX) {
            WOLFSSL_MSG("sec_qoriq: job ring reset did not complete");
            return WC_HW_E;
        }
        wc_SecQoriqCpuRelax();
    }

    /* Clear any latched interrupt status left over from a previous owner. */
    secWrite(dev->jr, SEC_QORIQ_JRINT, secRead(dev->jr, SEC_QORIQ_JRINT));

    /* The engine restarts at slot 0 after a ring reset, so our mirrors do
     * too. */
    dev->inIdx = 0;
    dev->outIdx = 0;

    return 0;
}

static int secRingsAlloc(SecQoriqDev* dev)
{
    word32 inSz  = SEC_QORIQ_RING_SIZE * (word32)sizeof(word32);
    word32 outSz = SEC_QORIQ_RING_SIZE * 2 * (word32)sizeof(word32);

    dev->inRing = (word32*)wc_SecQoriqDmaAlloc(inSz, &dev->inRingPhys);
    if (dev->inRing == NULL) {
        return MEMORY_E;
    }

    dev->outRing = (word32*)wc_SecQoriqDmaAlloc(outSz, &dev->outRingPhys);
    if (dev->outRing == NULL) {
        wc_SecQoriqDmaFree(dev->inRing, dev->inRingPhys, inSz);
        dev->inRing = NULL;
        return MEMORY_E;
    }

    if ((dev->inRingPhys >> 32) != 0 || (dev->outRingPhys >> 32) != 0) {
        WOLFSSL_MSG("sec_qoriq: rings allocated above 4GB");
        return MEMORY_E;
    }

    XMEMSET(dev->inRing, 0, inSz);
    XMEMSET(dev->outRing, 0, outSz);

    if (wc_SecQoriqCacheFlush(dev->inRing, inSz) != 0 ||
        wc_SecQoriqCacheFlush(dev->outRing, outSz) != 0) {
        return WC_HW_E;
    }

    return 0;
}

/* Newest first: the bare-metal backend is a bump allocator that can only
 * rewind its most recent allocation. */
static void secRingsFree(SecQoriqDev* dev)
{
    if (dev->outRing != NULL) {
        wc_SecQoriqDmaFree(dev->outRing, dev->outRingPhys,
            SEC_QORIQ_RING_SIZE * 2 * (word32)sizeof(word32));
        dev->outRing = NULL;
    }
    if (dev->inRing != NULL) {
        wc_SecQoriqDmaFree(dev->inRing, dev->inRingPhys,
            SEC_QORIQ_RING_SIZE * (word32)sizeof(word32));
        dev->inRing = NULL;
    }
}

/* The base address registers are 64-bit even in 32-bit pointer mode. */
static void secRingsProgram(SecQoriqDev* dev)
{
    secWrite(dev->jr, SEC_QORIQ_IRBA_MS, (word32)(dev->inRingPhys >> 32));
    secWrite(dev->jr, SEC_QORIQ_IRBA_LS, (word32)dev->inRingPhys);
    secWrite(dev->jr, SEC_QORIQ_IRS, SEC_QORIQ_RING_SIZE);

    secWrite(dev->jr, SEC_QORIQ_ORBA_MS, (word32)(dev->outRingPhys >> 32));
    secWrite(dev->jr, SEC_QORIQ_ORBA_LS, (word32)dev->outRingPhys);
    secWrite(dev->jr, SEC_QORIQ_ORS, SEC_QORIQ_RING_SIZE);
}

int wc_SecQoriqInit(void)
{
    SecQoriqDev* dev = &secQoriqDev;
    word32 svr = 0;
    word32 mcfgr, scfgr, chanumMs;
    int ret;

    if (dev->initialized) {
        return 0;
    }

    /* After a failed quiesce everything the wedged engine could reach was
     * leaked (rings, mappings, a staged backend's arena) and the pointers
     * are cleared, never freed, so re-initialisation cannot hand the engine
     * fresh memory it already references. The ring reset below then probes
     * whether the engine actually recovered; if it is still wedged the
     * bring-up fails cleanly. */
    XMEMSET(dev, 0, sizeof(SecQoriqDev));
    dev->jrIndex = SEC_QORIQ_JR_INDEX;

    /* A part without the engine has no SEC block, and reading its address
     * space is not guaranteed to fault cleanly. */
    ret = wc_SecQoriqGetSvr(&svr);
    if (ret != 0) {
        return ret;
    }
    if ((svr & SEC_QORIQ_SVR_E_BIT) == 0) {
        WOLFSSL_MSG("sec_qoriq: part has no security engine (not an E SKU)");
        return NOT_COMPILED_IN;
    }

    ret = wc_SecQoriqMapRegs(&dev->regs);
    if (ret != 0) {
        return ret;
    }
    dev->jr = dev->regs + SEC_QORIQ_JR_OFFSET(dev->jrIndex);

    /* Cache what later code needs to make capability decisions. */
    dev->era      = (secRead(dev->regs, SEC_QORIQ_CCBVID) &
                        SEC_QORIQ_CCBVID_ERA_MASK) >> SEC_QORIQ_CCBVID_ERA_SHIFT;
    dev->chaNumLs = secRead(dev->regs, SEC_QORIQ_CHANUM_LS);
    dev->chaVidLs = secRead(dev->regs, SEC_QORIQ_CHAVID_LS);

    chanumMs = secRead(dev->regs, SEC_QORIQ_CHANUM_MS);
    if (((chanumMs >> SEC_QORIQ_CHANUM_MS_JRNUM_SHIFT) & 0xF) <=
            dev->jrIndex) {
        WOLFSSL_MSG("sec_qoriq: requested job ring does not exist");
        wc_SecQoriqUnmapRegs(dev->regs);
        return BAD_FUNC_ARG;
    }

    /* Refuse rather than hand the engine addresses it reads as 64-bit. */
    mcfgr = secRead(dev->regs, SEC_QORIQ_MCFGR);
    if (mcfgr & SEC_QORIQ_MCFGR_LONG_PTR) {
        WOLFSSL_MSG("sec_qoriq: engine is in 64-bit pointer mode, unsupported");
        wc_SecQoriqUnmapRegs(dev->regs);
        return NOT_COMPILED_IN;
    }
    dev->longPtr = 0;

    ret = secRingsAlloc(dev);
    if (ret != 0) {
        secRingsFree(dev);
        wc_SecQoriqUnmapRegs(dev->regs);
        return ret;
    }

    ret = secJrReset(dev);
    if (ret != 0) {
        secRingsFree(dev);
        wc_SecQoriqUnmapRegs(dev->regs);
        return ret;
    }

    secRingsProgram(dev);

    /* With virtualization enabled the ring stays parked until started.
     * Both boards tested have VIRT_EN clear, but honour it anyway. */
    scfgr = secRead(dev->regs, SEC_QORIQ_SCFGR);
    if (scfgr & SEC_QORIQ_SCFGR_VIRT_EN) {
        word32 jrstart = secRead(dev->regs, SEC_QORIQ_JRSTART);
        secWrite(dev->regs, SEC_QORIQ_JRSTART,
            jrstart | SEC_QORIQ_JRSTART_JR(dev->jrIndex));
    }

    /* RNG offload needs state handle 0 instantiated, which the boot loaders
     * tested do not do. Record it and let the RNG paths decide. */
    dev->rngReady = (secRead(dev->regs, SEC_QORIQ_RDSTA) &
        SEC_QORIQ_RDSTA_IF0) ? 1 : 0;

    dev->initialized = 1;

#ifndef WC_NO_RNG
    /* Instantiate RNG4 now, while nothing else can reach the device: the
     * status check and TRNG programming inside are not atomic, so they must
     * never race a second initialiser or a live job. A failure only means
     * hardware seeding stays unavailable (rngReady 0); the rest of the
     * engine is still worth having. */
    if (dev->rngReady == 0 && wc_SecQoriqRngInit() != 0) {
        WOLFSSL_MSG("sec_qoriq: RNG4 unavailable, seeding stays in software");
    }
#endif

#if defined(WOLF_CRYPTO_CB) && !defined(WOLFSSL_SEC_QORIQ_NO_CRYPTOCB)
    ret = wc_SecQoriqRegisterCryptoCb();
    if (ret != 0) {
        WOLFSSL_MSG("sec_qoriq: could not register the crypto callback");
        dev->initialized = 0;
        secRingsFree(dev);
        wc_SecQoriqUnmapRegs(dev->regs);
        return ret;
    }
#endif

    WOLFSSL_MSG("sec_qoriq: initialized");
    return 0;
}

/* Keyed on the register mapping rather than on initialized: a device
 * poisoned by a failed quiesce has initialized cleared but still owns the
 * callback registration and mappings, and must still be torn down. */
int wc_SecQoriqFree(void)
{
    SecQoriqDev* dev = &secQoriqDev;

    if (dev->regs == NULL) {
        return 0;
    }

#if defined(WOLF_CRYPTO_CB) && !defined(WOLFSSL_SEC_QORIQ_NO_CRYPTOCB)
    wc_SecQoriqUnregisterCryptoCb();
#endif

    if (dev->quiesceFailed) {
        /* The engine survived both the ring reset and the DMA reset, so it
         * may still master the bus holding our physical addresses. Leak the
         * rings and the register mapping deliberately: freeing them would
         * let the allocator hand the engine's DMA targets to someone else.
         * A later wc_SecQoriqInit() starts over with fresh storage and
         * probes the engine with a ring reset. */
        WOLFSSL_MSG("sec_qoriq: engine not quiesced, leaking DMA memory");
        dev->initialized = 0;
        return 0;
    }

    (void)secJrReset(dev);
    secRingsFree(dev);
    wc_SecQoriqUnmapRegs(dev->regs);

    XMEMSET(dev, 0, sizeof(SecQoriqDev));

    return 0;
}

#endif /* WOLFSSL_SEC_QORIQ */
