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

word32 wc_SecQoriqRead(const byte* base, word32 off)
{
    return SEC_SWAP32(*(volatile const word32*)(base + off));
}

void wc_SecQoriqWrite(byte* base, word32 off, word32 val)
{
    *(volatile word32*)(base + off) = SEC_SWAP32(val);
}

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

/* Only 32-bit pointer mode is supported, so an address above 4 GB is a hard
 * error rather than a silent truncation. */
int wc_SecQoriqDescAddPtr(SecQoriqDesc* desc, word64 phys)
{
    if (desc == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((phys >> 32) != 0) {
        WOLFSSL_MSG("sec_qoriq: buffer above 4GB, needs 64-bit pointer mode");
        return BAD_FUNC_ARG;
    }

    return wc_SecQoriqDescAddWord(desc, (word32)phys);
}

/* Append a command word carrying a length, followed by the buffer address. */
int wc_SecQoriqDescAddBuf(SecQoriqDesc* desc, word32 cmd, const byte* buf,
    word32 bufSz)
{
    word64 phys;
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

    phys = wc_SecQoriqVirtToPhysLen((void*)buf, bufSz);
    if (phys == 0) {
        WOLFSSL_MSG("sec_qoriq: buffer not translatable or not contiguous");
        return BAD_FUNC_ARG;
    }

    return wc_SecQoriqDescAddPtr(desc, phys);
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

static int secRunLocked(SecQoriqDev* dev, SecQoriqDesc* desc)
{
    word64 descPhys;
    word32 descBytes;
    word32 status;
    word32 waited;
    word32 slot;
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

    dev->jobCount++;
    secDescFinalize(desc);
    descBytes = desc->idx * (word32)sizeof(word32);

    descPhys = wc_SecQoriqVirtToPhysLen(desc->desc, descBytes);
    if (descPhys == 0 || (descPhys >> 32) != 0) {
        WOLFSSL_MSG("sec_qoriq: descriptor not reachable by the engine");
        return BAD_FUNC_ARG;
    }

    /* The engine reads the descriptor from memory, so push it out first. */
    ret = wc_SecQoriqCacheFlush(desc->desc, descBytes);
    if (ret != 0) {
        return ret;
    }

    if (secRead(dev->jr, SEC_QORIQ_IRSA) == 0) {
        WOLFSSL_MSG("sec_qoriq: no room on the input ring");
        return WC_HW_E;
    }

    dev->inRing[dev->inIdx] = (word32)descPhys;
    ret = wc_SecQoriqCacheFlush(&dev->inRing[dev->inIdx], sizeof(word32));
    if (ret != 0) {
        return ret;
    }

    /* Publish the entry, then tell the engine one job was added. */
    secWrite(dev->jr, SEC_QORIQ_IRJA, 1);
    dev->inIdx = (dev->inIdx + 1) % SEC_QORIQ_RING_SIZE;

    waited = 0;
    while (secRead(dev->jr, SEC_QORIQ_ORSF) == 0) {
        if (++waited > SEC_QORIQ_POLL_MAX) {
            /* The engine may still hold this descriptor, which lives on the
             * caller's stack, and the index mirrors no longer track it.
             * Reset the ring so it cannot write into a frame about to be
             * reused. If the reset fails, mark the device dead so later
             * calls fail fast rather than corrupt memory. */
            WOLFSSL_MSG("sec_qoriq: timed out waiting for job completion");
            if (secJrReset(dev) != 0) {
                dev->initialized = 0;
            }
            else {
                secRingsProgram(dev);
            }
            return WC_HW_E;
        }
        wc_SecQoriqCpuRelax();
    }

    /* Output entries are two words wide: {descriptor address, status}. */
    slot = dev->outIdx * 2;

    ret = wc_SecQoriqCacheInval(&dev->outRing[slot], 2 * sizeof(word32));
    if (ret != 0) {
        return ret;
    }

    /* Confirm the engine retired our descriptor before trusting its
     * status. */
    if (dev->outRing[slot] != (word32)descPhys) {
        WOLFSSL_MSG("sec_qoriq: output ring returned an unexpected job");
        secWrite(dev->jr, SEC_QORIQ_ORJR, 1);
        dev->outIdx = (dev->outIdx + 1) % SEC_QORIQ_RING_SIZE;
        return WC_HW_E;
    }
    status = dev->outRing[slot + 1];
    dev->lastStatus = status;

    /* Release the slot back to the engine. */
    secWrite(dev->jr, SEC_QORIQ_ORJR, 1);
    dev->outIdx = (dev->outIdx + 1) % SEC_QORIQ_RING_SIZE;

    return wc_SecQoriqParseError(status);
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

int wc_SecQoriqFree(void)
{
    SecQoriqDev* dev = &secQoriqDev;

    if (dev->initialized == 0) {
        return 0;
    }

#if defined(WOLF_CRYPTO_CB) && !defined(WOLFSSL_SEC_QORIQ_NO_CRYPTOCB)
    wc_SecQoriqUnregisterCryptoCb();
#endif

    (void)secJrReset(dev);
    secRingsFree(dev);
    wc_SecQoriqUnmapRegs(dev->regs);

    XMEMSET(dev, 0, sizeof(SecQoriqDev));

    return 0;
}

#endif /* WOLFSSL_SEC_QORIQ */
