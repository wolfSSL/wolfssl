/* sec_qoriq_rng.c
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
 * RNG4 on the QorIQ SEC.
 *
 * The block powers up with no DRBG state handle, and neither U-Boot nor
 * wolfBoot instantiates one on the boards this was written against (RDSTA
 * reads 0 on both T2080 and T1040), so the driver does it itself.
 *
 * Instantiation goes through the job ring rather than direct DECO0 access.
 * Linux uses DECO0 because it must instantiate before handing rings to
 * consumers; we already own a ring.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SEC_QORIQ) && !defined(WC_NO_RNG)

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

/* Program the TRNG sampling parameters. Program mode only, and only with no
 * state handle live: changing these under one would invalidate it. */
static void secKickTrng(SecQoriqDev* dev, word32 entDelay)
{
    word32 val;

    /* program mode */
    val = wc_SecQoriqRead(dev->regs, SEC_QORIQ_RTMCTL);
    wc_SecQoriqWrite(dev->regs, SEC_QORIQ_RTMCTL,
        val | SEC_QORIQ_RTMCTL_PRGM);

    /* entropy delay: system clocks per entropy sample */
    val = wc_SecQoriqRead(dev->regs, SEC_QORIQ_RTSDCTL);
    val &= ~(word32)SEC_QORIQ_RTSDCTL_ENT_DLY_MASK;
    val |= entDelay << SEC_QORIQ_RTSDCTL_ENT_DLY_SHIFT;
    wc_SecQoriqWrite(dev->regs, SEC_QORIQ_RTSDCTL, val);

    /* the statistical checker's frequency bounds track the sample length */
    wc_SecQoriqWrite(dev->regs, SEC_QORIQ_RTFRQMIN, entDelay >> 2);
    wc_SecQoriqWrite(dev->regs, SEC_QORIQ_RTFRQMAX, entDelay << 3);

    /* back to run mode */
    val = wc_SecQoriqRead(dev->regs, SEC_QORIQ_RTMCTL);
    wc_SecQoriqWrite(dev->regs, SEC_QORIQ_RTMCTL,
        val & ~(word32)SEC_QORIQ_RTMCTL_PRGM);
}

/* Instantiate state handle 0, then generate the secure keys (JDKEK, TDKEK,
 * TDSK). The JUMP waits for the first operation; the LOAD clears the done
 * interrupt and returns the RNG to idle. */
static int secInstantiateRng(SecQoriqDev* dev)
{
    SecQoriqDesc desc;
    int ret;

    ret = wc_SecQoriqDescInit(&desc);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_OP | SEC_QORIQ_CLASS1 |
        SEC_QORIQ_RNG | SEC_QORIQ_ALG_INIT);
    if (ret == 0) {
        /* local jump, test all conditions, target the next command */
        ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_JUMP |
            SEC_QORIQ_JUMP_CLASS1 | 0x01);
    }
    if (ret == 0) {
        ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_LOAD_CLRW);
    }
    if (ret == 0) {
        ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CLRW_RESET);
    }
    if (ret == 0) {
        ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_OP |
            SEC_QORIQ_CLASS1 | SEC_QORIQ_RNG | SEC_QORIQ_RNG4_SK);
    }
    if (ret != 0) {
        return ret;
    }

    return wc_SecQoriqRun(dev, &desc);
}

int wc_SecQoriqRngInit(void)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    word32 entDelay = SEC_QORIQ_RTSDCTL_ENT_DLY_MIN;
    word32 scfgr;
    int ret = WC_HW_E;

    if (dev == NULL) {
        return WC_HW_E;
    }

    /* Do not touch the TRNG parameters if a handle is already live. */
    if (wc_SecQoriqRead(dev->regs, SEC_QORIQ_RDSTA) & SEC_QORIQ_RDSTA_IF0) {
        dev->rngReady = 1;
        return 0;
    }

    /* A failure usually means the statistical checks rejected the entropy
     * at this sample length, so widen it and retry. */
    while (entDelay < SEC_QORIQ_RTSDCTL_ENT_DLY_MAX) {
        secKickTrng(dev, entDelay);

        ret = secInstantiateRng(dev);
        if (ret == 0) {
            break;
        }

        entDelay += SEC_QORIQ_RTSDCTL_ENT_DLY_STEP;
    }

    if (ret != 0) {
        WOLFSSL_MSG("sec_qoriq: RNG4 instantiation failed");
        return ret;
    }

    if ((wc_SecQoriqRead(dev->regs, SEC_QORIQ_RDSTA) &
            SEC_QORIQ_RDSTA_IF0) == 0) {
        WOLFSSL_MSG("sec_qoriq: RNG4 job succeeded but no state handle");
        return WC_HW_E;
    }

    /* Read back the deterministic blocks rather than re-deriving them. */
    scfgr = wc_SecQoriqRead(dev->regs, SEC_QORIQ_SCFGR);
    wc_SecQoriqWrite(dev->regs, SEC_QORIQ_SCFGR,
        scfgr | SEC_QORIQ_SCFGR_RDBENABLE);

    dev->rngReady = 1;
    WOLFSSL_MSG("sec_qoriq: RNG4 instantiated");

    return 0;
}

int wc_SecQoriqRandomBlock(byte* out, word32 sz)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    SecQoriqDesc desc;
    int ret;

    if (out == NULL || sz == 0) {
        return BAD_FUNC_ARG;
    }
    if (dev == NULL) {
        return WC_HW_E;
    }
    if (dev->rngReady == 0) {
        ret = wc_SecQoriqRngInit();
        if (ret != 0) {
            return ret;
        }
    }

    ret = wc_SecQoriqDescInit(&desc);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_OP | SEC_QORIQ_CLASS1 |
        SEC_QORIQ_RNG);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_S |
        SEC_QORIQ_FIFOS_TYPE_RNG, out, sz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqCacheFlush(out, sz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqRun(dev, &desc);
    if (ret != 0) {
        return ret;
    }

    return wc_SecQoriqCacheInval(out, sz);
}

#endif /* WOLFSSL_SEC_QORIQ && !WC_NO_RNG */
