/* wolfcaam_linux.c
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
 * Request dispatch for the Linux port. QNX sends each request to a separate
 * resource manager over devctl; here the driver runs in the calling process,
 * so a request is a direct call.
 *
 * The work this layer does is moving data. Caller buffers come from
 * wolfCrypt's heap, which the engine cannot reach, so every operand is staged
 * in the reserved DMA pool and results are copied back.
 *
 * The staging buffers are shared, so a request holds a mutex from the moment
 * it starts staging until the results are copied out. The driver's own
 * jr_lock only covers the ring submission window, which is too narrow: two
 * threads could otherwise interleave their staging and each receive the
 * other's ciphertext.
 *
 * Note the return convention: wc_caamAddAndWait() tests against Success,
 * which is 1, and Failure is 0. This layer must not use the usual "zero means
 * success".
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CAAM) && defined(WOLFSSL_CAAM_LINUX)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Largest AES request taken by the engine. Anything bigger goes back as
 * CRYPTOCB_UNAVAILABLE for software to handle. */
#ifndef CAAM_LINUX_AES_MAX
    #define CAAM_LINUX_AES_MAX (16 * 1024)
#endif
#define CAAM_LINUX_KEY_MAX 32
#define CAAM_LINUX_IV_MAX  16

/* Bound on a single entropy request. WC_CAAM_MAX_ENTROPY is what
 * wc_GenerateSeed() asks for at a time. */
#define CAAM_LINUX_ENT_MAX 64

static int  caamInitDone = 0;
static int  caamLockInit = 0;
static wolfSSL_Mutex caamLock;

/* Staged once and reused: the pool is a bump allocator with no free, so a
 * fresh mapping per operation would exhaust it within a few hundred calls. */
static unsigned char* caamKeyBuf = NULL;
static unsigned char* caamIvBuf  = NULL;
static unsigned char* caamInBuf  = NULL;
static unsigned char* caamOutBuf = NULL;
static unsigned char* caamEntBuf = NULL;

int wc_CAAMInitInterface(void)
{
    int ret = 0;

    if (!caamLockInit) {
        if (wc_InitMutex(&caamLock) != 0) {
            WOLFSSL_MSG("caam: could not create the request mutex");
            return WC_HW_E;
        }
        caamLockInit = 1;
    }

    if (wc_LockMutex(&caamLock) != 0) {
        return WC_HW_E;
    }
    if (!caamInitDone) {
        if (InitCAAM() == 0) {
            caamInitDone = 1;
        }
        else {
            WOLFSSL_MSG("caam: could not initialize the driver");
            ret = WC_HW_E;
        }
    }
    wc_UnLockMutex(&caamLock);

    return ret;
}

void wc_CAAMFreeInterface(void)
{
    if (caamInitDone) {
        CleanupCAAM();
        caamInitDone = 0;
    }

    /* Leave nothing behind in the shared pool, then drop the pointers so a
     * later init cannot reuse them. */
    if (caamKeyBuf != NULL) {
        ForceZero(caamKeyBuf, CAAM_LINUX_KEY_MAX + CAAM_LINUX_IV_MAX +
            CAAM_LINUX_ENT_MAX + (2 * CAAM_LINUX_AES_MAX));
    }
    caamKeyBuf = NULL;
    caamIvBuf  = NULL;
    caamInBuf  = NULL;
    caamOutBuf = NULL;
    caamEntBuf = NULL;

    if (caamLockInit) {
        wc_FreeMutex(&caamLock);
        caamLockInit = 0;
    }
}

/* One pool block, split into the pieces a request needs. Taking it in a
 * single allocation means a failure cannot strand partially used pool. */
static int caamLinuxScratch(void)
{
    unsigned char* p;
    int need = CAAM_LINUX_KEY_MAX + CAAM_LINUX_IV_MAX + CAAM_LINUX_ENT_MAX +
               (2 * CAAM_LINUX_AES_MAX);

    if (caamOutBuf != NULL) {
        return 0;
    }

    p = (unsigned char*)CAAM_ADR_MAP(0, need, 0);
    if (p == NULL) {
        WOLFSSL_MSG("caam: could not reserve scratch in the DMA pool");
        return -1;
    }

    caamKeyBuf = p;                             p += CAAM_LINUX_KEY_MAX;
    caamIvBuf  = p;                             p += CAAM_LINUX_IV_MAX;
    caamEntBuf = p;                             p += CAAM_LINUX_ENT_MAX;
    caamInBuf  = p;                             p += CAAM_LINUX_AES_MAX;
    caamOutBuf = p;

    return 0;
}

/* Entropy is staged like everything else. caamEntropy() reads the TRNG
 * registers with the CPU on era < 9 parts, where a heap pointer would have
 * worked, but on era >= 9 it builds a descriptor and the engine DMAs the
 * result - and an address outside the pool translates to physical 0. */
static int caamLinuxEntropy(CAAM_BUFFER* buf, int sz)
{
    int ret;

    if (sz < 1 || buf == NULL || buf[0].Length <= 0 ||
            buf[0].Length > CAAM_LINUX_ENT_MAX) {
        return Failure;
    }
    if (caamLinuxScratch() != 0) {
        return Failure;
    }

    /* Pass the driver's status straight back: wc_caamAddAndWait() turns
     * CAAM_WAITING into RAN_BLOCK_E and wc_GenerateSeed() retries with a
     * delay, so do not spin here. */
    ret = caamEntropy(caamEntBuf, buf[0].Length);
    if (ret == Success) {
        XMEMCPY((void*)buf[0].TheAddress, caamEntBuf, buf[0].Length);
    }
    ForceZero(caamEntBuf, CAAM_LINUX_ENT_MAX);

    return ret;
}

/* AES-CBC/CTR/ECB. ECB has no IV, so it passes three buffers where CBC and
 * CTR pass four plus a slot for the updated IV. caamAes() walks its list the
 * same way, so both lists are built to the same shape. */
static int caamLinuxAes(int type, unsigned int args[4], CAAM_BUFFER* buf,
    int sz)
{
    DESCSTRUCT desc;
    CAAM_BUFFER dma[4];
    int ivIdx, inIdx, outIdx, ivSz = 0;
    int ret = Failure;

    if (buf == NULL) {
        return Failure;
    }

    ivIdx  = (type == CAAM_AESCBC || type == CAAM_AESCTR) ? 1 : 0;
    inIdx  = ivIdx + 1;
    outIdx = ivIdx + 2;
    if (sz < (outIdx + 1)) {
        return Failure;
    }

    /* Lengths come from the caller as signed ints and end up as a memcpy
     * size, so reject anything not in range rather than only too large. */
    if (buf[0].Length <= 0 || buf[inIdx].Length <= 0 ||
            buf[outIdx].Length <= 0 || (ivIdx && buf[1].Length <= 0)) {
        return Failure;
    }
    if (buf[0].Length > CAAM_LINUX_KEY_MAX ||
            buf[inIdx].Length > CAAM_LINUX_AES_MAX ||
            buf[outIdx].Length > CAAM_LINUX_AES_MAX ||
            (ivIdx && buf[1].Length > CAAM_LINUX_IV_MAX)) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (caamLinuxScratch() != 0) {
        return Failure;
    }

    XMEMCPY(caamKeyBuf, (void*)buf[0].TheAddress, buf[0].Length);
    XMEMCPY(caamInBuf,  (void*)buf[inIdx].TheAddress, buf[inIdx].Length);
    dma[0].BufferType = DataBuffer;
    dma[0].TheAddress = (CAAM_ADDRESS)caamKeyBuf;
    dma[0].Length     = buf[0].Length;

    if (ivIdx) {
        ivSz = buf[1].Length;
        XMEMCPY(caamIvBuf, (void*)buf[1].TheAddress, ivSz);
        dma[1].BufferType = DataBuffer;
        dma[1].TheAddress = (CAAM_ADDRESS)caamIvBuf;
        dma[1].Length     = ivSz;
    }

    dma[inIdx].BufferType = DataBuffer;
    dma[inIdx].TheAddress = (CAAM_ADDRESS)caamInBuf;
    dma[inIdx].Length     = buf[inIdx].Length;

    dma[outIdx].BufferType = DataBuffer | LastBuffer;
    dma[outIdx].TheAddress = (CAAM_ADDRESS)caamOutBuf;
    dma[outIdx].Length     = buf[outIdx].Length;

    caamDescInit(&desc, type, args, dma, outIdx + 1);
    if (caamAes(&desc, dma, args) == Success) {
        XMEMCPY((void*)buf[outIdx].TheAddress, caamOutBuf, buf[outIdx].Length);

        /* hand back the updated IV so chaining continues correctly */
        if (ivSz > 0 && sz > (outIdx + 1) && buf[outIdx + 1].TheAddress != 0) {
            XMEMCPY((void*)buf[outIdx + 1].TheAddress, caamIvBuf, ivSz);
        }
        ret = Success;
    }
    else {
        WOLFSSL_MSG("caam: AES job did not complete");
    }

    /* Clear the key material on every request: it is the secret, and it is
     * only 48 bytes. The data buffers are cleared at teardown instead -
     * wiping up to 2 x CAAM_LINUX_AES_MAX per call costs about a fifth of
     * the throughput, and the next request overwrites them before the engine
     * reads them anyway. */
    ForceZero(caamKeyBuf, CAAM_LINUX_KEY_MAX);
    ForceZero(caamIvBuf, CAAM_LINUX_IV_MAX);

    return ret;
}

int SynchronousSendRequest(int type, unsigned int args[4], CAAM_BUFFER* buf,
    int sz)
{
    int ret;

    if (wc_CAAMInitInterface() != 0) {
        return Failure;
    }

    switch (type) {
        case CAAM_ENTROPY:
        case CAAM_AESCBC:
        case CAAM_AESCTR:
        case CAAM_AESECB:
            break;
        default:
            /* Anything else goes to software rather than pretending to run. */
            WOLFSSL_MSG("caam: request type not handled by the Linux port");
            return CRYPTOCB_UNAVAILABLE;
    }

    /* Held across staging, submission and copy back, since the staging
     * buffers are shared by every caller. */
    if (wc_LockMutex(&caamLock) != 0) {
        return Failure;
    }

    if (type == CAAM_ENTROPY) {
        ret = caamLinuxEntropy(buf, sz);
    }
    else {
        ret = caamLinuxAes(type, args, buf, sz);
    }

    wc_UnLockMutex(&caamLock);

    return ret;
}

#endif /* WOLFSSL_CAAM && WOLFSSL_CAAM_LINUX */
