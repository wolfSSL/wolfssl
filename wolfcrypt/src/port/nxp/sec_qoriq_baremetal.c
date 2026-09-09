/* sec_qoriq_baremetal.c
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
 * Bare-metal backend for the QorIQ SEC driver.
 *
 * Assumes a flat, identity mapped address space, which is how both wolfBoot
 * and U-Boot leave the e5500/e6500 for the code they hand control to. There
 * is no allocator, so DMA memory comes from a static pool.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SEC_QORIQ) && defined(WOLFSSL_SEC_QORIQ_BAREMETAL)

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

/* e5500 and e6500 both use a 64 byte cache line. */
#ifndef SEC_QORIQ_CACHE_LINE
    #define SEC_QORIQ_CACHE_LINE 64
#endif

/* Backing store for job rings and any bounce buffers. Descriptors live on
 * the caller's stack, which is also DMA reachable on this target. */
#ifndef SEC_QORIQ_DMA_POOL_SZ
    #define SEC_QORIQ_DMA_POOL_SZ 8192
#endif

static byte secDmaPool[SEC_QORIQ_DMA_POOL_SZ]
    __attribute__((aligned(SEC_QORIQ_CACHE_LINE)));
static word32 secDmaUsed = 0;

int wc_SecQoriqMapRegs(byte** regsOut)
{
    if (regsOut == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Physically addressed, nothing to map. */
    *regsOut = (byte*)(SEC_QORIQ_CCSRBAR + SEC_QORIQ_OFFSET);
    return 0;
}

void wc_SecQoriqUnmapRegs(byte* regs)
{
    (void)regs;
}

/* Bump allocator. The driver allocates its rings once at init and never
 * frees them in normal operation, so reclaiming space is not worth the
 * complexity; wc_SecQoriqDmaFree only rewinds the most recent allocation. */
void* wc_SecQoriqDmaAlloc(word32 sz, word64* physOut)
{
    word32 aligned;
    byte* ptr;

    if (physOut == NULL || sz == 0) {
        return NULL;
    }

    aligned = (sz + (SEC_QORIQ_CACHE_LINE - 1)) &
        ~(word32)(SEC_QORIQ_CACHE_LINE - 1);

    if (secDmaUsed + aligned > SEC_QORIQ_DMA_POOL_SZ) {
        WOLFSSL_MSG("sec_qoriq: DMA pool exhausted");
        return NULL;
    }

    ptr = &secDmaPool[secDmaUsed];
    secDmaUsed += aligned;

    *physOut = (word64)(wolfssl_word)ptr;
    return ptr;
}

void wc_SecQoriqDmaFree(void* virt, word64 phys, word32 sz)
{
    word32 aligned = (sz + (SEC_QORIQ_CACHE_LINE - 1)) &
        ~(word32)(SEC_QORIQ_CACHE_LINE - 1);

    (void)phys;

    if (virt == NULL) {
        return;
    }

    /* Only the most recent allocation can be given back. Check the size
     * first: secDmaUsed and aligned are both word32, so a mismatched size
     * would wrap the subtraction and form a pointer outside the pool, which
     * is undefined behaviour even though it is only ever compared. */
    if ((aligned == 0) || (aligned > secDmaUsed)) {
        return;
    }
    if ((byte*)virt == &secDmaPool[secDmaUsed - aligned]) {
        secDmaUsed -= aligned;
    }
}

/* The address space is flat and identity mapped, so every buffer is
 * physically contiguous by construction and the length does not matter. */
word64 wc_SecQoriqVirtToPhysLen(void* virt, word32 len)
{
    (void)len;
    return (word64)(wolfssl_word)virt;
}

/* No staging on a flat map: memory neither moves nor copies-on-write, so
 * the engine can use every buffer in place. Cache maintenance around the
 * data stays with the drivers, which know each buffer's role. */
int wc_SecQoriqDmaJobBegin(void)
{
    return 0;
}

word64 wc_SecQoriqDmaMapBuf(void* virt, word32 sz, int dir)
{
    (void)dir;
    return wc_SecQoriqVirtToPhysLen(virt, sz);
}

void wc_SecQoriqDmaJobEnd(int ok, int abandoned)
{
    (void)ok;
    (void)abandoned;
}

/* dcbf writes back and invalidates, which is correct in both directions:
 * pushing our writes out to the engine, and dropping any stale line before
 * reading what the engine wrote. dcbi would be marginally cheaper on the
 * inbound path but risks discarding a dirty line if a buffer is ever shared
 * with CPU-written data, so it is deliberately not used. */
static void secCacheOp(void* virt, word32 sz)
{
    wolfssl_word addr = (wolfssl_word)virt;
    wolfssl_word end  = addr + sz;

    addr &= ~(wolfssl_word)(SEC_QORIQ_CACHE_LINE - 1);

    __asm__ __volatile__("msync" ::: "memory");
    while (addr < end) {
        __asm__ __volatile__("dcbf 0,%0" :: "r"(addr) : "memory");
        addr += SEC_QORIQ_CACHE_LINE;
    }
    __asm__ __volatile__("msync" ::: "memory");
}

int wc_SecQoriqCacheFlush(void* virt, word32 sz)
{
    if (virt == NULL) {
        return BAD_FUNC_ARG;
    }
    secCacheOp(virt, sz);
    return 0;
}

int wc_SecQoriqCacheInval(void* virt, word32 sz)
{
    if (virt == NULL) {
        return BAD_FUNC_ARG;
    }
    secCacheOp(virt, sz);
    return 0;
}

void wc_SecQoriqCpuRelax(void)
{
    /* Keep the compiler from hoisting the polled register read out of the
     * loop. There is no useful wait instruction here. */
    __asm__ __volatile__("" ::: "memory");
}

int wc_SecQoriqGetSvr(word32* svrOut)
{
    word32 svr;

    if (svrOut == NULL) {
        return BAD_FUNC_ARG;
    }

    /* SVR is SPR 1023 on the e500 family. */
    __asm__ __volatile__("mfspr %0, 1023" : "=r"(svr));
    *svrOut = svr;

    return 0;
}

#endif /* WOLFSSL_SEC_QORIQ && WOLFSSL_SEC_QORIQ_BAREMETAL */
