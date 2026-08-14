/* sec_qoriq_linux.c
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
 * Linux user space backend for the QorIQ SEC driver.
 *
 * Maps the SEC block through /dev/mem and resolves DMA addresses with
 * /proc/self/pagemap. The kernel's own caam driver must not be bound to the
 * job ring this driver claims; blacklist it or unbind that ring first.
 *
 * NOTE: this backend has not yet been exercised on hardware. The boards on
 * hand run bare metal, so sec_qoriq_baremetal.c is the tested path.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SEC_QORIQ) && defined(WOLFSSL_SEC_QORIQ_LINUX)

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#ifndef SEC_QORIQ_MEM_DEV
    #define SEC_QORIQ_MEM_DEV "/dev/mem"
#endif

#ifndef SEC_QORIQ_PAGE_SZ
    #define SEC_QORIQ_PAGE_SZ 4096
#endif

#ifndef SEC_QORIQ_CACHE_LINE
    #define SEC_QORIQ_CACHE_LINE 64
#endif

int wc_SecQoriqMapRegs(byte** regsOut)
{
    int fd;
    void* map;

    if (regsOut == NULL) {
        return BAD_FUNC_ARG;
    }

    fd = open(SEC_QORIQ_MEM_DEV, O_RDWR | O_SYNC);
    if (fd < 0) {
        WOLFSSL_MSG("sec_qoriq: cannot open " SEC_QORIQ_MEM_DEV);
        return WC_HW_E;
    }

    /* CCSR sits high in the physical map, so a 32-bit off_t cannot address
     * it. Fail loudly instead of mapping a truncated, wrong address, which on
     * a 36-bit part lands in DRAM and is refused by CONFIG_STRICT_DEVMEM. */
    if ((sizeof(off_t) < sizeof(word64)) &&
            ((SEC_QORIQ_CCSRBAR_PHYS + SEC_QORIQ_OFFSET) > 0x7FFFFFFFULL)) {
        close(fd);
        WOLFSSL_MSG("sec_qoriq: build with 64-bit off_t to map CCSR");
        return WC_HW_E;
    }

    map = mmap(NULL, SEC_QORIQ_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
        (off_t)(SEC_QORIQ_CCSRBAR_PHYS + SEC_QORIQ_OFFSET));
    close(fd);

    if (map == MAP_FAILED) {
        WOLFSSL_MSG("sec_qoriq: cannot map the SEC block");
        return WC_HW_E;
    }

    *regsOut = (byte*)map;
    return 0;
}

void wc_SecQoriqUnmapRegs(byte* regs)
{
    if (regs != NULL) {
        munmap(regs, SEC_QORIQ_SIZE);
    }
}

/* Locked, page aligned pages so the physical address stays put for the life
 * of the allocation. */
void* wc_SecQoriqDmaAlloc(word32 sz, word64* physOut)
{
    void* ptr;
    word64 phys;

    if (physOut == NULL || sz == 0) {
        return NULL;
    }

    ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }

    /* Fault it in before asking for the translation. */
    XMEMSET(ptr, 0, sz);

    /* MAP_LOCKED pins the pages but does not make them physically
     * contiguous, and the engine gets one base address for the whole
     * region, so verify the entire span rather than just the first frame.
     * A ring bigger than a page is the case that needs it. */
    phys = wc_SecQoriqVirtToPhysLen(ptr, sz);
    if (phys == 0) {
        munmap(ptr, sz);
        return NULL;
    }

    *physOut = phys;
    return ptr;
}

void wc_SecQoriqDmaFree(void* virt, word64 phys, word32 sz)
{
    (void)phys;

    if (virt != NULL) {
        munmap(virt, sz);
    }
}

/* Resolve one page. The engine is handed a single {physical address,
 * length} pair per buffer, which is only valid while the buffer stays inside
 * one physical frame, so callers must bound the length; see
 * wc_SecQoriqVirtToPhysLen(). */
static word64 secPhysOfPage(word64 vaddr)
{
    int fd;
    word64 entry = 0;
    word64 offset;
    word64 pfn;

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    offset = (vaddr / SEC_QORIQ_PAGE_SZ) * (word64)sizeof(word64);
    if (lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1 ||
            read(fd, &entry, sizeof(entry)) != (int)sizeof(entry)) {
        close(fd);
        return 0;
    }
    close(fd);

    /* bit 63 says the page is present; the frame number is bits 54:0 */
    if ((entry & (1ULL << 63)) == 0) {
        return 0;
    }

    pfn = entry & 0x7FFFFFFFFFFFFFULL;
    if (pfn == 0) {
        /* Either the mapping really is physical page 0 or, far more likely,
         * the process lacks CAP_SYS_ADMIN and the kernel zeroed the PFN.
         * Aiming engine DMA at physical 0 is not an acceptable guess. */
        WOLFSSL_MSG("sec_qoriq: pagemap PFN is zero, need CAP_SYS_ADMIN");
        return 0;
    }

    return (pfn * SEC_QORIQ_PAGE_SZ) + (vaddr % SEC_QORIQ_PAGE_SZ);
}

/* A buffer is only usable by the engine if it is physically contiguous.
 * Ordinary user memory is virtually contiguous but not physically, so verify
 * frame by frame and refuse rather than let the engine run off the end of
 * the first frame into an unrelated page. */
word64 wc_SecQoriqVirtToPhysLen(void* virt, word32 len)
{
    word64 vaddr = (word64)(wolfssl_word)virt;
    word64 base  = secPhysOfPage(vaddr);
    word64 off;

    if (base == 0 || len == 0) {
        return base;
    }

    for (off = SEC_QORIQ_PAGE_SZ - (vaddr % SEC_QORIQ_PAGE_SZ);
            off < (word64)len; off += SEC_QORIQ_PAGE_SZ) {
        if (secPhysOfPage(vaddr + off) != base + off) {
            WOLFSSL_MSG("sec_qoriq: buffer is not physically contiguous");
            return 0;
        }
    }

    return base;
}

/* The register window is uncached, but everything these hooks are actually
 * called with (the descriptor on the caller's stack, and the caller's key,
 * IV, AAD, input, output and tag buffers) is ordinary write-back cached
 * memory. dcbf is unprivileged on PowerPC, so the same maintenance the
 * bare-metal backend performs works from user space. */
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
    __asm__ __volatile__("" ::: "memory");
}

/* SVR is a supervisor register, so read it from the device configuration
 * block rather than with mfspr. */
int wc_SecQoriqGetSvr(word32* svrOut)
{
    int fd;
    volatile word32* map;
    void* page;

    if (svrOut == NULL) {
        return BAD_FUNC_ARG;
    }

    fd = open(SEC_QORIQ_MEM_DEV, O_RDONLY | O_SYNC);
    if (fd < 0) {
        return WC_HW_E;
    }

    page = mmap(NULL, SEC_QORIQ_PAGE_SZ, PROT_READ, MAP_SHARED, fd,
        (off_t)(SEC_QORIQ_CCSRBAR_PHYS + 0xE0000ULL));
    close(fd);

    if (page == MAP_FAILED) {
        return WC_HW_E;
    }

    map = (volatile word32*)((byte*)page + 0xA4);
    *svrOut = *map;
    munmap(page, SEC_QORIQ_PAGE_SZ);

    return 0;
}

#endif /* WOLFSSL_SEC_QORIQ && WOLFSSL_SEC_QORIQ_LINUX */
