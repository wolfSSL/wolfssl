/* caam_linux.c
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
 * Port layer letting the CAAM driver core run in Linux user space, developed
 * against the SEC on a QorIQ T1040. It implements the seam declared at the
 * bottom of caam_driver.h, the same one caam_qnx.c implements for QNX.
 *
 * Two things differ from QNX and shape the design.
 *
 * Memory: QNX hands out physically contiguous pages with
 * mmap(MAP_PHYS | MAP_ANON) and translates them with mem_offset64(). Linux
 * user space has neither, and on a part with more than 4 GB of DDR ordinary
 * pages sit above what a 32-bit descriptor pointer can reach. So nothing is
 * allocated from the heap: boot with mem= to leave a range of physical memory
 * unmanaged and carve engine buffers out of that. Translation is then a
 * subtraction and contiguity is free.
 *
 * Ownership: the in-tree caam driver claims all four job rings at boot and
 * configures the block globally, so it has to be unbound first, both the
 * rings and the parent. That leaves its interrupt handler registered, and the
 * first job to complete would raise an IRQ it services against freed state,
 * so this port masks the ring interrupt when it claims the ring. The driver
 * polls anyway. See README.md for the full sequence.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#undef WC_NO_HARDEN
#define WC_NO_HARDEN /* silence warning, it is irrelevant here */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CAAM_LINUX)

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <wolfssl/wolfcrypt/port/caam/caam_driver.h>

/* job ring configuration register, bit 0 masks the ring interrupt */
#define CAAM_LINUX_JRCFGR_LS   0x0054
#define CAAM_LINUX_JRCFGR_IMSK 0x00000001

static int    caamMemFd  = -1;   /* /dev/mem, held open while mapped */
static void*  caamSecMap = NULL; /* the SEC register block           */

static unsigned char* caamPoolVirt = NULL;
static CAAM_ADDRESS   caamPoolPhys = 0;
static unsigned int   caamPoolUsed = 0;

/* Map a physical range through /dev/mem, opening it on first use. */
static void* caamMapPhys(unsigned long long phys, unsigned int len)
{
    void* map;

    if (caamMemFd < 0) {
        caamMemFd = open(CAAM_LINUX_MEM_DEV, O_RDWR | O_SYNC);
        if (caamMemFd < 0) {
            WOLFSSL_MSG("caam: could not open /dev/mem");
            return NULL;
        }
    }

    map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, caamMemFd,
        (off_t)phys);
    if (map == MAP_FAILED) {
        WOLFSSL_MSG("caam: could not map physical range");
        return NULL;
    }

    return map;
}

/* Offset of an address within the pool, or -1 if it is not a pool address.
 * Linux must have been told not to manage the range (mem= on the kernel
 * command line), which also makes CONFIG_STRICT_DEVMEM allow the mapping:
 * the range is no longer reported as System RAM. */
static long caamPoolOffset(const void* v, int sz)
{
    const unsigned char* p = (const unsigned char*)v;

    if (caamPoolVirt == NULL || p < caamPoolVirt || sz < 0 ||
            (p + sz) > (caamPoolVirt + CAAM_LINUX_POOL_SZ)) {
        return -1;
    }

    return (long)(p - caamPoolVirt);
}

/* Hand out a cache line aligned block. Nothing is returned to the pool: the
 * driver takes a small, bounded set of buffers and holds them for the life of
 * the process, so a bump allocator cannot fragment. Callers that would
 * otherwise allocate per operation keep their own scratch instead. */
static unsigned char* caamPoolAlloc(int sz, CAAM_ADDRESS* physOut)
{
    unsigned int need;
    unsigned char* out;

    if (sz <= 0) {
        return NULL;
    }

    if (caamPoolVirt == NULL) {
        caamPoolVirt = (unsigned char*)caamMapPhys(CAAM_LINUX_POOL_PHYS,
            CAAM_LINUX_POOL_SZ);
        if (caamPoolVirt == NULL) {
            return NULL;
        }
        caamPoolPhys = (CAAM_ADDRESS)CAAM_LINUX_POOL_PHYS;
        caamPoolUsed = 0;
        memset(caamPoolVirt, 0, CAAM_LINUX_POOL_SZ);
    }

    need = ((unsigned int)sz + 63u) & ~63u;
    if (caamPoolUsed + need > (unsigned int)CAAM_LINUX_POOL_SZ) {
        WOLFSSL_MSG("caam: reserved DMA pool exhausted");
        return NULL;
    }

    out = caamPoolVirt + caamPoolUsed;
    if (physOut != NULL) {
        *physOut = caamPoolPhys + caamPoolUsed;
    }
    caamPoolUsed += need;

    return out;
}


/* The mapping is uncached and both the host and the SEC are big endian here,
 * so a plain volatile access is enough. */
unsigned int CAAM_READ(CAAM_ADDRESS reg)
{
    return *(volatile unsigned int*)reg;
}

void CAAM_WRITE(CAAM_ADDRESS reg, unsigned int in)
{
    *(volatile unsigned int*)reg = in;
}


int CAAM_SET_BASEADDR(CAAM_ADDRESS* baseAddr)
{
    if (baseAddr == NULL) {
        return -1;
    }

    caamSecMap = caamMapPhys(CAAM_LINUX_CCSR_PHYS + CAAM_LINUX_SEC_OFFSET,
        CAAM_LINUX_SEC_SIZE);
    if (caamSecMap == NULL) {
        return -1;
    }
    *baseAddr = (CAAM_ADDRESS)caamSecMap;

    return 0;
}

void CAAM_UNSET_BASEADDR(CAAM_ADDRESS baseAddr)
{
    (void)baseAddr;

    if (caamSecMap != NULL) {
        munmap(caamSecMap, CAAM_LINUX_SEC_SIZE);
        caamSecMap = NULL;
    }
    if (caamMemFd >= 0) {
        close(caamMemFd);
        caamMemFd = -1;
    }
}

/* The job ring registers are inside the block CAAM_SET_BASEADDR already
 * mapped, so this only offsets into it. The ring itself comes from the pool. */
int CAAM_SET_JOBRING_ADDR(CAAM_ADDRESS* base, CAAM_ADDRESS* ringInPhy,
    void** ringInVir)
{
    unsigned char* ring;
    CAAM_ADDRESS phys = 0;

    if (base == NULL || ringInPhy == NULL || ringInVir == NULL ||
            caamSecMap == NULL) {
        return -1;
    }

    *base = (CAAM_ADDRESS)caamSecMap + CAAM_LINUX_JR_OFFSET;

    /* Mask this ring's interrupt: the kernel driver leaves its handler
     * installed after an unbind, and a completion interrupt would then be
     * serviced against memory it has already freed. */
    CAAM_WRITE(*base + CAAM_LINUX_JRCFGR_LS,
        CAAM_READ(*base + CAAM_LINUX_JRCFGR_LS) | CAAM_LINUX_JRCFGR_IMSK);

    ring = caamPoolAlloc(1024, &phys);
    if (ring == NULL) {
        return -1;
    }

    *ringInPhy = phys;
    *ringInVir = ring;

    return 0;
}

void CAAM_UNSET_JOBRING_ADDR(CAAM_ADDRESS base, CAAM_ADDRESS ringInPhy,
    void* ringInVir)
{
    /* The ring came from the pool and the register window is part of the
     * block mapping, so there is nothing to give back. */
    (void)base;
    (void)ringInPhy;
    (void)ringInVir;
}


CAAM_ADDRESS CAAM_ADR_TO_PHYSICAL(void* in, int inSz)
{
    long off = caamPoolOffset(in, inSz);

    if (off < 0) {
        WOLFSSL_MSG("caam: address is not in the reserved DMA pool");
        return 0;
    }

    return caamPoolPhys + (CAAM_ADDRESS)off;
}

CAAM_ADDRESS CAAM_ADR_TO_VIRTUAL(CAAM_ADDRESS in, int length)
{
    (void)length;

    if (caamPoolVirt == NULL || in < caamPoolPhys ||
            in >= (caamPoolPhys + CAAM_LINUX_POOL_SZ)) {
        WOLFSSL_MSG("caam: physical address is outside the reserved pool");
        return 0;
    }

    return (CAAM_ADDRESS)(caamPoolVirt + (in - caamPoolPhys));
}

/* Take a caller buffer and give back one the engine can reach. */
void* CAAM_ADR_MAP(CAAM_ADDRESS in, int inSz, unsigned char copy)
{
    unsigned char* out = caamPoolAlloc(inSz, NULL);

    if (out != NULL && copy && in != 0) {
        memcpy(out, (void*)in, inSz);
    }

    return out;
}

void CAAM_ADR_UNMAP(void* vaddr, CAAM_ADDRESS out, int outSz,
    unsigned char copy)
{
    if (copy && vaddr != NULL && out != 0 && outSz > 0) {
        memcpy((void*)out, vaddr, outSz);
    }

    /* pool blocks are not individually freed; see caamPoolAlloc() */
}

/* The pool is mapped uncached, so there is no cache to push or drop. The
 * barrier stops descriptor writes being reordered past the register write
 * that rings the doorbell. */
int CAAM_ADR_SYNC(void* vaddr, int sz)
{
    (void)vaddr;
    (void)sz;

    __asm__ __volatile__("sync" ::: "memory");

    return 0;
}

#endif /* WOLFSSL_CAAM_LINUX */
