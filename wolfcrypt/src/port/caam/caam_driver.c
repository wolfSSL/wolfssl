/* caam_driver.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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


#if (defined(__INTEGRITY) || defined(INTEGRITY)) || \
    (defined(__QNX__) || defined(__QNXNTO__))

#if defined(__INTEGRITY) || defined(INTEGRITY)
    /* build into Integrity kernel */
    #include <bsp.h>
    #define CAAM_READ(reg) *(volatile unsigned int*)(CAAM_BASE | (reg))
    #define CAAM_WRITE(reg, in) *(volatile unsigned int*)(CAAM_BASE | (reg)) = (in);
    typedef UINT4 unsigned int
    #define WOLFSSL_MSG db_printf
#endif

#if defined(__QNX__) || defined(__QNXNTO__)
    #include <sys/mman.h>
    #include <hw/inout.h>
    #include <sys/iofunc.h>
    #include <sys/neutrino.h>

    #include "caam_qnx.h"
#endif

#include "caam_driver.h"
#include "caam_error.h"

#include <string.h> /* for memcpy / memset */


struct JobRing {
    CAAM_ADDRESS JobIn;
    CAAM_ADDRESS JobOut;
    CAAM_ADDRESS Desc;
    void* VirtualIn;
    void* VirtualOut;
    void* VirtualDesc;
    Value   page;    /* page allocation for descriptor to use */
    CAAM_MUTEX jr_lock;
};

struct CAAM_DEVICE {
#if defined(__INTEGRITY) || defined(INTEGRITY)
    struct IODeviceVectorStruct caamVector;
    struct IODescriptorStruct   IODescriptorArray[BUFFER_COUNT];
    struct DescStruct           DescArray[DESC_COUNT];
    volatile Value              InterruptStatus;
    CALL                        HandleInterruptCall;
#endif
    struct JobRing              ring;
};

#define DRIVER_NAME "wolfSSL_CAAM_Driver"

static struct CAAM_DEVICE caam;

/* function declarations */
Error caamAddJob(DESCSTRUCT* desc);
Error caamDoJob(DESCSTRUCT* desc);


/******************************************************************************
  Internal CAAM Job Ring and partition functions
  ****************************************************************************/

#ifdef CAAM_DEBUG_MODE
/* runs a descriptor in debug mode */
static Error caamDebugDesc(struct DescStruct* desc)
{
    int z;
    int sz;
    unsigned int flag = 0x20000000;

    /* clear and set desc size */
    sz = desc->desc[0] & 0x0000007F;
    CAAM_WRITE(CAAM_DECORR, 1); /* ask for DECO permissions */
    printf("CAAM_DECORR = 0x%08X\n", CAAM_READ(CAAM_DECORR));
    printf("STATUS : 0x%08X\n", CAAM_READ(CAAM_DOOPSTA_MS));
    printf("CAAM STATUS : 0x%08X\n", CAAM_READ(0x0FD4));
    printf("DECO DRG (bit 32 is valid -- running) : 0x%08X\n", CAAM_READ(0x8E04));

    printf("Descriptor input :\n");
    /* write descriptor into descriptor buffer */
    for (z = 0; z < sz; z++) {
        CAAM_WRITE(CAAM_DODESB + (z*4), desc->desc[z]);
        printf("\t0x%08X\n", desc->desc[z]);
    }
    printf("\n");

    printf("command size = %d\n", sz);
    if (sz > 4) {
        flag |= 0x10000000;
    }

    CAAM_WRITE(CAAM_DODAR+4, desc->caam->ring.Desc);
    /* set WHL bit since we loaded the entire descriptor */
    CAAM_WRITE(CAAM_DOJQCR_MS, flag);

    printf("CAAM STATUS : 0x%08X\n", CAAM_READ(0x0FD4));
    printf("DECO DRG (bit 32 is valid -- running) : 0x%08X\n", CAAM_READ(0x8E04));

    /* DECO buffer */
    printf("DECO BUFFER [0x%08X]:\n", CAAM_READ(CAAM_DODAR+4));
    printf("\tSTATUS : 0x%08X\n", CAAM_READ(CAAM_DOOPSTA_MS));
    printf("\tJRSTAR_JR0 : 0x%08X\n", CAAM_READ(0x1044));
    for (z = 0; z < sz; z++)
        printf("\t0x%08X\n", CAAM_READ(CAAM_DODESB + (z*4)));


    //D0JQCR_LS
    printf("Next command to be executed = 0x%08X\n", CAAM_READ(0x8804));
    printf("Desc          = 0x%08X\n", desc->caam->ring.Desc);


    /* DECO buffer */
    printf("DECO BUFFER [0x%08X]:\n", CAAM_READ(CAAM_DODAR+4));
    printf("\tSTATUS : 0x%08X\n", CAAM_READ(CAAM_DOOPSTA_MS));
    printf("\tJRSTAR_JR0 : 0x%08X\n", CAAM_READ(0x1044));
    for (z = 0; z < sz; z++)
        printf("\t0x%08X\n", CAAM_READ(CAAM_DODESB + (z*4)));

    printf("Next command to be executed = 0x%08X\n", CAAM_READ(0x8804));
    printf("CAAM STATUS : 0x%08X\n", CAAM_READ(0x0FD4));
    while (CAAM_READ(0x8E04) & 0x80000000) {
        printf("DECO DRG (bit 32 is valid -- running) : 0x%08X\n", CAAM_READ(0x8E04));
        sleep(1);
    }
    CAAM_WRITE(CAAM_DECORR, 0); /* free DECO */
    printf("done with debug job\n");
    return Success;
}
#endif /* CAAM_DEBUG_MODE */


#if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
static void printSecureMemoryInfo()
{
    unsigned int SMVID_MS, SMVID_LS;

    printf("SMSTA = 0x%08X\n", CAAM_READ(0x1FB4));
    printf("SMPO = 0x%08X\n", CAAM_READ(CAAM_SM_SMPO));
    SMVID_MS = CAAM_READ(CAAM_SM_SMVID_MS);
    SMVID_LS = CAAM_READ(CAAM_SM_SMVID_LS);
    printf("\tNumber Partitions : %d\n", (SMVID_MS >> 12 & 0xF));
    printf("\tNumber Pages : %d\n", (SMVID_MS & 0x3FF));
    printf("\tPage Size : 2^%d\n", ((SMVID_LS >> 16) & 0x7));
}
#endif

/* flush job ring and reset */
static Error caamReset(void)
{
    int t = 100000; /* time out counter for flushing job ring */

    /* make sure interrupts are masked in JRCFGR0_LS register */
    CAAM_WRITE(0x1054, CAAM_READ(0x1054) | 1);

    /* flush and reset job rings using JRCR0 register */
    CAAM_WRITE(0x106C, 1);

    /* check register JRINTR for if halt is in progress */
    while (t > 0 && ((CAAM_READ(0x104C) & 0x4) == 0x4)) t--;
    if (t == 0) {
        /*unrecoverable failure, the job ring is locked, up hard reset needed*/
        return -1;//NotRestartable;
    }

    /* now that flush has been done restart the job ring */
    t = 100000;
    CAAM_WRITE(0x106C, 1);
    while (t > 0 && ((CAAM_READ(0x106C) & 1) == 1)) t--;
    if (t == 0) {
        /*unrecoverable failure, reset bit did not return to 0 */
        return -1;//NotRestartable;
    }

    /* reset most registers and state machines in CAAM using MCFGR register
       also reset DMA */
    CAAM_WRITE(0x0004, 0x90000000);

    /* DAR 0x0120 can be used to check if hung */

    /* DDR */
    CAAM_WRITE(0x0124, 1);

    return Success;
}


/* free the page and dealloc */
static Error caamFreePage(unsigned char page)
{
    /* owns the page can dealloc it */
    CAAM_WRITE(CAAM_SM_CMD, (page << 16) | 0x2);
    while ((CAAM_READ(CAAM_SM_STATUS) & 0x00004000) > 0 &&
        (CAAM_READ(CAAM_SM_STATUS) & 0x00003000)  == 0) {
        CAAM_CPU_CHILL();
    }
    if ((CAAM_READ(CAAM_SM_STATUS) & 0x00003000)  > 0) {
        /* error while deallocating page */
        WOLFSSL_MSG("error while deallocating page");
        return MemoryMapMayNotBeEmpty; /* PSP set on page or is unavailable */
    }
    WOLFSSL_MSG("free'd page");
    return Success;
}

/* free the partition and dealloc */
Error caamFreePart(int part)
{
    unsigned int status;

    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
    printf("freeing partition %d\n", part);
    #endif
    CAAM_WRITE(CAAM_SM_CMD, (part << 8) | 0x3);

    status = CAAM_READ(CAAM_SM_STATUS);
    while ((status & 0x00004000) > 0 && (status & 0x00003000) == 0) {
        CAAM_CPU_CHILL();
        status = CAAM_READ(CAAM_SM_STATUS);
    }

    if (((status & 0x00003000) > 0) || ((status & 0x0000C000) > 0)) {
        /* error while deallocating page */
        WOLFSSL_MSG("error while deallocating partition");
        return MemoryMapMayNotBeEmpty; /* PSP set on page or is unavailable */
    }
    WOLFSSL_MSG("free'd partition");
    return Success;
}


/* find all partitions we own and free them */
static Error caamFreeAllPart()
{
    unsigned int SMPO;
    int i;

    WOLFSSL_MSG("Free all partitions");
    SMPO = CAAM_READ(0x1FBC);
    for (i = 0; i < 15; i++) {
        if ((SMPO & (0x3 << (i * 2))) == (0x3U << (i * 2))) {
            caamFreePart(i);
        }
    }

    return 0;
}


/* search through the partitions to find an unused one
 * returns negative value on failure, on success returns 0 or greater
 */
int caamFindUnusuedPartition()
{
    unsigned int SMPO;
    int i, ret = -1;

    SMPO = CAAM_READ(0x1FBC);
    for (i = 0; i < 15; i++) {
        if ((SMPO & (0x3 << (i * 2))) == 0) {
            ret = i;
            break;
        }
    }

    return ret;
}


/* flag contains how the parition is set i.e CSP flag and read/write access
 *      it also contains if locked
 */
static Error caamCreatePartition(unsigned char page, unsigned char par,
        unsigned int flag)
{

    unsigned int status;

    /* check ownership of partition */
    status = CAAM_READ(0x1FBC);
    if ((status & (0x3 << (par * 2))) > 0) {
        if ((status & (0x3 << (par * 2))) == (0x3U << (par * 2))) {
            WOLFSSL_MSG("we own this partition!");
        }
        else {
            return MemoryMapMayNotBeEmpty;
        }
    }

    CAAM_WRITE(0x1A04 + (par * 16), flag);

    /* dealloc page if we own it */
    CAAM_WRITE(CAAM_SM_CMD, (page << 16) | 0x5);
    while ((CAAM_READ(CAAM_SM_STATUS) & 0x00004000) > 0 &&
       (CAAM_READ(CAAM_SM_STATUS) & 0x00003000)  == 0) {
        CAAM_CPU_CHILL();
    }
    if ((CAAM_READ(CAAM_SM_STATUS) & 0x000000C0) == 0xC0) {
        if (caamFreePage(page) != Success) {
            return MemoryMapMayNotBeEmpty;
        }
    }
    else if ((CAAM_READ(CAAM_SM_STATUS) & 0x000000C0) == 0x00) {
        WOLFSSL_MSG("page available and un-owned");
    }
    else {
        WOLFSSL_MSG("we don't own the page...");
        return -1;
    }

    CAAM_WRITE(CAAM_SM_CMD, (page << 16) | (par << 8) | 0x1);
    /* wait for alloc cmd to complete */
    while ((CAAM_READ(CAAM_SM_STATUS) & 0x00004000) > 0 &&
       (CAAM_READ(CAAM_SM_STATUS) & 0x00003000)  == 0) {
        CAAM_CPU_CHILL();
    }

    return Success;
}


/* return a mapped address to the partition on success, returns 0 on fail */
CAAM_ADDRESS caamGetPartition(int part, int partSz, unsigned int* phys,
        unsigned int flag)
{
    int err;
    CAAM_ADDRESS vaddr;
    unsigned int local;

    (void)flag; /* flag is for future changes to flag passed when creating */

    /* create and claim the partition */
    err = caamCreatePartition(part, part, CAAM_SM_CSP | CAAM_SM_SMAP_LOCK |
                CAAM_SM_CSP | CAAM_SM_ALL_RW);
    if (err != Success) {
        WOLFSSL_MSG("Error creating partiions for secure ecc key");
        return 0;
    }

    /* map secure partition to virtual address */
    local = (CAAM_PAGE + (part << 12));
    vaddr = CAAM_ADR_TO_VIRTUAL(local, partSz);
    if (phys != NULL) {
        *phys = local;
    }
    return vaddr;
}


/* Gets the status of a job. Returns CAAM_WAITING if no output jobs ready to be
 * read.
 * If no jobs are done then return CAAM_WAITING
 * If jobs are done but does not match desc then return NoActivityReady
 * Status holds the error values if any */
static Error caamGetJob(struct CAAM_DEVICE* dev, unsigned int* status)
{
    unsigned int reg;
    if (status) {
        *status = 0;
    }

#ifdef CAAM_DEBUG_MODE
    (void)dev;
    return Success;
#endif

    /* Check number of done jobs in output list */
    reg = CAAM_READ(0x103C);
#if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
    printf("number of jobs in output list = 0x%08X\n", reg);
#endif
    if ((reg & 0x000003FF) > 0) {
        unsigned int *pt;

        if (CAAM_ADR_SYNC(caam.ring.VirtualOut, (2 * CAAM_JOBRING_SIZE *
                        sizeof(unsigned int))) != 0) {
            return -1;
        }

        /* sanity check on job out */
        pt = (unsigned int*)caam.ring.VirtualOut;
        if (pt[0] != caam.ring.Desc) {
            return -1;
        }
    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
        printf("\tjob 0x%08X done - result 0x%08X\n", pt[0], pt[1]);
    #endif
        *status = pt[1];

        /* increment jobs removed */
    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
        printf("removing job from list\n");
        fflush(stdout);
    #endif
        CAAM_WRITE(0x1034, 1);
    }
    else {
        /* check if the CAAM is idle and not processing any descriptors */
        if ((CAAM_READ(0x0FD4) & 0x00000002) == 2 /* idle */
        && (CAAM_READ(0x0FD4) & 0x00000001) == 0) {
            WOLFSSL_MSG("caam is idle.....");
            return NoActivityReady;
        }
        return CAAM_WAITING;
    }
    (void)dev;

    CAAM_WRITE(JRCFGR_JR0_LS, 0);
    if (*status == 0) {
        return Success;
    }
    return Failure;
}


#if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
/* debug print out JDKEK */
static void print_jdkek()
{
    int i;

    printf("JDKEK = ");
    for (i = 0; i < 8; i++) {
        printf("%08X ", CAAM_READ(0x0400 + (i*4)));
    }
    printf("\n");
}
#endif


/* instantiate RNG and create JDKEK, TDKEK, and TDSK key */
static unsigned int wc_rng_start[] = {
    CAAM_HEAD | 0x00000006,
    CAAM_OP | CAAM_CLASS1 | CAAM_RNG | 0x00000004, /* Instantiate RNG handle 0 with TRNG */
    CAAM_JUMP | 0x02000001,  /* wait for Class1 RNG and jump to next cmd */
    CAAM_LOAD | 0x00880004,  /* Load to clear written register */
    0x00000001, /* reset done interrupt */
    CAAM_OP | CAAM_CLASS1 | CAAM_RNG | 0x00001000   /* Generate secure keys */
};



/* Initialize CAAM RNG
 * returns 0 on success */
int caamInitRng(struct CAAM_DEVICE* dev);
int caamInitRng(struct CAAM_DEVICE* dev)
{
    DESCSTRUCT desc;
    unsigned int reg, status;
    int ret = 0;

    memset(&desc, 0, sizeof(DESCSTRUCT));

    /* Set up use of the TRNG for seeding wolfSSL HASH-DRBG */
    /* check out the status and see if already setup */
    CAAM_WRITE(CAAM_RTMCTL, CAAM_PRGM);
    CAAM_WRITE(CAAM_RTMCTL, CAAM_READ(CAAM_RTMCTL) | 0x40); /* reset */

    /* Set up reading from TRNG */
    CAAM_WRITE(CAAM_RTMCTL, CAAM_READ(CAAM_RTMCTL) | CAAM_TRNG);

    /* Set up delay for TRNG @TODO Optimizations?
     * Shift left with RTSDCTL because 0-15 is for sample number
     * Also setting the max and min frequencies */
    CAAM_WRITE(CAAM_RTSDCTL, (CAAM_ENT_DLY << 16) | 0x09C4);
    CAAM_WRITE(CAAM_RTFRQMIN, CAAM_ENT_DLY >> 1); /* 1/2      */
    CAAM_WRITE(CAAM_RTFRQMAX, CAAM_ENT_DLY << 3); /* up to 8x */

    /* Set back to run mode and clear RTMCL error bit */
    reg = CAAM_READ(CAAM_RTMCTL) ^ CAAM_PRGM;

    CAAM_WRITE(CAAM_RTMCTL, reg);
    reg = CAAM_READ(CAAM_RTMCTL);
    reg |= CAAM_CTLERR;
    CAAM_WRITE(CAAM_RTMCTL, reg);

    /* check out the status and see if already setup */
    reg = CAAM_READ(CAAM_RDSTA);
    if (((reg >> 16) & 0xF) > 0) {
        WOLFSSL_MSG("RNG is in error state");
        caamReset();
    }

    if (reg & (1 << 30)) {
        WOLFSSL_MSG("JKDKEK rng was setup using a non determinstic key");
        return 0;
    }

    if (CAAM_READ(0x1014) > 0) {
        int i;
    #ifdef CAAM_DEBUG_MODE
        for (i = 0; i < 6; i++)
            desc.desc[desc.idx++] = wc_rng_start[i];

        desc.caam = dev;
        ret = caamDoJob(&desc);
    #else
       unsigned int *pt = (unsigned int*)caam.ring.VirtualDesc;
       for (i = 0; i < 6; i++)
          pt[i] = wc_rng_start[i];
       pt    = (unsigned int*)caam.ring.VirtualIn;
       pt[0] = (unsigned int)caam.ring.Desc;

        /* start process */
    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
        printf("incrementing job count\n");
        fflush(stdout);
    #endif
        CAAM_WRITE(CAAM_IRJAR0, 0x00000001);
    #endif
    }
    else {
        return CAAM_WAITING;
    }

    do {
        ret = caamGetJob(dev, &status);
        CAAM_CPU_CHILL();
    } while (ret == CAAM_WAITING);

    if (ret == Success)
        return 0;
    return -1;
}


/* Take in a descriptor and add it to the job list */
Error caamAddJob(DESCSTRUCT* desc)
{
    /* clear and set desc size */
    desc->desc[0] &= 0xFFFFFF80;
    desc->desc[0] += desc->idx + (desc->startIdx << 16);

    CAAM_LOCK_MUTEX(&caam.ring.jr_lock);
    /* check input slot is available and then add */
    if (CAAM_READ(0x1014) > 0) {
        int i;
        unsigned int *pt;

        pt = (unsigned int*)caam.ring.VirtualDesc;
    #if defined(WOLFSSL_CAAM_PRINT)
        printf("Doing Job :\n");
    #endif
        for (i = 0; i < desc->idx; i++) {
            pt[i] = desc->desc[i];
    #if defined(WOLFSSL_CAAM_PRINT)
            printf("\tCMD %02d [%p] = 0x%08X\n", i+1, pt + i,
                  desc->desc[i]);
    #endif
        }

        pt    = (unsigned int*)caam.ring.VirtualIn;
        pt[0] = (unsigned int)caam.ring.Desc;

        if (CAAM_ADR_SYNC(caam.ring.VirtualDesc,
                    desc->idx * sizeof(unsigned int)) != 0) {
            return -1;
        }

        if (CAAM_ADR_SYNC(caam.ring.VirtualIn,
                    CAAM_JOBRING_SIZE * sizeof(unsigned int)) != 0) {
            return -1;
        }

    #ifdef CAAM_DEBUG_MODE
        caamDebugDesc(desc);
    #else
        #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
        printf("started job 0x%08X done\n", (unsigned int)caam.ring.Desc);
        #endif
        CAAM_WRITE(CAAM_IRJAR0, 0x00000001);
    #endif
    }
    else {
        #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
        printf("SLOT = 0x%08X, IRJAR0 = 0x%08X\n", CAAM_READ(0x1014),
                CAAM_READ(CAAM_IRJAR0));
        printf("Number of job in done queue = 0x%08X\n", CAAM_READ(0x103C));
        #endif
        CAAM_UNLOCK_MUTEX(&caam.ring.jr_lock);
        return CAAM_WAITING;
    }
    CAAM_UNLOCK_MUTEX(&caam.ring.jr_lock);
    return Success;
}


/* Synchronous job completion, add it to job queue and wait till finished */
Error caamDoJob(DESCSTRUCT* desc)
{
    Error ret;
    unsigned int status;

    ret = caamAddJob(desc);
    if (ret != Success) {
        return ret;
    }

    do {
        ret = caamGetJob(desc->caam, &status);
        CAAM_CPU_CHILL();
    } while (ret == CAAM_WAITING);

    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
    printf("job status = 0x%08X, ret = %d\n", status, ret);
    #endif

    if (status != 0 || ret != Success) {
        /* try to reset after error */
    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
        int i;
        for (i = 0; i < desc->idx; i++) {
            printf("\tCMD %02d = 0x%08X\n", i+1, desc->desc[i]);
        }
        printf("\n");
    #endif
        /* consider any job ring errors as fatal, and try reset */
        if (caamParseJRError(CAAM_READ(JRINTR_JR0)) != 0) {
            caamReset();
        }
        caamParseError(status);
        return ret;
    }

    return Success;
}


/******************************************************************************
  CAAM Blob Operations
  ****************************************************************************/

/* limit on size due to size of job ring being 64 unsigned int's */
int caamBlob(DESCSTRUCT* desc)
{
    void *vaddrOut, *vaddr, *keymod;
    Error err;
    unsigned int keyType = 0x00000C08; /* default red */
    unsigned int i = 0;
    int inputSz;
    int outputSz;

    if (desc->idx + 3 > MAX_DESC_SZ) {
        return Failure;
    }

    /* doing black blobs */
    if (desc->state) {
        WOLFSSL_MSG("making a black blob");
        keyType = 0x00000010;
    }

    desc->desc[desc->idx++] = (CAAM_LOAD_CTX | CAAM_CLASS2 | keyType);

    /* add key modifier */
    keymod = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(keymod, desc->buf[i].dataSz);
    i++;

    inputSz = desc->buf[i].dataSz;
    if (desc->state && (desc->type == CAAM_BLOB_ENCAP)) {
        /* black keys with CCM have mac at the end */
        inputSz += 16;
    }

    vaddr = CAAM_ADR_MAP(desc->buf[i].data, inputSz, 1);

    /* add input */
    desc->desc[desc->idx++] = CAAM_SEQI + desc->buf[i].dataSz;
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr, inputSz);
    i++;
    desc->outputIdx = i;

    outputSz = desc->buf[i].dataSz;
    if (desc->state && (desc->type == CAAM_BLOB_DECAP)) {
        /* black keys with CCM have mac at the end */
        outputSz += 16;
    }
    vaddrOut = CAAM_ADR_MAP(desc->buf[i].data, outputSz, 0);

    /* add output */
    desc->desc[desc->idx++] = CAAM_SEQO + desc->buf[i].dataSz;
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddrOut, outputSz);
    if (desc->idx + 1 > MAX_DESC_SZ) {
        return Failure;
    }
    desc->desc[desc->idx] = CAAM_OP |  CAAM_OPID_BLOB | desc->type;

    if (desc->state) {
        desc->desc[desc->idx] |= 0x104; /* EKT and Black_key (key is covered) */
    }
    desc->idx++;
    do {
        err = caamDoJob(desc);
    } while (err == CAAM_WAITING);

    CAAM_ADR_UNMAP(keymod, desc->buf[0].data, desc->buf[0].dataSz, 0);
    CAAM_ADR_UNMAP(vaddr, desc->buf[1].data, inputSz, 0);
    CAAM_ADR_UNMAP(vaddrOut, desc->buf[2].data, outputSz, 1);

    return err;
}


/******************************************************************************
  CAAM AES Operations
  ****************************************************************************/

int caamAesCmac(DESCSTRUCT* desc, int sz, unsigned int args[4])
{
    Error err;
    unsigned int keySz;
    unsigned int macSz = 0;
    void *vaddr[4] = {0};
    unsigned int vidx = 0;
    unsigned int ctx;
    unsigned int isBlackKey;
    int i;

    isBlackKey = args[2];
    keySz = args[1];

    /* Get CTX physical address */
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[1].data, desc->buf[1].dataSz, 1);
    ctx = CAAM_ADR_TO_PHYSICAL(vaddr[vidx], desc->buf[1].dataSz);
    vidx++;

    /* LOAD KEY */
    desc->desc[desc->idx] = (CAAM_KEY | CAAM_CLASS1 | CAAM_NWB) + keySz;
    if (isBlackKey) {
        desc->desc[desc->idx] |= CAAM_LOAD_BLACK_KEY;
        macSz = 16; /* copy over 16 additional bytes to account for mac */
    }
    desc->idx++;
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[0].data, desc->buf[0].dataSz + macSz, 1);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
            desc->buf[0].dataSz + macSz);
    #if 0
    {
        unsigned int p; byte* pt = (byte*)vaddr[vidx];
        printf("Using key [%d]:", desc->buf[0].dataSz + macSz);
        for (p = 0; p < keySz; p++)
            printf("%02X", pt[p]);
        printf("\n");
    }
    #endif
    vidx++;

    /* Load in CTX only when not initialization */
    if ((desc->state & CAAM_ALG_INIT) == 0) {
        int ofst = 0;
        desc->desc[desc->idx++] = (CAAM_LOAD_CTX | CAAM_CLASS1 | ofst) +
            desc->buf[1].dataSz;
        desc->desc[desc->idx++] = ctx;

        #if 0
        {
            unsigned int z; byte* pt = (byte*)vaddr[0];
            printf("loading in CTX [%d] :", desc->buf[1].dataSz);
            for (z = 0; z < 32; z++)
                printf("%02X", pt[z]);
            printf("\n");
        }
        #endif
    }

    /* add protinfo to operation command */
    desc->desc[desc->idx++] = CAAM_OP | CAAM_CLASS1 | desc->type | desc->state;


    /* add in all input buffers */
    for (i = 2; i < sz; i++) {
        desc->desc[desc->idx] = (CAAM_FIFO_L | CAAM_CLASS1 | FIFOL_TYPE_MSG)
            + desc->buf[i].dataSz;
        if (i+1 == sz) {
            /* this is the last input buffer, signal the HW with LC1 bit */
            desc->desc[desc->idx] |= FIFOL_TYPE_LC1;
        }
        desc->idx++;

        vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);

        #if 0
        {
            unsigned int z; byte* pt = (byte*)vaddr[vidx];
            printf("MSG [%d] :", desc->buf[i].dataSz);
            for (z = 0; z < desc->buf[i].dataSz; z++)
                printf("%02X", pt[z]);
            printf("\n");
        }
        #endif

        vidx++;

    }

    /* if there is no input buffers than add in a single FIFO LOAD to kick off
     * the operation */
    if (sz == 2) { /* only key and ctx buffer */
        desc->desc[desc->idx++] = CAAM_FIFO_L | FIFOL_TYPE_LC1 | CAAM_CLASS1 |
            FIFOL_TYPE_MSG;
        vaddr[vidx] = CAAM_ADR_MAP(0, 0, 0);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx], 0);
        vidx++;
    }

    desc->desc[desc->idx++] = CAAM_STORE_CTX | CAAM_CLASS1 | 32;
    desc->desc[desc->idx++] = ctx;

    do {
        err = caamDoJob(desc);
    } while (err == CAAM_WAITING);

    #if 0
    {
        unsigned int z; byte* pt = (byte*)vaddr[0];
        printf("CTX: ");
        for (z = 0; z < 32; z++)
            printf("%02X", pt[z]);
        printf("\n");
    }
    #endif

    CAAM_ADR_UNMAP(vaddr[0], desc->buf[1].data, desc->buf[1].dataSz, 1);
    CAAM_ADR_UNMAP(vaddr[1], desc->buf[0].data, desc->buf[0].dataSz + macSz, 0);
    for (vidx = 2, i = 2; i < sz; i++) { /* unmap the input buffers */
        CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0);
    }
    return err;
}


#if defined(__INTEGRITY) || defined(INTEGRITY)
/* returns amount written on success and negative value in error case.
 * Is different from caamAddIO in that it only adds a single input buffer
 * rather than multiple ones.
 */
static int caamAesInput(struct DescStruct* desc, unsigned int* idx, int align,
    unsigned int totalSz)
{
    int sz;
    unsigned int i = *idx;

    /* handle alignment constraints on input */
    if (desc->alignIdx > 0) {
        sz = desc->alignIdx;

        /* if there is more input buffers then add part of it */
        if (i < desc->outputIdx && i < desc->DescriptorCount) {
            sz = align - desc->alignIdx;
            sz = (sz <= desc->buf[i].dataSz) ? sz : desc->buf[i].dataSz;
            memcpy((unsigned char*)(desc->alignBuf) + desc->alignIdx,
                   (unsigned char*)(desc->buf[i].data), sz);

            desc->buf[i].dataSz -= sz;
            desc->buf[i].data   += sz;
            sz += desc->alignIdx;
        }

        if (desc->idx + 2 > MAX_DESC_SZ) {
            return -1;
        }
        ASP_FlushCaches((CAAM_ADDRESS)desc->alignBuf, sz);
        desc->desc[desc->idx++] = (CAAM_FIFO_L | FIFOL_TYPE_LC1 |
                                   CAAM_CLASS1 | FIFOL_TYPE_MSG) + sz;
        desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->alignBuf);
        desc->alignIdx = 0;
    }
    else {
        sz = desc->buf[i].dataSz;
        if ((totalSz + sz) == desc->inputSz) { /* not an issue on final */
            align = 1;
        }

        desc->alignIdx = sz % align;
        if (desc->alignIdx != 0) {
            sz -= desc->alignIdx;
            memcpy((unsigned char*)desc->alignBuf,
                   (unsigned char*)(desc->buf[i].data) + sz,
                   desc->alignIdx);
        }

        if (desc->idx + 2 > MAX_DESC_SZ) {
            return -1;
        }
        desc->desc[desc->idx++] = (CAAM_FIFO_L | FIFOL_TYPE_LC1 |
                                   CAAM_CLASS1 | FIFOL_TYPE_MSG) + sz;
        desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->buf[i].data);
        i++;
    }

    *idx = i;
    return sz;
}


/* returns enum Success on success, all other return values should be
 * considered an error.
 *
 * ofst    is the amount of leftover buffer from previous calls
 * inputSz is the amount of input in bytes that is being matched to output
 */
static Error caamAesOutput(struct DescStruct* desc, int* ofst, unsigned int inputSz)
{
    int offset = *ofst;

    if (desc->output != 0 && offset > 0 && inputSz > 0) {
        unsigned int addSz;

        /* handle potential leftovers */
        addSz = (inputSz >= offset) ? offset : inputSz;

        inputSz -= addSz;
        desc->desc[desc->idx++] = CAAM_FIFO_S | FIFOS_TYPE_MSG + addSz;
        if (inputSz > 0) { /* check if expecting more output */
            desc->desc[desc->idx - 1] |= CAAM_FIFOS_CONT;
        }
        desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->output);

        if (addSz == offset) {
            /* reset */
            desc->output = 0;
            offset       = 0;
        }
        else {
            offset -= addSz;
            desc->output += addSz;

            if (offset < 0) {
                return TransferFailed;
            }
        }
    }

    for (; desc->lastIdx < desc->DescriptorCount; desc->lastIdx++) {
        struct buffer* buf = &desc->buf[desc->lastIdx];

        if (inputSz > 0) {
            int tmp;

            if (buf->dataSz <= inputSz) {
                tmp = buf->dataSz;
            }
            else {
                offset = buf->dataSz - inputSz;
                tmp    = inputSz;
                desc->output = buf->data + tmp;
            }
            inputSz -= tmp;
            if (desc->idx + 2 > MAX_DESC_SZ) {
                return TransferFailed;
            }
            desc->desc[desc->idx++] = CAAM_FIFO_S | FIFOS_TYPE_MSG + tmp;
            if (inputSz > 0) { /* check if expecting more output */
                desc->desc[desc->idx - 1] |= CAAM_FIFOS_CONT;
            }
            desc->desc[desc->idx++] = BSP_VirtualToPhysical(buf->data);
        }
        else {
            break;
        }
    }

    *ofst = offset;
    return Success;
}


/* check size of output and get starting buffer for it */
static Error caamAesOutSz(struct DescStruct* desc, unsigned int i)
{
    int sz = 0;

    for (desc->outputIdx = i; desc->outputIdx < desc->DescriptorCount &&
    sz < desc->inputSz; desc->outputIdx++) {
        sz += desc->buf[desc->outputIdx].dataSz;
    }
    desc->lastIdx = desc->outputIdx;

    /* make certain that output size is same as input */
    sz = 0;
    for (; desc->lastIdx < desc->DescriptorCount; desc->lastIdx++) {
        sz += desc->buf[desc->lastIdx].dataSz;
    }
    if (sz != desc->inputSz) {
        return SizeIsTooLarge;
    }
    desc->lastIdx = desc->outputIdx;

    return Success;
}


/* AES operations follow the buffer sequence of KEY -> (IV) -> Input -> Output
 */
static Error caamAes(struct DescStruct* desc)
{
    struct buffer* ctx[3];
    struct buffer* iv[3];
    Value ofst = 0;
    Error err;
    unsigned int i, totalSz = 0;
    int ctxIdx = 0;
    int ivIdx  = 0;
    int offset = 0;
    int align  = 1;
    int sz     = 0;

    int ctxSz = desc->ctxSz;

    if (desc->state != CAAM_ENC && desc->state != CAAM_DEC) {
        return IllegalStatusNumber;
    }

    if (ctxSz != 16 && ctxSz != 24 && ctxSz != 32) {
        return ArgumentError;
    }

    /* get key */
    for (i = 0; i < desc->DescriptorCount; i++) {
        struct buffer* buf = &desc->buf[i];
        unsigned char* local = (unsigned char*)desc->ctxBuf;

        if (sz < ctxSz && sz < (MAX_CTX * sizeof(unsigned int))) {
            ctx[ctxIdx] = buf;
            sz += buf->dataSz;

            memcpy((unsigned char*)&local[offset],
                   (unsigned char*)ctx[ctxIdx]->data, ctx[ctxIdx]->dataSz);
            offset += ctx[ctxIdx]->dataSz;
            ctxIdx++;
        }
        else {
            break;
        }
    }

    /* sanity checks on size of key */
    if (sz > ctxSz) {
        return SizeIsTooLarge;
    }
    if (ctxSz > (MAX_CTX * sizeof(unsigned int)) - 16) {
        return ArgumentError;
    }

    /* Flush cache of ctx buffer then :
       Add KEY Load command          0x0220000X
       Add address to read key from  0xXXXXXXXX */
    ASP_FlushCaches((CAAM_ADDRESS)desc->ctxBuf, ctxSz);
    if (desc->idx + 2 > MAX_DESC_SZ) {
        return TransferFailed;
    }
    desc->desc[desc->idx++] = (CAAM_KEY | CAAM_CLASS1 | CAAM_NWB) + ctxSz;
    desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->ctxBuf);

    /* get IV if needed by algorithm */
    switch (desc->type) {
        case CAAM_AESECB:
            break;

        case CAAM_AESCTR:
            ofst = 0x00001000;
            /* fall through because states are the same only the offset changes */

        case CAAM_AESCBC:
        {
            int maxSz = 16; /* default to CBC/CTR max size */

            sz = 0;
            offset = 0;
            for (; i < desc->DescriptorCount; i++) {
                struct buffer* buf = &desc->buf[i];
                unsigned char* local = (unsigned char*)desc->iv;

                if (sz < maxSz) {
                    iv[ivIdx] = buf;

                    if (buf->dataSz + sz > maxSz) {
                        return SizeIsTooLarge;
                    }

                    sz += buf->dataSz;
                    memcpy((unsigned char*)&local[offset],
                        (unsigned char*)iv[ivIdx]->data, iv[ivIdx]->dataSz);
                    offset += iv[ivIdx]->dataSz;
                    ivIdx++;
                }
                else {
                    break;
                }
            }

            if (sz != maxSz) {
                /* invalid IV size */
                return SizeIsTooLarge;
            }

            ASP_FlushCaches((CAAM_ADDRESS)desc->iv, maxSz);
            if (desc->idx + 2 > MAX_DESC_SZ) {
                return TransferFailed;
            }
            desc->desc[desc->idx++] = (CAAM_LOAD_CTX | CAAM_CLASS1 | ofst) + maxSz;
            desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->iv);
         }
         break;

        default:
            return OperationNotImplemented;
    }

    /* write operation */
    if (desc->idx + 1 > MAX_DESC_SZ) {
        return TransferFailed;
    }
    desc->desc[desc->idx++] = CAAM_OP | CAAM_CLASS1 | desc->type |
             CAAM_ALG_UPDATE | desc->state;

    /* find output buffers */
    if (caamAesOutSz(desc, i) != Success) {
        return SizeIsTooLarge;
    }

    /* set alignment constraints */
    if (desc->type == CAAM_AESCBC || desc->type == CAAM_AESECB) {
        align = 16;
    }

    /* indefinite loop for input/output buffers */
    desc->headIdx = desc->idx;
    desc->output  = 0;
    offset = 0; /* store left over amount for output buffer */
    do {
        desc->idx = desc->headIdx; /* reset for each loop */

        /* add a single input buffer (multiple ones was giving deco watch dog
         * time out errors on the FIFO load of 1c.
         * @TODO this could be a place for optimization if more data could be
         * loaded in at one time */
        if ((sz = caamAesInput(desc, &i, align, totalSz)) < 0) {
            return TransferFailed;
        }
        totalSz += sz;

        if (caamAesOutput(desc, &offset, sz) != Success) {
            return TransferFailed;
        }

        /* store updated IV */
        if (ivIdx > 0) {
            if (desc->idx + 2 > MAX_DESC_SZ) {
                return TransferFailed;
            }
            desc->desc[desc->idx++] = CAAM_STORE_CTX | CAAM_CLASS1 | ofst | 16;
            desc->desc[desc->idx++] = BSP_VirtualToPhysical((CAAM_ADDRESS)desc->iv);
        }

        if ((err = caamDoJob(desc)) != Success) {
            return err;
        }
        ASP_FlushCaches((CAAM_ADDRESS)desc->iv, 16);
    } while (desc->lastIdx < desc->DescriptorCount || offset > 0);

    /* flush output buffers */
    for (i = desc->outputIdx; i < desc->lastIdx; i++) {
        ASP_FlushCaches(desc->buf[i].data, desc->buf[i].dataSz);
    }

    /* handle case with IV */
    if (ivIdx > 0) {
        unsigned char* pt = (unsigned char*)desc->iv;
        ASP_FlushCaches((CAAM_ADDRESS)pt, 16);
        for (i = 0; i < ivIdx; i++) {
            memcpy((unsigned char*)iv[i]->data, pt, iv[i]->dataSz);
            pt += iv[i]->dataSz;
            ASP_FlushCaches(iv[i]->data, iv[i]->dataSz);
        }
    }

    return Success;
}
#endif


/******************************************************************************
  CAAM AEAD Operations
  ****************************************************************************/

#if defined(__INTEGRITY) || defined(INTEGRITY)
/* AEAD operations follow the buffer sequence of KEY -> (IV or B0 | CTR0) -> (AD)
 * -> Input -> Output
 *
 */
static Error caamAead(struct DescStruct* desc)
{
    struct buffer* ctx[3];
    struct buffer* iv[3];
    Value ofst    = 0;
    unsigned int state   = CAAM_ALG_INIT;
    unsigned int totalSz = 0;
    Error err;
    unsigned int i;
    int ctxIdx = 0;
    int ivIdx  = 0;
    int offset = 0;
    int sz     = 0;
    int ivSz   = 32; /* size of B0 | CTR0 for CCM mode */
    int ctxSz  = desc->ctxSz;
    int align  = 16; /* input should be multiples of 16 bytes unless is final */
    int opIdx;

    if (desc->state != CAAM_ENC && desc->state != CAAM_DEC) {
        return IllegalStatusNumber;
    }

    /* sanity check is valid AES key size */
    if (ctxSz != 16 && ctxSz != 24 && ctxSz != 32) {
        return ArgumentError;
    }

    /* get key */
    for (i = 0; i < desc->DescriptorCount; i++) {
        struct buffer* buf = &desc->buf[i];
        unsigned char* local = (unsigned char*)desc->ctxBuf;

        if (sz < ctxSz && sz < (MAX_CTX * sizeof(unsigned int))) {
            ctx[ctxIdx] = buf;
            sz += buf->dataSz;

            memcpy((unsigned char*)&local[offset],
                   (unsigned char*)ctx[ctxIdx]->data, ctx[ctxIdx]->dataSz);
            offset += ctx[ctxIdx]->dataSz;
            ctxIdx++;
        }
        else {
            break;
        }
    }

    /* sanity checks on size of key */
    if (sz > ctxSz) {
        return SizeIsTooLarge;
    }

    /* Flush cache of ctx buffer then :
       Add KEY Load command          0x0220000X
       Add address to read key from  0xXXXXXXXX */
    ASP_FlushCaches((CAAM_ADDRESS)desc->ctxBuf, ctxSz);
    if (desc->idx + 2 > MAX_DESC_SZ) {
        return TransferFailed;
    }
    desc->desc[desc->idx++] = (CAAM_KEY | CAAM_CLASS1 | CAAM_NWB) + ctxSz;
    desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->ctxBuf);

    desc->headIdx = desc->idx;
    desc->output  = 0;
    offset = 0; /* store left over amount for output buffer */
    do {
        desc->idx = desc->headIdx; /* reset for each loop */

        /* write operation */
        if (desc->idx + 1 > MAX_DESC_SZ) {
            return TransferFailed;
        }
        opIdx = desc->idx;
        desc->desc[desc->idx++] = CAAM_OP | CAAM_CLASS1 | state | desc->type |
                                  desc->state;

        /* get IV if needed by algorithm */
        switch (desc->type) {
            case CAAM_AESCCM:
                if ((state & CAAM_ALG_INIT) == CAAM_ALG_INIT) {
                    sz = 0;
                    offset = 0;
                    for (; i < desc->DescriptorCount; i++) {
                        struct buffer* buf = &desc->buf[i];
                        unsigned char* local = (unsigned char*)desc->iv;

                        if (sz < ivSz) {
                            iv[ivIdx] = buf;

                            if (buf->dataSz + sz > ivSz) {
                                return SizeIsTooLarge;
                            }

                            sz += buf->dataSz;
                            memcpy((unsigned char*)&local[offset],
                            (unsigned char*)iv[ivIdx]->data, iv[ivIdx]->dataSz);
                            offset += iv[ivIdx]->dataSz;
                            ivIdx++;
                        }
                        else {
                            break;
                        }
                    }

                    if (sz != ivSz) {
                        /* invalid IV size */
                        return SizeIsTooLarge;
                    }
                    offset = 0;
                }

                ASP_FlushCaches((CAAM_ADDRESS)desc->iv, ivSz);
                if (desc->idx + 2 > MAX_DESC_SZ) {
                    return TransferFailed;
                }
                desc->desc[desc->idx++] = (CAAM_LOAD_CTX | CAAM_CLASS1 | ofst)
                                           + ivSz;
                desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->iv);
                break;

            default:
                return OperationNotImplemented;
        }


        /********* handle AAD -- is only done with Init **********************/
        if ((state & CAAM_ALG_INIT) == CAAM_ALG_INIT) {
            if ((desc->type == CAAM_AESCCM) && (desc->aadSz > 0)) {
                /* set formatted AAD buffer size for CCM */
                ASP_FlushCaches((CAAM_ADDRESS)desc->aadSzBuf, sizeof(desc->aadSzBuf));
                desc->desc[desc->idx++] = CAAM_FIFO_L | CAAM_CLASS1 |
                    FIFOL_TYPE_AAD + desc->aadSz;
                desc->desc[desc->idx++] = BSP_VirtualToPhysical(desc->aadSzBuf);

                /* now set aadSz to unformatted version for getting buffers */
                if (desc->aadSz == 2) {
                    unsigned char* pt = (unsigned char*)desc->aadSzBuf;
                    desc->aadSz = (((unsigned int)pt[0] & 0xFF) << 8) |
                           ((unsigned int)pt[1] & 0xFF);
                }
                else {
                    unsigned char* pt = (unsigned char*)desc->aadSzBuf;
                    desc->aadSz = (((unsigned int)pt[2] & 0xFF) << 24) |
                                  (((unsigned int)pt[3] & 0xFF) << 16) |
                                  (((unsigned int)pt[4] & 0xFF) <<  8) |
                                   ((unsigned int)pt[5] & 0xFF);
                }
            }

            /* get additional data buffers */
            if (desc->aadSz > 0) {
                sz = 0;
                for (; i < desc->DescriptorCount; i++) {
                    struct buffer* buf = &desc->buf[i];
                    if (sz < desc->aadSz) {
                        if (desc->idx + 2 > MAX_DESC_SZ) {
                            return TransferFailed;
                        }
                        desc->lastFifo = desc->idx;
                        desc->desc[desc->idx++] = CAAM_FIFO_L | CAAM_CLASS1 |
                                                  FIFOL_TYPE_AAD + buf->dataSz;
                        desc->desc[desc->idx++] = BSP_VirtualToPhysical(buf->data);
                        sz += buf->dataSz;
                    }
                    else {
                        break;
                    }
                }

                /* flush AAD from FIFO and pad it to 16 byte block */
                desc->desc[desc->lastFifo] |= FIFOL_TYPE_FC1;
            }

            /* find output buffers */
            if (caamAesOutSz(desc, i) != Success) {
                return SizeIsTooLarge;
            }
        }

        /* handle alignment constraints on input */
        if ((sz = caamAesInput(desc, &i, align, totalSz)) < 0) {
            return TransferFailed;
        }
        totalSz += sz;

        /* handle output buffers  */
        if (caamAesOutput(desc, &offset, sz) != Success) {
            return TransferFailed;
        }

        /* store updated IV, if is last then set offset and final for MAC */
        if ((desc->lastIdx == desc->DescriptorCount) && (offset == 0)) {
            ivSz = 16;
            if (desc->state == CAAM_ENC) {
                ofst = 32 << 8; /* offset is in 15-8 bits */
            }
            else {
                ofst = 0;
            }
            desc->desc[opIdx] |= CAAM_ALG_FINAL;
        }
        else {
            /* if not final then store and use ctr and encrypted ctr from
                context dword 2,3 and 4,5. Also store MAC and AAD info from
                context dword 6. */
            ivSz = 56;
            ofst = 0;
        }

        if (desc->idx + 2 > MAX_DESC_SZ) {
            return TransferFailed;
        }
        desc->desc[desc->idx++] = CAAM_STORE_CTX | CAAM_CLASS1 | ofst | ivSz;
        desc->desc[desc->idx++] = BSP_VirtualToPhysical((CAAM_ADDRESS)desc->iv);

        if ((err = caamDoJob(desc)) != Success) {
            return err;
        }
        state = CAAM_ALG_UPDATE;
    } while (desc->lastIdx < desc->DescriptorCount || offset > 0);

    /* flush output buffers */
    for (i = desc->outputIdx; i < desc->lastIdx; i++) {
        ASP_FlushCaches(desc->buf[i].data, desc->buf[i].dataSz);
    }

    /* handle case with IV (This is also the output of MAC with AES-CCM) */
    if (ivIdx > 0) {
        unsigned char* pt = (unsigned char*)desc->iv;
        ASP_FlushCaches((CAAM_ADDRESS)pt, ivSz);
        for (i = 0; i < ivIdx; i++) {
            memcpy((unsigned char*)iv[i]->data, pt, iv[i]->dataSz);
            pt += iv[i]->dataSz;
            ASP_FlushCaches(iv[i]->data, iv[i]->dataSz);
        }
    }

    return Success;
}
#endif


/* ECDSA generate black key
 *
 * return Success on success. All other return values are considered a fail
 *         case.
 */
int caamECDSAMake(DESCSTRUCT* desc, CAAM_BUFFER* buf, unsigned int args[4])
{
    Error err;
    int part = 0;
    unsigned int isBlackKey = 0;
    unsigned int pdECDSEL   = 0;
    unsigned int phys;
    void *vaddr[2];

    if (args != NULL) {
        isBlackKey = args[0];
        pdECDSEL   = args[1];
    }
    vaddr[0] = NULL;
    vaddr[1] = NULL;

    desc->desc[desc->idx++] = pdECDSEL;
    if (isBlackKey) {
        /* create secure partition for private key out */
        part = caamFindUnusuedPartition();
        if (part < 0) {
            WOLFSSL_MSG("error finding an unused partition for new key");
            return -1;
        }

        /* create and claim the partition */
        err = caamCreatePartition(part, part, CAAM_SM_CSP | CAAM_SM_SMAP_LOCK |
                CAAM_SM_CSP | CAAM_SM_ALL_RW);
        if (err != Success) {
            WOLFSSL_MSG("error creating partition for secure ecc key");
            return -1;
        }

        /* map secure partition to virtual address */
        phys = (CAAM_PAGE + (part << 12));
        buf[0].TheAddress = CAAM_ADR_TO_VIRTUAL(phys,
               buf[0].Length + buf[1].Length + 16);/*add 16 for MAC on private*/
        desc->desc[desc->idx++] = phys;

        /* public x,y out */
        buf[1].TheAddress = buf[0].TheAddress + 16 + buf[0].Length;
        desc->desc[desc->idx++] = phys + 16 + buf[0].Length;
    }
    else {
        vaddr[0] = CAAM_ADR_MAP(0, buf[0].Length, 0);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[0], buf[0].Length);

        vaddr[1] = CAAM_ADR_MAP(0, buf[1].Length, 0);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[1], buf[1].Length);
    }

    /* add protinfo to operation command */
    desc->startIdx = desc->idx;

    /* add operation command               OPTYPE        PROTOID */
    desc->desc[desc->idx] = CAAM_OP | CAAM_PROT_UNIDI | desc->type;
    if (isBlackKey) {
        desc->desc[desc->idx] |= CAAM_PKHA_ENC_PRI_AESCCM;
    }
    desc->desc[desc->idx++] |= CAAM_PKHA_ECC;

    do {
        err = caamDoJob(desc);
    } while (err == CAAM_WAITING);

    if (isBlackKey) {
        /* store partition number holding black keys */
        if (err != Success)
            caamFreePart(part);
        else
            args[2] = part;
    }
    else {
        /* copy non black keys out to buffers */
        CAAM_ADR_UNMAP(vaddr[0], buf[0].TheAddress, buf[0].Length, 1);
        CAAM_ADR_UNMAP(vaddr[1], buf[1].TheAddress, buf[1].Length, 1);
    }

    return err;
}


/* ECDSA verify signature
 *
 * return Success on success. All other return values are considered a fail
 *         case.
 */
int caamECDSAVerify(DESCSTRUCT* desc, CAAM_BUFFER* buf, int sz,
        unsigned int args[4])
{
    unsigned int isBlackKey = 0;
    unsigned int pdECDSEL   = 0;
    unsigned int msgSz = 0;
    unsigned int vidx = 0;
    unsigned int L;
    int i = 0;
    Error err;
    void* vaddr[sz];

    if (args != NULL) {
        isBlackKey = args[0];
        pdECDSEL   = args[1];
        msgSz      = args[2];
    }

    if (pdECDSEL == 0) {
        return -1;
    }
    else {
        L = args[3]; /* keysize */
        desc->desc[desc->idx++] = pdECDSEL;
    }

    /* public key */
    if (!isBlackKey) {
        vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
        vidx++;
    }
    else {
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL((void*)desc->buf[i].data,
                desc->buf[i].dataSz);
    }
    i++;

    /* message */
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
    vidx++; i++;

    /* r */
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
    vidx++; i++;

    /* s */
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
    vidx++; i++;

    /* tmp buffer */
    vaddr[vidx] = CAAM_ADR_MAP(0, 2*L, 0);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
            desc->buf[i].dataSz);
    vidx++; i++;

    if (msgSz > 0) {
        desc->desc[desc->idx++] = msgSz;
    }

    /* add protinfo to operation command */
    desc->startIdx = desc->idx;

    /* add operation command               OPTYPE        PROTOID */
    desc->desc[desc->idx] = CAAM_OP | CAAM_PROT_UNIDI | desc->type;
    if (msgSz > 0) {
        desc->desc[desc->idx] |= CAAM_ECDSA_MESREP_HASHED;
    }
    desc->desc[desc->idx++] |= CAAM_PKHA_ECC;

    do {
        err = caamDoJob(desc);
    } while (err == CAAM_WAITING);

    vidx = 0; i = 0;
    if (!isBlackKey) {
        CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0);
    }
    i++;

    /* msg , r, s, tmp */
    CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0); i++;
    CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0); i++;
    CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0); i++;
    CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0); i++;

    return err;
}


/* ECDSA generate signature
 *
 * return Success on success. All other return values are considered a fail
 *         case.
 */
int caamECDSASign(DESCSTRUCT* desc, int sz, unsigned int args[4])
{
    Error err;
    unsigned int isBlackKey = 0;
    unsigned int pdECDSEL   = 0;
    unsigned int msgSz = 0;
    unsigned int vidx = 0;
    int i = 0;
    void* vaddr[sz];

    if (args == NULL) {
        return -1;
    }

    isBlackKey = args[0];
    pdECDSEL   = args[1];
    msgSz      = args[2];
    if (pdECDSEL == 0) {
        return -1;
    }

    /* using parameters already in hardware */
    desc->desc[desc->idx++] = pdECDSEL;

    /* private key */
    if (!isBlackKey) {
        vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
    #if 0
        {
            unsigned int z; byte* pt;
            printf("private :");
            pt = (byte*)desc->buf[i].data;
            for (z = 0; z < desc->buf[i].dataSz; z++)
                printf("%02X", pt[z]);
            printf("\n");
        }
    #endif
        vidx++;
    }
    else {
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL((void*)desc->buf[i].data,
                desc->buf[i].dataSz);
    }
    i++;

    for (; i < sz; i++) {
        vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
    #if 0
        {
            unsigned int z;
            byte *pt = (byte*)vaddr[vidx];
            for (z = 0; z < desc->buf[i].dataSz; z++)
                printf("%02X", pt[z]);
            printf("\n");
        }
    #endif
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
        vidx++;
    }

    desc->desc[desc->idx++] = msgSz;

    /* add protinfo to operation command */
    desc->startIdx = desc->idx;

    /* add operation command               OPTYPE        PROTOID */
    desc->desc[desc->idx] = CAAM_OP | CAAM_PROT_UNIDI | desc->type;
    if (isBlackKey) { /* set flag to use AES-CCM with black key */
        desc->desc[desc->idx] |= CAAM_PKHA_ENC_PRI_AESCCM;
    }

    /* add protinfo to operation command */
    desc->desc[desc->idx++] |= CAAM_ECDSA_MESREP_HASHED | CAAM_PKHA_ECC;

    do {
        err = caamDoJob(desc);
    } while (err == CAAM_WAITING);

    vidx = 0; i = 0;
    if (!isBlackKey) {
        CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0);
    }
    i++;

    /* msg */
    CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 0); i++;

    /* copy out the r and s values */
    CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 1); i++;
    CAAM_ADR_UNMAP(vaddr[vidx++], desc->buf[i].data, desc->buf[i].dataSz, 1); i++;

    return err;
}


/* ECDH generate shared secret
 *
 * return Success on success. All other return values are considered a fail
 *         case.
 */
int caamECDSA_ECDH(DESCSTRUCT* desc, int sz, unsigned int args[4])
{
    Error err;
    unsigned int isBlackKey = 0;
    unsigned int peerBlackKey = 0;
    unsigned int pdECDSEL   = 0;
    unsigned int vidx = 0;
    int i = 0;
    void* vaddr[sz];

    if (args != NULL) {
        isBlackKey = args[0];
        peerBlackKey = args[1];
        pdECDSEL   = args[2];
    }

    if (pdECDSEL == 0) {
        return -1;
    }
    else {
        /* using parameters already in hardware */
        desc->desc[desc->idx++] = pdECDSEL;
    }

    /* public key */
    if (!peerBlackKey) {
        vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
    #if 0
        {
            unsigned int z; byte* pt;
            printf("pubkey :");
            pt = (byte*)desc->buf[i].data;
            for (z = 0; z < desc->buf[i].dataSz; z++)
                printf("%02X", pt[z]);
            printf("\n");
        }
    #endif
        vidx++;
    }
    else {
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL((void*)desc->buf[i].data,
                desc->buf[i].dataSz);
    }
    i++;

    /* private key */
    if (!isBlackKey) {
        vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
    #if 0
        {
            unsigned int z; byte* pt;
            printf("private :");
            pt = (byte*)desc->buf[i].data;
            for (z = 0; z < desc->buf[i].dataSz; z++)
                printf("%02X", pt[z]);
            printf("\n");
        }
    #endif
        vidx++;
    }
    else {
        desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL((void*)desc->buf[i].data,
                desc->buf[i].dataSz);
    }
    i++;

    /* shared output */
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
            desc->buf[i].dataSz);
    i++; vidx++;

    /* add protinfo to operation command */
    desc->startIdx = desc->idx;

    /* add operation command               OPTYPE        PROTOID */
    desc->desc[desc->idx] = CAAM_OP | CAAM_PROT_UNIDI | desc->type;
    if (isBlackKey) {
        desc->desc[desc->idx] |= CAAM_PKHA_ENC_PRI_AESCCM;
    }

    /* add protinfo to operation command */
    desc->desc[desc->idx++] |= CAAM_PKHA_ECC;

    do {
        err = caamDoJob(desc);
    } while (err == CAAM_WAITING);

    vidx = 0; i = 0;
    if (pdECDSEL == 0) {
        /* unmap prime key */
        CAAM_ADR_UNMAP(vaddr[vidx], desc->buf[i].data, desc->buf[i].dataSz, 0);
        vidx++; i++;
    }

    if (!peerBlackKey) {
        CAAM_ADR_UNMAP(vaddr[vidx], desc->buf[i].data, desc->buf[i].dataSz, 0);
        vidx++;
    }
    i++;

    if (!isBlackKey) {
        CAAM_ADR_UNMAP(vaddr[vidx], desc->buf[i].data, desc->buf[i].dataSz, 0);
        vidx++;
    }
    i++;
    CAAM_ADR_UNMAP(vaddr[vidx], desc->buf[i].data, desc->buf[i].dataSz, 1);
    vidx++; i++;

    if (pdECDSEL == 0) {
        /* unmap A , B*/
        CAAM_ADR_UNMAP(vaddr[vidx], desc->buf[i].data, desc->buf[i].dataSz, 0);
        vidx++; i++;
    }
    return err;
}


/******************************************************************************
  IODevice Start, Transfer and Finish Buffer
  ****************************************************************************/
/* If Entropy is not ready then return CAAM_WAITING */
int caamTRNG(unsigned char *out, int outSz)
{
    int sz = 0;

    CAAM_ADDRESS  reg; /* RTENT reg to read */
    unsigned char* local;
    int ofst = sizeof(unsigned int);

    /* Check ENT_VAL bit to make sure entropy is ready */
    if ((CAAM_READ(CAAM_RTMCTL) & CAAM_ENTVAL) != CAAM_ENTVAL) {
        return CAAM_WAITING;
    }

    /* check state of TRNG */
    if ((CAAM_READ(CAAM_RTSTATUS) & 0x0000FFFF) > 0) {
        return Failure;
    }

    /* read entropy from RTENT registers */
    reg   = CAAM_RTENT0;
    sz    = outSz;
    local = out;

    while (sz > 3 && reg <= CAAM_RTENT_MAX) {
        unsigned int data = CAAM_READ(reg);
        *((unsigned int*)local) = data;
        reg    += ofst;
        local  += ofst;
        sz     -= ofst;
    }

    if (reg > CAAM_RTENT_MAX && sz > 0) {
        return -1;//SizeIsTooLarge;
    }

    /* handle non unsigned int size amount left over */
    if (sz > 0) {
        unsigned int tmp = CAAM_READ(reg);
        memcpy(local, (unsigned char*)&tmp, sz);
    }

    /* read the max RTENT to trigger new entropy generation */
    if (reg != CAAM_RTENT_MAX) {
        CAAM_READ(CAAM_RTENT_MAX);
    }

    return Success;
}


/* cover a plain text key and make it a black key */
int caamKeyCover(DESCSTRUCT* desc, int sz, unsigned int args[4])
{
    Error err;
    unsigned int vidx = 0;
    int i = 0;
    void* vaddr[sz];

    (void)args;

    /* add input key */
    desc->desc[desc->idx++] = (CAAM_KEY | CAAM_CLASS1) +
        desc->buf[i].dataSz;
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz, 1);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz);
    vidx++;
    i++;

    /* add output */
    desc->desc[desc->idx++] = (CAAM_FIFO_S | CAAM_CLASS1 | desc->state) +
        desc->buf[i].dataSz;
    vaddr[vidx] = CAAM_ADR_MAP(desc->buf[i].data, desc->buf[i].dataSz + 16, 0);
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[vidx],
                desc->buf[i].dataSz + 16);

#if 0
    /* sanity check can we load it? */
    desc->desc[desc->idx++] = (CAAM_KEY | CAAM_CLASS1 | 0x500000) +
        desc->buf[i].dataSz;
    desc->desc[desc->idx++] = CAAM_ADR_TO_PHYSICAL(vaddr[1], desc->buf[1].dataSz);
#endif

    do {
        err = caamDoJob(desc);
    } while (err == CAAM_WAITING);

    CAAM_ADR_UNMAP(vaddr[0], desc->buf[0].data, desc->buf[0].dataSz, 0);
    CAAM_ADR_UNMAP(vaddr[1], desc->buf[1].data, desc->buf[1].dataSz + 16, 1);
    return err;
}


/******************************************************************************
  Init
  ****************************************************************************/

/* initialize a DESCSTRUCT for an operation */
void caamDescInit(DESCSTRUCT* desc, int type, unsigned int args[4],
        CAAM_BUFFER* buf, int sz)
{
    int i;

    desc->type   = type;
    desc->idx    = 0;
    desc->output = 0;
    desc->ctxOut = 0;
    desc->outputIdx = 0;
    desc->alignIdx = 0;
    desc->lastFifo = 0;
    if (args == NULL) {
        desc->state    = 0;
        desc->ctxSz    = 0;
        desc->inputSz  = 0;
    }
    else {
        desc->state    = args[0];
        desc->ctxSz    = args[1];
        desc->inputSz  = args[2];
    }
    desc->aadSz    = 0;
    desc->DescriptorCount = sz;
    desc->startIdx = 0;
    desc->desc[desc->idx++] = CAAM_HEAD; /* later will put size to header*/

    for (i = 0; i < sz; i++) {
        desc->buf[i].data   = buf[i].TheAddress;
        desc->buf[i].dataSz = buf[i].Length;
    }
}


int InitCAAM(void)
{
    Error ret;

    /* map to memory addresses needed for accessing CAAM */
    ret = CAAM_SET_BASEADDR();
    if (ret != 0) {
        return ret;
    }

    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
    printf("CHANUM_MS = 0x%08X\n", CAAM_READ(0x0FF0));
    printf("DECO0MIDR_MS = 0x%08X\n", CAAM_READ(0x00A0));
    printf("SCFGR = 0x%08X\n", CAAM_READ(0x000C));
    print_jdkek();
    printSecureMemoryInfo();
    printf("JR0MIDR_MS, _LS = 0x%08X , 0x%08X\n", CAAM_READ(0x0010),
            CAAM_READ(0x0014));
    printf("JR1MIDR_MS, _LS = 0x%08X , 0x%08X\n", CAAM_READ(0x0018),
            CAAM_READ(0x001C));
    printf("JR2MIDR_MS, _LS = 0x%08X , 0x%08X\n", CAAM_READ(0x0020),
            CAAM_READ(0x0024));
    #endif

    ret = Failure;
    for (caam.ring.page = 1; caam.ring.page < 7; caam.ring.page++) {
        ret = caamCreatePartition(caam.ring.page, caam.ring.page,
                CAAM_SM_CSP | CAAM_SM_ALL_RW);
        if (ret == Success)
            break;
    }
    if (ret != Success) {
        return -1;
    }

    caam.ring.JobIn  =  CAAM_PAGE + (caam.ring.page << 12);
    caam.ring.JobOut = caam.ring.JobIn  + (CAAM_JOBRING_SIZE *
            sizeof(unsigned int));
    caam.ring.Desc   = caam.ring.JobOut + (2 * CAAM_JOBRING_SIZE *
            sizeof(unsigned int));

    CAAM_INIT_MUTEX(&caam.ring.jr_lock);

    caam.ring.VirtualIn = mmap_device_memory(NULL,
            CAAM_JOBRING_SIZE * sizeof(unsigned int),
            PROT_READ | PROT_WRITE | PROT_NOCACHE,
            MAP_SHARED | MAP_PHYS, caam.ring.JobIn);
    memset(caam.ring.VirtualIn, 0, CAAM_JOBRING_SIZE * sizeof(unsigned int));
    caam.ring.VirtualOut  = mmap_device_memory(NULL,
            2 * CAAM_JOBRING_SIZE * sizeof(unsigned int),
            PROT_READ | PROT_WRITE | PROT_NOCACHE,
            MAP_SHARED | MAP_PHYS, caam.ring.JobOut);
    memset(caam.ring.VirtualOut, 0, 2 * CAAM_JOBRING_SIZE * sizeof(unsigned int));
    caam.ring.VirtualDesc = mmap_device_memory(NULL,
            CAAM_DESC_MAX * CAAM_JOBRING_SIZE,
            PROT_READ | PROT_WRITE | PROT_NOCACHE,
            MAP_SHARED | MAP_PHYS, caam.ring.Desc);
    memset(caam.ring.VirtualDesc, 0, CAAM_DESC_MAX * CAAM_JOBRING_SIZE);

    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
    printf("extra wolfssl debug - Setting JOB IN  0x%08X\n", caam.ring.JobIn);
    printf("extra wolfssl debug - Setting JOB OUT 0x%08X\n", caam.ring.JobOut);
    printf("extra wolfssl debug - Setting DESC 0x%08X\n", caam.ring.Desc);
    #endif
    CAAM_WRITE(CAAM_IRBAR0, caam.ring.JobIn);
    CAAM_WRITE(CAAM_ORBAR0, caam.ring.JobOut);

    /* Initialize job ring sizes */
    CAAM_WRITE(CAAM_IRSR0, CAAM_JOBRING_SIZE);
    CAAM_WRITE(CAAM_ORSR0, CAAM_JOBRING_SIZE);

    /* set DECO watchdog to time out and flush jobs that cause the DECO to hang */
    CAAM_WRITE(0x0004, CAAM_READ(0x0004) | 0x40000000);

    /* start up RNG if not already started */
    if (caamInitRng(&caam) != 0) {
        WOLFSSL_MSG("Error initializing RNG");
        INTERRUPT_Panic();
        return -1;
    }

    #if defined(WOLFSSL_CAAM_DEBUG) || defined(WOLFSSL_CAAM_PRINT)
    print_jdkek();
    printf("FADR = 0x%08X\n", CAAM_READ(0x0FCC));
    printf("RTMCTL = 0x%08X\n", CAAM_READ(0x0600));
    #endif
    WOLFSSL_MSG("Successfully initilazed CAAM driver");
    return 0;
}


int caamJobRingFree()
{
    CAAM_FREE_MUTEX(&caam.ring.jr_lock);
    caamFreeAllPart();
    return 0;
}
#if defined(__INTEGRITY) || defined(INTEGRITY)
void (*__ghsentry_bspuserinit_InitCAAM)(void) = &InitCAAM;

#endif /* INTEGRITY */
#endif
