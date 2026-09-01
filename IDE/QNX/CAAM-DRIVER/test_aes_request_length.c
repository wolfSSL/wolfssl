/* test_aes_request_length.c
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

#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <sys/resmgr.h>
#include <devctl.h>
#include <limits.h>
#include <semaphore.h>

#include <wolfssl/wolfcrypt/port/caam/caam_driver.h>

static ssize_t caamTestMsgReadv(resmgr_context_t* ctp, iov_t* iov,
        int parts, size_t offset);
static ssize_t caamTestMsgWritev(resmgr_context_t* ctp, const iov_t* iov,
        int parts, size_t offset);
static void caamTestDescInit(DESCSTRUCT* desc, int type,
        unsigned int args[4], CAAM_BUFFER* buf, int sz);
static int caamTestAesCombined(DESCSTRUCT* desc, CAAM_BUFFER* buf,
        unsigned int args[4], unsigned int phyMem);
static CAAM_ADDRESS caamTestGetPartition(unsigned int part, int partSz,
        unsigned int flag);
static int caamTestFreePart(unsigned int part);
static int caamTestAead(DESCSTRUCT* desc, CAAM_BUFFER* buf,
        unsigned int args[4]);
static int caamTestAesCmac(DESCSTRUCT* desc, int sz,
        unsigned int args[4]);
static int caamTestBlob(DESCSTRUCT* desc);
static int caamTestECDSAMake(DESCSTRUCT* desc, CAAM_BUFFER* buf,
        unsigned int args[4]);
static int caamTestECDSASign(DESCSTRUCT* desc, int sz,
        unsigned int args[4]);
static int caamTestECDSAVerify(DESCSTRUCT* desc, CAAM_BUFFER* buf, int sz,
        unsigned int args[4]);
static int caamTestECDSAEcdh(DESCSTRUCT* desc, int sz,
        unsigned int args[4]);
static int caamTestEntropy(unsigned char* out, int outSz);
static int caamTestFindUnusedPartition(void);
static int caamTestKeyCover(DESCSTRUCT* desc, int sz,
        unsigned int args[4]);
static void* caamTestMmap(void* addr, size_t len, int prot, int flags,
        int fd, off_t offset);
static int caamTestMunmap(void* addr, size_t len);
static int caamTestMsync(void* addr, size_t len, int flags);

#ifdef CAAM_QNX_TEST_HOST
static int caamTestSemTryWait(sem_t* sem);
static int caamTestSemPost(sem_t* sem);
static int caamTestSemInit(sem_t* sem, int shared, unsigned int value);
static int caamTestSemDestroy(sem_t* sem);

    #define sem_trywait caamTestSemTryWait
    #define sem_post caamTestSemPost
    #define sem_init caamTestSemInit
    #define sem_destroy caamTestSemDestroy
#endif

#define resmgr_msgreadv caamTestMsgReadv
#define resmgr_msgwritev caamTestMsgWritev
#define caamDescInit caamTestDescInit
#define caamAesCombined caamTestAesCombined
#define caamGetPartition caamTestGetPartition
#define caamFreePart caamTestFreePart
#define caamAead caamTestAead
#define caamAesCmac caamTestAesCmac
#define caamBlob caamTestBlob
#define caamECDSAMake caamTestECDSAMake
#define caamECDSASign caamTestECDSASign
#define caamECDSAVerify caamTestECDSAVerify
#define caamECDSA_ECDH caamTestECDSAEcdh
#define caamEntropy caamTestEntropy
#define caamFindUnusedPartition caamTestFindUnusedPartition
#define caamKeyCover caamTestKeyCover
#define mmap caamTestMmap
#define munmap caamTestMunmap
#define msync caamTestMsync
#define main caamQnxServerMain
#ifndef CAAM_QNX_SOURCE
    #define CAAM_QNX_SOURCE "../../../wolfcrypt/src/port/caam/caam_qnx.c"
#endif
#include CAAM_QNX_SOURCE
#undef main
#undef msync
#undef munmap
#undef mmap
#undef caamKeyCover
#undef caamFindUnusedPartition
#undef caamEntropy
#undef caamECDSA_ECDH
#undef caamECDSAVerify
#undef caamECDSASign
#undef caamECDSAMake
#undef caamBlob
#undef caamAesCmac
#undef caamAead
#undef caamFreePart
#undef caamGetPartition
#undef caamAesCombined
#undef caamDescInit
#undef resmgr_msgwritev
#undef resmgr_msgreadv

static int caamTestReadSz;
static int caamTestAesCalls;
static int caamTestFreeCalls;
static int caamTestGetPartitionCalls;
static int caamTestEcdsaCalls;
static unsigned int caamTestEcdsaPartition;
static const unsigned char* caamTestReadData;
static size_t caamTestReadDataSz;
static unsigned char caamTestMappedBuffer[64];
static size_t caamTestMappedLen;
static size_t caamTestMappedSensitiveLen;
static int caamTestMappedWasCleared;

#ifdef CAAM_QNX_TEST_HOST
static int caamTestSemaphore;

static int caamTestSemTryWait(sem_t* sem)
{
    (void)sem;
    if (caamTestSemaphore == 0)
        return -1;

    caamTestSemaphore = 0;
    return 0;
}

static int caamTestSemPost(sem_t* sem)
{
    (void)sem;
    caamTestSemaphore++;
    return 0;
}

static int caamTestSemInit(sem_t* sem, int shared, unsigned int value)
{
    (void)sem;
    (void)shared;
    caamTestSemaphore = (int)value;
    return 0;
}

static int caamTestSemDestroy(sem_t* sem)
{
    (void)sem;
    return 0;
}
#endif

static void* caamTestMmap(void* addr, size_t len, int prot, int flags,
        int fd, off_t offset)
{
    (void)addr;
    (void)prot;
    (void)flags;
    (void)fd;
    (void)offset;

    if (len > sizeof(caamTestMappedBuffer))
        return MAP_FAILED;

    caamTestMappedLen = len;
    return caamTestMappedBuffer;
}

static int caamTestMunmap(void* addr, size_t len)
{
    size_t i;

    if (addr == (void*)caamTestMappedBuffer && len == caamTestMappedLen) {
        caamTestMappedWasCleared = 1;
        for (i = 0; i < caamTestMappedSensitiveLen; i++) {
            if (caamTestMappedBuffer[i] != 0) {
                caamTestMappedWasCleared = 0;
                break;
            }
        }
    }

    return 0;
}

static int caamTestMsync(void* addr, size_t len, int flags)
{
    (void)addr;
    (void)len;
    (void)flags;

    return 0;
}

static ssize_t caamTestMsgReadv(resmgr_context_t* ctp, iov_t* iov,
        int parts, size_t offset)
{
    int i;
    size_t copied = 0;

    (void)ctp;
    (void)offset;

    for (i = 0; i < parts && copied < caamTestReadDataSz; i++) {
        size_t copySz = iov[i].iov_len;

        if (copySz > caamTestReadDataSz - copied)
            copySz = caamTestReadDataSz - copied;
        memcpy(iov[i].iov_base, caamTestReadData + copied, copySz);
        copied += copySz;
    }

    return caamTestReadSz;
}

static ssize_t caamTestMsgWritev(resmgr_context_t* ctp, const iov_t* iov,
        int parts, size_t offset)
{
    (void)ctp;
    (void)iov;
    (void)parts;
    (void)offset;

    return -1;
}

static void caamTestDescInit(DESCSTRUCT* desc, int type,
        unsigned int args[4], CAAM_BUFFER* buf, int sz)
{
    (void)desc;
    (void)type;
    (void)args;
    (void)buf;
    (void)sz;
}

static int caamTestAesCombined(DESCSTRUCT* desc, CAAM_BUFFER* buf,
        unsigned int args[4], unsigned int phyMem)
{
    (void)desc;
    (void)buf;
    (void)args;
    (void)phyMem;

    caamTestAesCalls++;
    return Failure;
}

static CAAM_ADDRESS caamTestGetPartition(unsigned int part, int partSz,
        unsigned int flag)
{
    (void)part;
    (void)partSz;
    (void)flag;
    caamTestGetPartitionCalls++;
    return 0;
}

static int caamTestFreePart(unsigned int part)
{
    (void)part;
    caamTestFreeCalls++;
    return Success;
}

static int caamTestAead(DESCSTRUCT* desc, CAAM_BUFFER* buf,
        unsigned int args[4])
{
    (void)desc;
    (void)buf;
    (void)args;
    return Failure;
}

static int caamTestAesCmac(DESCSTRUCT* desc, int sz, unsigned int args[4])
{
    (void)desc;
    (void)sz;
    (void)args;
    return Failure;
}

static int caamTestBlob(DESCSTRUCT* desc)
{
    (void)desc;
    return Failure;
}

static int caamTestECDSAMake(DESCSTRUCT* desc, CAAM_BUFFER* buf,
        unsigned int args[4])
{
    (void)desc;
    (void)buf;
    caamTestEcdsaCalls++;
    args[2] = caamTestEcdsaPartition;
    return Success;
}

static int caamTestECDSASign(DESCSTRUCT* desc, int sz,
        unsigned int args[4])
{
    (void)desc;
    (void)sz;
    (void)args;
    return Failure;
}

static int caamTestECDSAVerify(DESCSTRUCT* desc, CAAM_BUFFER* buf, int sz,
        unsigned int args[4])
{
    (void)desc;
    (void)buf;
    (void)sz;
    (void)args;
    return Failure;
}

static int caamTestECDSAEcdh(DESCSTRUCT* desc, int sz,
        unsigned int args[4])
{
    (void)desc;
    (void)sz;
    (void)args;
    return Failure;
}

static int caamTestEntropy(unsigned char* out, int outSz)
{
    (void)out;
    (void)outSz;
    return Failure;
}

static int caamTestFindUnusedPartition(void)
{
    return -1;
}

static int caamTestKeyCover(DESCSTRUCT* desc, int sz,
        unsigned int args[4])
{
    (void)desc;
    (void)sz;
    (void)args;
    return Failure;
}

static int testRejectIncompleteRequest(void)
{
    resmgr_context_t ctp;
    io_devctl_t msg;
    unsigned char scratch[48];
    unsigned int args[4] = {0U, 16U, 16U, 0U};
    int ret;
    int i;

    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    memset(scratch, 0xA5, sizeof(scratch));
    if (sem_init(&localMemSem, 0, 1) != 0)
        return 1;

    localMemory = scratch;
    localPhy = 0U;
    caamTestReadSz = 16;
    caamTestAesCalls = 0;
    ret = doAES(&ctp, &msg, args, 0U, WC_CAAM_AESECB);
    localMemory = NULL;

    if (sem_destroy(&localMemSem) != 0)
        return 1;
    if (ret != EBADMSG || caamTestAesCalls != 0) {
        printf("Unexpected result: ret=%d caamCalls=%d\n", ret,
                caamTestAesCalls);
        return 1;
    }

    for (i = 0; i < 32; i++) {
        if (scratch[i] != 0) {
            printf("Scratch was not cleared at offset %d\n", i);
            return 1;
        }
    }

    return 0;
}

static int testClearMappedRequest(void)
{
    resmgr_context_t ctp;
    io_devctl_t msg;
    unsigned char request[48];
    unsigned int args[4] = {0U, 16U, 16U, 0U};
    int ret;

    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    memset(request, 0xA5, sizeof(request));
    memset(caamTestMappedBuffer, 0xA5, sizeof(caamTestMappedBuffer));
    if (sem_init(&localMemSem, 0, 0) != 0)
        return 1;

    localMemory = NULL;
    localPhy = 0U;
    caamTestReadData = request;
    caamTestReadDataSz = sizeof(request);
    caamTestReadSz = sizeof(request);
    caamTestAesCalls = 0;
    caamTestMappedLen = 0U;
    caamTestMappedSensitiveLen = sizeof(request);
    caamTestMappedWasCleared = 0;
    ret = doAES(&ctp, &msg, args, 0U, WC_CAAM_AESCBC);
    caamTestReadData = NULL;
    caamTestReadDataSz = 0U;

    if (sem_destroy(&localMemSem) != 0)
        return 1;
    if (ret != ECANCELED || caamTestAesCalls != 1 ||
            caamTestMappedLen != sizeof(caamTestMappedBuffer) ||
            !caamTestMappedWasCleared) {
        return 1;
    }

    return 0;
}

static int testRejectOversizedRequest(void)
{
    resmgr_context_t ctp;
    io_devctl_t msg;
    unsigned int args[4] = {0U, 16U,
        (unsigned int)((INT_MAX / 2) + 1), 0U};
    int ret;

    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    caamTestAesCalls = 0;
    ret = doAES(&ctp, &msg, args, 0U, WC_CAAM_AESECB);

    return ret == EBADMSG && caamTestAesCalls == 0 ? 0 : 1;
}

static int testRejectInvalidPartitionIndex(void)
{
    resmgr_context_t ctp;
    io_devctl_t msg;
    iofunc_ocb_t ocb;
    unsigned int args[4];
    int ret;
    int i;

    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    memset(&ocb, 0, sizeof(ocb));
    for (i = 0; i < MAX_OWNER_PART; i++)
        sm_ownerId[i] = 0;

    if (!CAAM_QNX_PARTITION_IS_VALID(0U) ||
            !CAAM_QNX_PARTITION_IS_VALID(CAAM_QNX_MAX_PARTITIONS - 1U) ||
            CAAM_QNX_PARTITION_IS_VALID(CAAM_QNX_MAX_PARTITIONS) ||
            CAAM_QNX_PARTITION_IS_VALID(~0U)) {
        return 1;
    }

    memset(args, 0, sizeof(args));
    args[0] = CAAM_QNX_MAX_PARTITIONS;
    args[1] = 1U;
    caamTestGetPartitionCalls = 0;
    ret = doGET_PART(&ctp, &msg, args, 0U, &ocb);
    if (ret != EBADMSG || caamTestGetPartitionCalls != 0)
        return 1;

    memset(args, 0, sizeof(args));
    args[0] = CAAM_BLACK_KEY_SM;
    args[3] = 16U;
    caamTestEcdsaPartition = CAAM_QNX_MAX_PARTITIONS;
    caamTestEcdsaCalls = 0;
    ret = doECDSA_KEYPAIR(&ctp, &msg, args, 0U, &ocb);
    if (ret != EBADMSG || caamTestEcdsaCalls != 1)
        return 1;

    for (i = 0; i < MAX_OWNER_PART; i++) {
        if (sm_ownerId[i] != 0)
            return 1;
    }

    memset(args, 0, sizeof(args));
    args[0] = CAAM_QNX_MAX_PARTITIONS;
    ctp.size = sizeof(msg.i) + sizeof(args);
    msg.i.dcmd = WC_CAAM_FREE_PART;
    caamTestFreeCalls = 0;
    caamTestReadData = (const unsigned char*)args;
    caamTestReadDataSz = sizeof(args);
    caamTestReadSz = sizeof(args);
    ret = io_devctl(&ctp, &msg, &ocb);
    caamTestReadData = NULL;
    caamTestReadDataSz = 0U;

    if (ret != EBADMSG || caamTestFreeCalls != 0)
        return 1;

    return 0;
}

static int testRejectOtherOwnerPartitionAccess(void)
{
    resmgr_context_t ctp;
    io_devctl_t msg;
    iofunc_ocb_t owner;
    iofunc_ocb_t other;
    unsigned int args[4];
    int commands[3] = {WC_CAAM_WRITE_PART, WC_CAAM_READ_PART,
        WC_CAAM_FREE_PART};
    int ret;
    int i;

    memset(&ctp, 0, sizeof(ctp));
    memset(&msg, 0, sizeof(msg));
    memset(&owner, 0, sizeof(owner));
    memset(&other, 0, sizeof(other));
    ctp.size = sizeof(msg.i) + sizeof(args);
    msg.o.nbytes = 1U;

    for (i = 0; i < 3; i++) {
        memset(args, 0, sizeof(args));
        if (commands[i] == WC_CAAM_FREE_PART) {
            args[0] = 0U;
        }
        else {
            args[0] = CAAM_PAGE;
            args[1] = 1U;
        }

        msg.i.dcmd = commands[i];
        sm_ownerId[0] = (CAAM_ADDRESS)&owner;
        caamTestFreeCalls = 0;
        caamTestReadData = (const unsigned char*)args;
        caamTestReadDataSz = sizeof(args);
        caamTestReadSz = sizeof(args);
        ret = io_devctl(&ctp, &msg, &other);
        caamTestReadData = NULL;
        caamTestReadDataSz = 0U;

        if (ret != EACCES || sm_ownerId[0] != (CAAM_ADDRESS)&owner ||
                caamTestFreeCalls != 0) {
            return 1;
        }
    }

    return 0;
}

static int testRejectInvalidPartitionRange(void)
{
    CAAM_ADDRESS lastPart;

    lastPart = CAAM_PAGE +
        ((CAAM_QNX_MAX_PARTITIONS - 1U) * CAAM_PAGE_SZ);

    if (sanityCheckPartitionAddress(CAAM_PAGE + CAAM_PAGE_SZ - 1U, 2) == 0)
        return 1;
    if (sanityCheckPartitionAddress(CAAM_PAGE, 0) == 0)
        return 1;
    if (sanityCheckPartitionAddress(lastPart + CAAM_PAGE_SZ, 1) == 0)
        return 1;
    if (sanityCheckPartitionAddress(lastPart, CAAM_PAGE_SZ) != 0)
        return 1;
    if (sanityCheckPartitionAddress(CAAM_PAGE + 32U, 64) != 0)
        return 1;

    return 0;
}

#ifdef CAAM_QNX_TEST_HOST
    #undef sem_destroy
    #undef sem_init
    #undef sem_post
    #undef sem_trywait
#endif

int main(void)
{
    if (pthread_mutex_init(&sm_mutex, NULL) != EOK)
        return 1;
    if (testRejectIncompleteRequest() != 0) {
        printf("testRejectIncompleteRequest: FAIL\n");
        return 1;
    }
    if (testClearMappedRequest() != 0) {
        printf("testClearMappedRequest: FAIL\n");
        return 1;
    }
    if (testRejectOversizedRequest() != 0) {
        printf("testRejectOversizedRequest: FAIL\n");
        return 1;
    }
    if (testRejectInvalidPartitionIndex() != 0) {
        printf("testRejectInvalidPartitionIndex: FAIL\n");
        return 1;
    }
    if (testRejectOtherOwnerPartitionAccess() != 0) {
        printf("testRejectOtherOwnerPartitionAccess: FAIL\n");
        return 1;
    }
    if (testRejectInvalidPartitionRange() != 0) {
        printf("testRejectInvalidPartitionRange: FAIL\n");
        return 1;
    }

    (void)pthread_mutex_destroy(&sm_mutex);

    printf("testRejectIncompleteRequest: PASS\n");
    printf("testClearMappedRequest: PASS\n");
    printf("testRejectOversizedRequest: PASS\n");
    printf("testRejectInvalidPartitionIndex: PASS\n");
    printf("testRejectOtherOwnerPartitionAccess: PASS\n");
    printf("testRejectInvalidPartitionRange: PASS\n");
    return 0;
}
