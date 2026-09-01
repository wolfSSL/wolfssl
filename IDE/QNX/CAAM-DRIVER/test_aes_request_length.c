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
#define main caamQnxServerMain
#ifndef CAAM_QNX_SOURCE
    #define CAAM_QNX_SOURCE "../../../wolfcrypt/src/port/caam/caam_qnx.c"
#endif
#include CAAM_QNX_SOURCE
#undef main
#undef caamAesCombined
#undef caamDescInit
#undef resmgr_msgwritev
#undef resmgr_msgreadv

static int caamTestReadSz;
static int caamTestAesCalls;

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

static ssize_t caamTestMsgReadv(resmgr_context_t* ctp, iov_t* iov,
        int parts, size_t offset)
{
    (void)ctp;
    (void)iov;
    (void)parts;
    (void)offset;

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

#ifdef CAAM_QNX_TEST_HOST
    #undef sem_destroy
    #undef sem_init
    #undef sem_post
    #undef sem_trywait
#endif

int main(void)
{
    if (testRejectIncompleteRequest() != 0) {
        printf("testRejectIncompleteRequest: FAIL\n");
        return 1;
    }
    if (testRejectOversizedRequest() != 0) {
        printf("testRejectOversizedRequest: FAIL\n");
        return 1;
    }

    printf("testRejectIncompleteRequest: PASS\n");
    printf("testRejectOversizedRequest: PASS\n");
    return 0;
}
