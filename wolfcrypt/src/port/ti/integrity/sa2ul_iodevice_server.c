/* sa2ul_iodevice_server.c
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

#include <INTEGRITY.h>
#include <INTEGRITY_intrinsics.h>
#include <string.h>
#include <stddef.h>

#include <wolfssl/wolfcrypt/port/ti/integrity/sa2ul_driver.h>
#include <wolfssl/wolfcrypt/port/ti/integrity/sa2ul_iodevice.h>
#include <wolfssl/wolfcrypt/port/ti/integrity/sa2ul_iodevice_server.h>

static struct IODeviceVectorStruct Sa2ulDeviceVector;
static struct Sa2ulCtrl *volatile gCtrl = NULL;
static struct Sa2ulData *volatile gData = NULL;

/* Non-zero while a caller owns the shared pages (SA2UL_IODEVICE_STATUS_
 * ACQUIRE .. _RELEASE). Callbacks can run on any core concurrently, so it is
 * claimed with an exclusive load/store pair. The callback can't identify
 * its caller, so this serializes cooperating AddressSpaces rather than
 * enforcing ownership. */
static volatile unsigned int gPagesBusy = 0u;

static Error Sa2ulPagesAcquire(void)
{
    for (;;) {
        if (__LDXR32((unsigned int *)&gPagesBusy) != 0u) {
            return ResourceNotAvailable;
        }
        if (__STXR32(1u, (unsigned int *)&gPagesBusy) == 0) {
            break;
        }
    }
    __DMB();
    return Success;
}

static void Sa2ulPagesRelease(void)
{
    __DMB();
    gPagesBusy = 0u;
}

static Error Sa2ulDeviceCreate(IODeviceVector TheIODeviceVector)
{
    (void)TheIODeviceVector;
    return Success;
}

static Error Sa2ulDeviceReadStatus(IODeviceVector TheIODeviceVector,
        Value StatusNumber, void *Buffer, Address Length)
{
    struct Sa2ulCtrl LocalCtrl;
    struct Sa2ulCtrl *ctrl = gCtrl;
    struct Sa2ulData *data = gData;

    (void)TheIODeviceVector;
    (void)Buffer;
    (void)Length;

    if (ctrl == NULL || data == NULL) {
        /* not attached yet: the Task will fall back to software */
        return Failure;
    }

    switch (StatusNumber) {
    case SA2UL_IODEVICE_STATUS_ACQUIRE:
        return Sa2ulPagesAcquire();
    case SA2UL_IODEVICE_STATUS_RELEASE:
        Sa2ulPagesRelease();
        return Success;
    case SA2UL_IODEVICE_STATUS_NUMBER:
        break;
    default:
        return IllegalStatusNumber;
    }
    if (gPagesBusy == 0u) {
        /* the pages weren't claimed for this request */
        return Failure;
    }

    __DMB();
    memcpy(&LocalCtrl, ctrl, sizeof(LocalCtrl));

    switch (LocalCtrl.op) {
    case SA2UL_OP_SHA1:
    case SA2UL_OP_SHA224:
    case SA2UL_OP_SHA256:
    case SA2UL_OP_SHA384:
    case SA2UL_OP_SHA512:
        (void)sa2ul_driver_sha(&LocalCtrl, data);
        break;
    default:
        (void)sa2ul_driver_aes(&LocalCtrl, data);
        break;
    }

    /* don't leave the key in this kernel stack frame */
    {
        volatile uint8_t *k = LocalCtrl.key;
        size_t i;
        for (i = 0; i < sizeof(LocalCtrl.key); i++) {
            k[i] = 0;
        }
    }

    memcpy(ctrl, &LocalCtrl, sizeof(LocalCtrl));
    __DMB();

    /* don't keep the GCM hash subkey here */
    {
        volatile uint8_t *h = LocalCtrl.ghash;
        size_t i;
        for (i = 0; i < sizeof(LocalCtrl.ghash); i++) {
            h[i] = 0;
        }
    }

    return Success;
}

void sa2ul_iodevice_attach_shared_pages(void *Ctrl, Address CtrlLen,
        void *Data, Address DataLen)
{
    if (Ctrl == NULL || Data == NULL ||
            CtrlLen < sizeof(struct Sa2ulCtrl) ||
            DataLen < sizeof(struct Sa2ulData)) {
        return;
    }
    gData = (struct Sa2ulData *)Data;
    __DMB();
    gCtrl = (struct Sa2ulCtrl *)Ctrl;
}

void InitSa2ulDevice(void)
{
    memset(&Sa2ulDeviceVector, 0, sizeof(Sa2ulDeviceVector));
    Sa2ulDeviceVector.Create     = Sa2ulDeviceCreate;
    Sa2ulDeviceVector.ReadStatus = Sa2ulDeviceReadStatus;

    RegisterIODeviceVector(&Sa2ulDeviceVector, SA2UL_IODEVICE_NAME);
}

typedef void (*voidfunc)();
voidfunc __ghsentry_bspuserinit_InitSa2ulDevice = InitSa2ulDevice;
