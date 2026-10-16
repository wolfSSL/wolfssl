/* rng_iodevice_server.c
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

/* Kernel-side IODevice server exposing rng_driver.c to Task AddressSpaces */

#include <INTEGRITY.h>
#include <bsp.h>
#include <kernel/iodevicevector.h>
#include <string.h>

#include <wolfssl/wolfcrypt/port/ti/integrity/rng_driver.h>
#include <wolfssl/wolfcrypt/port/ti/integrity/rng_iodevice.h>

static struct IODeviceVectorStruct RngDeviceVector;

static Error RngDeviceCreate(IODeviceVector TheIODeviceVector)
{
    (void)TheIODeviceVector;
    return Success;
}

static Error RngDeviceReadStatus(IODeviceVector TheIODeviceVector,
        Value StatusNumber, void *Buffer, Address Length)
{
    (void)TheIODeviceVector;
    (void)StatusNumber;

    if (rng_driver_read((unsigned char *)Buffer, (unsigned int)Length) != 0) {
        return Failure;
    }
    return Success;
}

void InitRngDevice(void)
{
    memset(&RngDeviceVector, 0, sizeof(RngDeviceVector));
    RngDeviceVector.Create     = RngDeviceCreate;
    RngDeviceVector.ReadStatus = RngDeviceReadStatus;

    RegisterIODeviceVector(&RngDeviceVector, RNG_IODEVICE_NAME);
}

typedef void (*voidfunc)();
voidfunc __ghsentry_bspuserinit_InitRngDevice = InitRngDevice;
