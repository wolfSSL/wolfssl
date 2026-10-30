/* rng_port.c
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

#include <wolfssl/wolfcrypt/port/ti/integrity/rng_iodevice.h>

static volatile IODevice gRngDev = NULL;

/* Several tasks may seed at once: each one that finds no handle requests
 * its own, and only the first to finish publishes it (TestAndSet); the
 * others close theirs and use the published one. */
static int rng_iodevice_open(void)
{
    IODevice dev = NULL;

    if (gRngDev != NULL) {
        return 0;
    }
    if (RequestResource((Object *)&dev, RNG_IODEVICE_NAME,
            "!systempassword") != Success) {
        return -1;
    }
    if (TestAndSet((volatile Address *)&gRngDev, (Address)NULL,
            (Address)dev) != Success) {
        (void)CloseIODevice(dev);
    }
    return 0;
}

int integrity_rand_generate_seed(unsigned char* output, unsigned int sz);

int integrity_rand_generate_seed(unsigned char* output, unsigned int sz)
{
    if (rng_iodevice_open() != 0) {
        return -1;
    }
    if (ReadIODeviceStatus(gRngDev, RNG_IODEVICE_STATUS_NUMBER, output, sz)
            != Success) {
        return -1;
    }
    return 0;
}
