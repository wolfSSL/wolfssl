/* ele_rng.c
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

/* TRNG of the NXP EdgeLock Secure Enclave. The in-kernel fsl-se driver
 * registers it with the Linux hwrng framework, so it is reached as a character
 * device and needs no NXP userspace library. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_NXP_ELE

#include <wolfssl/wolfcrypt/port/nxp/ele.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_NXP_ELE_TRNG

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* Opened per read, not cached: seeding is rare and a file-scope fd would need
 * locking against concurrent seeders. */
static int wc_ele_trng_open(void)
{
    int fd = wc_open_cloexec(WOLFSSL_NXP_ELE_TRNG_DEVICE, O_RDONLY);
    if (fd < 0) {
        if (errno == EACCES) {
            WOLFSSL_MSG("ELE TRNG: permission denied opening hwrng device; "
                        "the node is root-only unless a udev rule grants "
                        "access");
        }
        else {
            WOLFSSL_MSG("ELE TRNG: unable to open hwrng device");
        }
        return WC_HW_E;
    }

    return fd;
}

int wc_ele_trng_read(byte* buf, word32 sz)
{
    int fd;
    ssize_t got;
    word32 pos = 0;

    if (buf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        return 0;
    }

    fd = wc_ele_trng_open();
    if (fd < 0) {
        return fd;
    }

    /* hwrng returns short reads while the entropy pool refills. */
    while (pos < sz) {
        got = read(fd, buf + pos, (size_t)(sz - pos));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            WOLFSSL_MSG("ELE TRNG: read failed");
            close(fd);
            return RNG_FAILURE_E;
        }
        if (got == 0) {
            /* No progress: fail rather than spin. */
            WOLFSSL_MSG("ELE TRNG: no entropy returned");
            close(fd);
            return RNG_FAILURE_E;
        }
        pos += (word32)got;
    }

    close(fd);
    return 0;
}

#endif /* WOLFSSL_NXP_ELE_TRNG */
#endif /* WOLFSSL_NXP_ELE */
