/* liboqs.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/*

DESCRIPTION
This library provides the support interfaces to the liboqs library providing
implementations for Post-Quantum cryptography algorithms.

*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/port/liboqs/liboqs.h>

#if defined(HAVE_LIBOQS)

/* RNG for liboqs */
static WC_RNG liboqsDefaultRNG;
static WC_RNG* liboqsCurrentRNG;

static wolfSSL_Mutex liboqsRNGMutex;

static int liboqs_init = 0;


static void wolfSSL_liboqsGetRandomData(uint8_t* buffer, size_t numOfBytes)
{
    int ret;
    word32 numOfBytes_word32;

    while (numOfBytes > 0) {
        numOfBytes_word32 = (word32)numOfBytes;
        numOfBytes -= numOfBytes_word32;
        ret = wc_RNG_GenerateBlock(liboqsCurrentRNG, buffer,
                                   numOfBytes_word32);
        if (ret != 0) {
            /* ToDo: liboqs exits program if RNG fails,
             * not sure what to do here
             */
            WOLFSSL_MSG_EX(
                "wc_RNG_GenerateBlock(..., %u) failed with ret %d "
                "in wolfSSL_liboqsGetRandomData().", numOfBytes_word32, ret
                );
            abort();
        }
    }
}

int wolfSSL_liboqsInit(void)
{
    int ret = 0;

    if (liboqs_init == 0) {
        ret = wc_InitMutex(&liboqsRNGMutex);
        if (ret != 0) {
            return ret;
        }
        ret = wc_LockMutex(&liboqsRNGMutex);
        if (ret != 0) {
            return ret;
        }
        ret = wc_InitRng(&liboqsDefaultRNG);
        if (ret == 0) {
            OQS_init();
            liboqs_init = 1;
        }
        liboqsCurrentRNG = &liboqsDefaultRNG;
        wc_UnLockMutex(&liboqsRNGMutex);

        OQS_randombytes_custom_algorithm(wolfSSL_liboqsGetRandomData);
    }

    return ret;
}

void wolfSSL_liboqsClose(void)
{
    wc_FreeRng(&liboqsDefaultRNG);
}

int wolfSSL_liboqsRngMutexLock(WC_RNG* rng)
{
    int ret = wolfSSL_liboqsInit();
    if (ret == 0) {
        ret = wc_LockMutex(&liboqsRNGMutex);
    }
    if (ret == 0 && rng != NULL) {
        /* Update the pointer with the RNG to use. This is safe as we locked the mutex */
        liboqsCurrentRNG = rng;
    }
    return ret;
}

int wolfSSL_liboqsRngMutexUnlock(void)
{
    liboqsCurrentRNG = &liboqsDefaultRNG;

    if (liboqs_init) {
        return wc_UnLockMutex(&liboqsRNGMutex);
    }
    else {
        return BAD_MUTEX_E;
    }
}

#endif /* HAVE_LIBOQS */
