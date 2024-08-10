/* liboqs.h
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

/*!
    \file wolfssl/wolfcrypt/port/liboqs/liboqs.h
*/
/*

DESCRIPTION
This library provides the support interfaces to the liboqs library providing
implementations for Post-Quantum cryptography algorithms.
*/

#ifndef WOLF_CRYPT_LIBOQS_H
#define WOLF_CRYPT_LIBOQS_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>


#ifdef __cplusplus
    extern "C" {
#endif

#if defined(HAVE_LIBOQS)

#include "oqs/oqs.h"


int wolfSSL_liboqsInit(void);

void wolfSSL_liboqsClose(void);

int wolfSSL_liboqsRngMutexLock(WC_RNG* rng);

int wolfSSL_liboqsRngMutexUnlock(void);

#endif /* HAVE_LIBOQS */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_LIBOQS_H */
