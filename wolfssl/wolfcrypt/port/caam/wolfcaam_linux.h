/* wolfcaam_linux.h
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

#ifndef WOLFCAAM_LINUX_H
#define WOLFCAAM_LINUX_H

#if defined(WOLFSSL_CAAM_LINUX)

#include <wolfssl/wolfcrypt/port/caam/caam_driver.h>

/* caam_linux.h, pulled in by caam_driver.h, already supplies CAAM_ADDRESS,
 * CAAM_BUFFER, Error/Value/Boolean and the status values. What is left is
 * what the shim layer itself refers to. */
#define DataBuffer 0
#define LastBuffer 0
#define ResourceNotAvailable -3

/* unique devId for CAAM use on crypto callbacks */
#ifndef WOLFSSL_CAAM_DEVID
    #define WOLFSSL_CAAM_DEVID 7
#endif

#include <wolfssl/wolfcrypt/port/caam/wolfcaam_ecdsa.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam_cmac.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam_aes.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam_hash.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

/* Unlike QNX, which reaches a resource manager over devctl, the Linux port
 * drives the engine from inside the calling process, so a request is a plain
 * function call. */
WOLFSSL_LOCAL int SynchronousSendRequest(int type, unsigned int args[4],
        CAAM_BUFFER *buf, int sz);
WOLFSSL_LOCAL int wc_CAAMInitInterface(void);
WOLFSSL_LOCAL void wc_CAAMFreeInterface(void);

#define CAAM_SEND_REQUEST(type, sz, arg, buf) \
        SynchronousSendRequest((type), (arg), (buf), (sz))
#define CAAM_INIT_INTERFACE  wc_CAAMInitInterface
#define CAAM_FREE_INTERFACE  wc_CAAMFreeInterface

#endif /* WOLFSSL_CAAM_LINUX */
#endif /* WOLFCAAM_LINUX_H */
