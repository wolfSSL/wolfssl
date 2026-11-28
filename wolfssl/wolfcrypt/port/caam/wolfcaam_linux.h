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

#include <stdint.h>

/* Self-contained, like wolfcaam_qnx.h and the other port shim headers. This
 * one is installed (wolfssl/wolfcrypt/include.am) while caam_driver.h and
 * caam_linux.h are not, so including them here would break every consumer
 * that picks up wolfcaam.h from an installed tree. The guards match
 * caam_linux.h so the driver sources, which do include both, still agree.
 *
 * DataBuffer and LastBuffer are both zero, matching wolfcaam_qnx.h,
 * wolfcaam_seco.h and wolfcaam_fsl_nxp.h. CAAM_BUFFER.BufferType exists for
 * environments that pass buffer lists across an address space boundary; the
 * driver core never reads it, and callers pass the buffer count instead, so
 * the values carry no meaning here and must stay consistent with the other
 * ports. */
#define CAAM_ADDRESS uintptr_t

#ifndef WOLFSSL_CAAM_BUFFER
#define WOLFSSL_CAAM_BUFFER
    typedef struct CAAM_BUFFER {
        int BufferType;
        CAAM_ADDRESS TheAddress;
        int Length;
    } CAAM_BUFFER;
#endif

#define DataBuffer 0
#define LastBuffer 0
#define ResourceNotAvailable -3

/* Status values the shim layer and the crypto callbacks refer to. Same
 * spellings and values as caam_linux.h, which the driver sources also
 * include; an object-like macro may be redefined identically. */
#define Success 1
#define Failure 0
#define MemoryMapMayNotBeEmpty -1
#define CAAM_WAITING -2
#define NoActivityReady -1
#define MemoryOperationNotPerformed -1
#define CAAM_ARGS_E -3

/* unique devId for CAAM use on crypto callbacks */
#ifndef WOLFSSL_CAAM_DEVID
    #define WOLFSSL_CAAM_DEVID 7
#endif

/* The Linux backend offloads only AES and the TRNG (see settings.h, which sets
 * WOLFSSL_NO_CAAM_ECC / _HASH and WOLFSSL_CAAM_NO_SM for it). Pull in only the
 * AES and crypto-callback interfaces; including the ECC/CMAC/hash headers would
 * break a valid --enable-caam=linux --disable-ecc build, where wolfcaam_hash.h
 * declares wc_CAAM_ShaHash(wc_Sha*, ...) before wc_Sha is defined. */
#include <wolfssl/wolfcrypt/port/caam/wolfcaam_aes.h>
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
