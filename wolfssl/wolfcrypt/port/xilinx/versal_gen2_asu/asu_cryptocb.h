/* asu_cryptocb.h
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

/* wolfSSL crypto callback device for the Versal Gen2 ASU. Registering this
 * device routes wolfCrypt operations to the ASU hardware engines, with a
 * software fallback for anything the ASU does not handle. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_CRYPTOCB_H
#define WOLFSSL_VERSAL_GEN2_ASU_CRYPTOCB_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Register the ASU device with the wolfSSL crypto callback framework. The ASU
 * client must already be initialized with XAsu_ClientInit. Pass the same devId
 * that WC_USE_DEVID is set to so wolfSSL routes operations to this device. */
WOLFSSL_API int wc_AsuCryptoCb_RegisterDevice(int devId);

/* Remove the ASU device from the crypto callback framework. */
WOLFSSL_API void wc_AsuCryptoCb_UnRegisterDevice(int devId);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CRYPTOCB_H */
