/*
 * wisekey_vaultic.h
 *
 * Copyright (C) 2023 wolfSSL Inc.
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

#ifndef _WOLFPORT_WISEKEY_VAULTIC_H_
#define _WOLFPORT_WISEKEY_VAULTIC_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

/*
 * Implementation of wolfCrypt devcrypto callbacks
 *
 * The wolfSSL port of the Wisekey VaultIC provides a wrapper library to allow
 * the VaultIC to be used as an external crypto provider.  This library depends
 * on the Wisekey-provided VaultIC interface libraries that have been statically
 * compiled in the proper hardware configuration.
 */

/* DevID MSBs have ascii "VI" */
#define WISEKEY_VAULTIC_DEVID (0x56490000ul)
#define WISEKEY_VAULTIC420_DEVID (WISEKEY_VAULTIC_DEVID + 0x0420)

/* Register this callback using:
 * int rc = wc_CryptoCb_RegisterDevice(WISEKEY_VAULTIC420_DEVID,
 *                      wolfSSL_WisekeyVaultIC_CryptoDevCb, NULL);
 *
 * Associate this device with your context using:
 *
 */
int wolfSSL_WisekeyVaultIC_CryptoDevCb(int devId,
                                       wc_CryptoInfo* info,
                                       void* ctx);

#endif /* _WOLFPORT_WISEKEY_VAULTIC_H_ */
