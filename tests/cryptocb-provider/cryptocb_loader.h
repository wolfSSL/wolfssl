/* cryptocb_loader.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 *
 * Public API header for the external crypto callback provider.
 */

#ifndef CRYPTOCB_LOADER_H
#define CRYPTOCB_LOADER_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef WOLF_CRYPTO_CB_TEST_PROVIDER

int wc_CryptoCb_InitTestCryptoCbProvider(void);
void wc_CryptoCb_CleanupTestCryptoCbProvider(void);

#endif
#endif /* CRYPTOCB_LOADER_H */
