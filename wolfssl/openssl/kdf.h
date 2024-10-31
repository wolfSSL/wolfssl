/* kdf.h
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

#ifndef WOLFSSL_KDF_H_
#define WOLFSSL_KDF_H_

#ifdef __cplusplus
    extern "C" {
#endif

#define WOLFSSL_EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND 0
#define WOLFSSL_EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY 1
#define WOLFSSL_EVP_PKEY_HKDEF_MODE_EXPAND_ONLY 2

#ifndef OPENSSL_COEXIST

#define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND WOLFSSL_EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND
#define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY WOLFSSL_EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY
#define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY WOLFSSL_EVP_PKEY_HKDEF_MODE_EXPAND_ONLY

#endif /* !OPENSSL_COEXIST */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_KDF_H_ */
