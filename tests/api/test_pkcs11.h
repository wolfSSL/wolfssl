/* test_pkcs11.h
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

#ifndef WOLFCRYPT_TEST_PKCS11_H
#define WOLFCRYPT_TEST_PKCS11_H

#include <tests/api/api_decl.h>

#if defined(HAVE_PKCS11) && defined(HAVE_ECC) && \
    defined(HAVE_ECC_VERIFY) && !defined(WC_NO_RNG) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP)

int test_wc_Pkcs11_EcdsaSigDecode(void);

#define TEST_PKCS11_DECLS                                                   \
    TEST_DECL_GROUP("pkcs11", test_wc_Pkcs11_EcdsaSigDecode)

#else

#define TEST_PKCS11_DECLS

#endif

#endif /* WOLFCRYPT_TEST_PKCS11_H */
