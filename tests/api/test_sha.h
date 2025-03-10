/* test_sha.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLFCRYPT_TEST_SHA_H
#define WOLFCRYPT_TEST_SHA_H

int test_wc_InitSha(void);
int test_wc_ShaUpdate(void);
int test_wc_ShaFinal(void);
int test_wc_ShaFinalRaw(void);
int test_wc_Sha_KATs(void);
int test_wc_Sha_other(void);
int test_wc_ShaCopy(void);
int test_wc_ShaGetHash(void);
int test_wc_ShaTransform(void);
int test_wc_Sha_Flags(void);

#endif /* WOLFCRYPT_TEST_SHA_H */
