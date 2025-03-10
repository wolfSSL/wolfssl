/* test_sha512.h
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

#ifndef WOLFCRYPT_TEST_SHA512_H
#define WOLFCRYPT_TEST_SHA512_H

int test_wc_InitSha512(void);
int test_wc_Sha512Update(void);
int test_wc_Sha512Final(void);
int test_wc_Sha512FinalRaw(void);
int test_wc_Sha512_KATs(void);
int test_wc_Sha512_other(void);
int test_wc_Sha512Copy(void);
int test_wc_Sha512GetHash(void);
int test_wc_Sha512Transform(void);
int test_wc_Sha512_Flags(void);

int test_wc_InitSha512_224(void);
int test_wc_Sha512_224Update(void);
int test_wc_Sha512_224Final(void);
int test_wc_Sha512_224FinalRaw(void);
int test_wc_Sha512_224_KATs(void);
int test_wc_Sha512_224_other(void);
int test_wc_Sha512_224Copy(void);
int test_wc_Sha512_224GetHash(void);
int test_wc_Sha512_224Transform(void);
int test_wc_Sha512_224_Flags(void);

int test_wc_InitSha512_256(void);
int test_wc_Sha512_256Update(void);
int test_wc_Sha512_256Final(void);
int test_wc_Sha512_256FinalRaw(void);
int test_wc_Sha512_256_KATs(void);
int test_wc_Sha512_256_other(void);
int test_wc_Sha512_256Copy(void);
int test_wc_Sha512_256GetHash(void);
int test_wc_Sha512_256Transform(void);
int test_wc_Sha512_256_Flags(void);

int test_wc_InitSha384(void);
int test_wc_Sha384Update(void);
int test_wc_Sha384Final(void);
int test_wc_Sha384FinalRaw(void);
int test_wc_Sha384_KATs(void);
int test_wc_Sha384_other(void);
int test_wc_Sha384Copy(void);
int test_wc_Sha384GetHash(void);
int test_wc_Sha384_Flags(void);

#endif /* WOLFCRYPT_TEST_SHA512_H */
