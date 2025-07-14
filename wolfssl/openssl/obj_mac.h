/* obj_mac.h
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
 */

/* obj_mac.h for openSSL */

#ifndef WOLFSSL_OBJ_MAC_H_
#define WOLFSSL_OBJ_MAC_H_
#ifdef __cplusplus
    extern "C" {
#endif

#define WC_NID_sect163k1 721
#define WC_NID_sect163r1 722
#define WC_NID_sect163r2 723
#define WC_NID_sect193r1 724
#define WC_NID_sect193r2 725
#define WC_NID_sect233k1 726
#define WC_NID_sect233r1 727
#define WC_NID_sect239k1 728
#define WC_NID_sect283k1 729
#define WC_NID_sect283r1 730
#define WC_NID_sect409k1 731
#define WC_NID_sect409r1 732
#define WC_NID_sect571k1 733
#define WC_NID_sect571r1 734

#ifndef OPENSSL_COEXIST

#define NID_sect163k1 WC_NID_sect163k1
#define NID_sect163r1 WC_NID_sect163r1
#define NID_sect163r2 WC_NID_sect163r2
#define NID_sect193r1 WC_NID_sect193r1
#define NID_sect193r2 WC_NID_sect193r2
#define NID_sect233k1 WC_NID_sect233k1
#define NID_sect233r1 WC_NID_sect233r1
#define NID_sect239k1 WC_NID_sect239k1
#define NID_sect283k1 WC_NID_sect283k1
#define NID_sect283r1 WC_NID_sect283r1
#define NID_sect409k1 WC_NID_sect409k1
#define NID_sect409r1 WC_NID_sect409r1
#define NID_sect571k1 WC_NID_sect571k1
#define NID_sect571r1 WC_NID_sect571r1

/* mapping of short names */
#define SN_md4        WC_SN_md4
#define SN_md5        WC_SN_md5
#define SN_sha1       WC_SN_sha1
#define SN_sha224     WC_SN_sha224
#define SN_sha256     WC_SN_sha256
#define SN_sha384     WC_SN_sha384
#define SN_sha512     WC_SN_sha512
#define SN_sha512_224 WC_SN_sha512_224
#define SN_sha512_256 WC_SN_sha512_256
#define SN_sha3_224   WC_SN_sha3_224
#define SN_sha3_256   WC_SN_sha3_256
#define SN_sha3_384   WC_SN_sha3_384
#define SN_sha3_512   WC_SN_sha3_512
#define SN_shake128   WC_SN_shake128
#define SN_shake256   WC_SN_shake256
#define SN_blake2s256 WC_SN_blake2s256
#define SN_blake2s512 WC_SN_blake2s512
#define SN_blake2b512 WC_SN_blake2b512
#define SN_sm3        WC_SN_sm3

#endif /* !OPENSSL_COEXIST */

/* the definition is for Qt Unit test */
#define SN_jurisdictionCountryName "jurisdictionC"
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_OBJ_MAC_H_ */

