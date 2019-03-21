/* user_setting.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

#ifndef DEOS_USER_SETTINGS_H_
#define DEOS_USER_SETTINGS_H_

#ifdef __cplusplus
    extern "C" {
#endif

#define WOLFSSL_DEOS

/* You can select none or all of the following tests
using #define instead of #undef.
By default, all four tests run*/

#undef NO_CRYPT_TEST
#undef NO_CRYPT_BENCHMARK
#undef NO_WOLFSSL_CLIENT
#undef NO_WOLFSSL_SERVER

/* adjust CURRENT_UNIX_TIMESTAMP to seconds since Jan 01 1970. (UTC)
You can get the current time from https://www.unixtimestamp.com/
*/
#define CURRENT_UNIX_TIMESTAMP 1545864916

#define NO_FILESYSTEM
#define SIZEOF_LONG_LONG 8

/* prevents from including multiple definition of main() */
#define NO_MAIN_DRIVER
#define NO_TESTSUITE_MAIN_DRIVER

/* includes certificate test buffers via header files */
#define USE_CERT_BUFFERS_2048

/*use kB instead of mB for embedded benchmarking*/
#define BENCH_EMBEDDED

#define NO_WRITE_TEMP_FILES

#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519
#define ED25519_SMALL

/* TLS 1.3 */
#if 0
    #define WOLFSSL_TLS13
    #define WC_RSA_PSS
    #define HAVE_HKDF
    #define HAVE_FFDHE_2048
    #define HAVE_AEAD
#endif

#if 0

/* You can use your own custom random generator function with
   no input parameters and a `CUSTOM_RAND_TYPE` return type*/

    #ifndef CUSTOM_RAND_GENERATE
         #define CUSTOM_RAND_TYPE     int
         #define CUSTOM_RAND_GENERATE yourRandGenFunc
    #endif

#endif

#if 1
    #undef  XMALLOC_OVERRIDE
    #define XMALLOC_OVERRIDE
    /* prototypes for user heap override functions */

    #include <stddef.h>  /* for size_t */

    extern void *malloc_deos(size_t size);
    extern void  free_deos(void *ptr);
    extern void *realloc_deos(void *ptr, size_t size);

    #define XMALLOC(n, h, t)     malloc_deos(n)
    #define XFREE(p, h, t)       free_deos(p)
    #define XREALLOC(p, n, h, t) realloc_deos(p, n)

#endif

#define printf printx

#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif
