/* user_settings.h
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
#if 1
    #define OPENSSL_COEXIST

    /* HKDF for engine */
    #undef HAVE_HKDF
    #if 1
        #define HAVE_HKDF
        #define HAVE_X963_KDF
    #endif

    #undef WOLFSSL_PUBLIC_MP
    #define WOLFSSL_PUBLIC_MP

    #undef NO_OLD_RNGNAME
    #define NO_OLD_RNGNAME

    #undef NO_OLD_WC_NAMES
    #define NO_OLD_WC_NAMES

    #undef NO_OLD_SSL_NAMES
    #define NO_OLD_SSL_NAMES

    #undef NO_OLD_SHA_NAMES
    #define NO_OLD_SHA_NAMES

    #undef NO_OLD_MD5_NAME
    #define NO_OLD_MD5_NAME

    #undef NO_OLD_SHA256_NAMES
    #define NO_OLD_SHA256_NAMES
#endif

#undef WOLFSSL_SYS_CA_CERTS
#define WOLFSSL_SYS_CA_CERTS

#undef LIBWOLFSSL_GLOBAL_EXTRA_CFLAGS
#define LIBWOLFSSL_GLOBAL_EXTRA_CFLAGS

#undef HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_SERVER_RENEGOTIATION_INFO

/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#undef  NO_WOLFSSL_SERVER
//#define NO_WOLFSSL_SERVER

#undef  NO_WOLFSSL_CLIENT
//#define NO_WOLFSSL_CLIENT

#undef  NO_CRYPT_TEST
//#define NO_CRYPT_TEST

#undef  NO_CRYPT_BENCHMARK
//#define NO_CRYPT_BENCHMARK

#undef  WOLFCRYPT_ONLY
#define WOLFCRYPT_ONLY

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#undef  NO_INLINE
//#define NO_INLINE

#undef  NO_FILESYSTEM
//#define NO_FILESYSTEM

#undef  NO_WRITEV
//#define NO_WRITEV

#undef  NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef  NO_DEV_RANDOM
//#define NO_DEV_RANDOM

#undef  NO_DSA
#define NO_DSA

#undef  NO_RC4
#define NO_RC4

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PWDBASED
//#define NO_PWDBASED

#undef  NO_CODING
//#define NO_CODING

#undef  NO_ASN_TIME
//#define NO_ASN_TIME

#undef  NO_CERTS
//#define NO_CERTS

#undef  NO_SIG_WRAPPER
//#define NO_SIG_WRAPPER

#undef NO_DO178
#define NO_DO178

#undef WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE128

#undef WOLFSSL_NO_SHAKE256
#define WOLFSSL_NO_SHAKE256

/* wolfSSL engineering ACVP algo and operational testing only (Default: Off) */
#if 1
    #undef WOLFSSL_PUBLIC_MP
    #define WOLFSSL_PUBLIC_MP

    #undef OPTEST_LOGGING_ENABLED
    //#define OPTEST_LOGGING_ENABLED

    #undef OPTEST_INVALID_LOGGING_ENABLED
    //#define OPTEST_INVALID_LOGGING_ENABLED

    #undef NO_MAIN_OPTEST_DRIVER
    #define NO_MAIN_OPTEST_DRIVER

    #undef DEBUG_FIPS_VERBOSE
    #define DEBUG_FIPS_VERBOSE

    #undef HAVE_FORCE_FIPS_FAILURE
    #define HAVE_FORCE_FIPS_FAILURE

    #undef NO_WRITE_TEMP_FILES
    #define NO_WRITE_TEMPT_FILES
#endif

#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_USER_SETTINGS_H */
