/* user_settings.h
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define CloseSocket close
#define NO_DEV_RANDOM
#define USE_CERT_BUFFERS_2048
#define WOLFSSL_USER_CURRTIME
#define SIZEOF_LONG_LONG 8
#define NO_WOLFSSL_DIR 
#define WOLFSSL_NO_CURRDIR
#define WOLFSSL_LOG_PRINTF
#define NO_FILESYSTEM

/* #define DEBUG_WOLFSSL */

#define OPENSSL_EXTRA

#define WOLFSSL_SMALL_STACK
#define WOLFSSL_DH_CONST
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES

/* #define USER_TIME */
/* #define XTIME time */
#define TIME_OVERRIDES
#define HAVE_TM_TYPE
#define HAVE_TIME_T_TYPE
#define USE_WOLF_SUSECONDS_T
#define USE_WOLF_TIMEVAL_T

#define WOLFSSL_USER_CURRTIME /* for benchmark */

#define WOLFSSL_GENSEED_FORTEST /* Wardning: define your own seed gen */

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#define SINGLE_THREADED  /* or define RTOS  option */
/* #undef SINGLE_THREADED */
/*#define WOLFSSL_CMSIS_RTOS */

/* #define NO_DH */
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519
#define NO_OLD_SHA256_NAMES

/*#define NO_WOLFSSL_STUB*/
#define WOLFSSL_SHA384
#define HAVE_CRL

/* Platform */
#define RI600V4

/* Server Renegotiate */
#define WOLFSSL_SERVER_RENEGOTIATION
#define HAVE_SERVER_RENEGOTIATION_INFO

#if defined(TIME_OVERRIDES) && defined(HAVE_TM_TYPE) && defined(HAVE_TIME_T_TYPE)
   /* #include "time_mng.h" */
    typedef unsigned long Time_t;
    #define time_t Time_t
    #define WOLFSSL_GMTIME
    #define XGMTIME gmtime
    #define XTIME user_time

    struct tm {
        int   tm_sec;
        int   tm_min;
        int   tm_hour;
        int   tm_mday;
        int   tm_wday;
        int   tm_mon;
        int   tm_year;
        int   tm_yday;
        int   tm_isdst;
    };
#endif

// #define HAVE_STUNNEL
#define KEEP_OUR_CERT

#ifdef NO_ASN
#undef NO_ASN
#endif

#define WOLFSSL_GETENV_RANDFILE "randfile"
#define WOLFSSL_GETENV_HOME "envhome"