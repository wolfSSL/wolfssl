#ifndef MICRIUM_USER_SETTINGS_H_
#define MICRIUM_USER_SETTINGS_H_

#ifdef __cplusplus
    extern "C" {
#endif

#define MICRIUM
#define WOLFSSL_MICRIUM_3_0

#define WOLFSSL_BENCHMARK_TEST
/*
#define WOLFSSL_MICRIUM_CRYPTO_TEST
#define WOLFSSL_MICRIUM_CLIENT_TEST
#define WOLFSSL_MICRIUM_SERVER_TEST
*/

/* test.h includes platform dependent header files.
When using Windows simulator, you must define USE_WINDOWS_API */
#ifdef _WIN32
define USE_WINDOWS_API
#endif

#define NO_FILESYSTEM
#define SIZEOF_LONG_LONG 8

/* prevents from including multiple definition of main() */
#define NO_MAIN_DRIVER
#define NO_TESTSUITE_MAIN_DRIVER

/* wolfSSL_dtls_get_current_timeout is called from MicriumReceiveFrom */
#define WOLFSSL_DTLS

/* includes certificate test buffers via header files */
#define USE_CERT_BUFFERS_2048
/*use kB instead of mB for embedded benchmarking*/
#define BENCH_EMBEDDED
#define NO_ECC_VECTOR_TEST
#define NO_WRITE_TEMP_FILES

/* no pow, no math.h */
#define WOLFSSL_DH_CONST

#define XSNPRINTF snprintf

//#define NO_ASN_TIME

#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif
