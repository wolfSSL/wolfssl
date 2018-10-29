#ifndef MICRIUM_USER_SETTINGS_H_
#define MICRIUM_USER_SETTINGS_H_

#ifdef __cplusplus
    extern "C" {
#endif

#define MICRIUM

#define WOLFSSL_MICRIUM_3_0

/*for test.h to include platform dependent socket related header files.*/
#define USE_WINDOWS_API

#define SIZEOF_LONG_LONG 8

#define NO_FILESYSTEM

#define NO_MAIN_DRIVER

#define NO_TESTSUITE_MAIN_DRIVER

// wolfSSL_dtls_get_current_timeout is called from MicriumReceiveFrom
#define WOLFSSL_DTLS

/* include certificate test buffers via header files */
#define USE_CERT_BUFFERS_2048

/*use kB instead of mB for embedded benchmarking*/
#define BENCH_EMBEDDED

#define NO_ECC_VECTOR_TEST

#define NO_WRITE_TEMP_FILES

// no pow, no math.h
#define WOLFSSL_DH_CONST

#define XSNPRINTF snprintf

#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif
