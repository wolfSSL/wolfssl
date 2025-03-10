#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM
#define USE_CERT_BUFFERS_2048
#define WOLFSSL_USER_CURRTIME
#define SIZEOF_LONG_LONG 8
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_CURRDIR
#define NO_WOLF_C99
#define NO_MULTIBYTE_PRINT

#define XVALIDATEDATE(d, f,t) (0)
#define WOLFSSL_USER_CURRTIME /* for benchmark */

#define WOLFSSL_GENSEED_FORTEST /* Warning: define your own seed gen */

/* A few examples of different math options below.
 *
 * See examples/configs/user_settings_template.h for a more
 * detailed template. */
#if 1
    /* Use only single precision (SP) math and algorithms.
     * SP math is written to accelerate specific/common key
     * sizes and curves. This adds code from sp_c32.c, or one of the specific
     * assembly implementations like sp_cortexm.c. This code is faster than the
     * multi-precision support because it's optimized for the key/curve.
     * The SP math can be used together with any multi-precision math library
     * if WOLFSSL_SP_MATH is removed. If only standard keys/curves are being
     * used the multi-precision math is not required.
     */
    #define WOLFSSL_SP_MATH
    /* Enable SP ECC support */
    #define WOLFSSL_HAVE_SP_ECC
    /* Enable SP RSA support */
    #define WOLFSSL_HAVE_SP_RSA
    /* Enable SP DH support */
    #define WOLFSSL_HAVE_SP_DH
    /* Reduce stack use specifically in SP implementation.  */
    #define WOLFSSL_SP_SMALL_STACK
    /* use smaller version of code */
    #define WOLFSSL_SP_SMALL
    /* Assembly optimized version - sp_cortexm.c */
    //#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#elif 1
    /* Use SP math for all key sizes and curves. This will use
     * the multi-precision (MP) math implementation in sp_int.c */
    #define WOLFSSL_SP_MATH_ALL
    /* Disable use of dynamic stack items */
    #define WOLFSSL_SP_NO_DYN_STACK
    /* use smaller version of code */
    #define WOLFSSL_SP_SMALL
#elif 1
    /* Fast Math (tfm.c) (stack based and timing resistant) */
    #define USE_FAST_MATH
    /* Enable Fast Math Timing Resistance */
    #define TFM_TIMING_RESISTANT
#else
    /* Normal (integer.c) (heap based, not timing resistant) - not recommended*/
    #define USE_INTEGER_HEAP_MATH
#endif

/* Enable ECC Timing Resistance */
#define ECC_TIMING_RESISTANT
/* Enables blinding mode, to prevent timing attacks */
#define WC_RSA_BLINDING

/* reduce stack use. For variables over 100 bytes allocate from heap */
#define WOLFSSL_SMALL_STACK
/* disable mutex locking */
#define SINGLE_THREADED  /* or define RTOS  option */
/* #define WOLFSSL_CMSIS_RTOS */
#define NO_FILESYSTEM

/* #define NO_DH */
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519
