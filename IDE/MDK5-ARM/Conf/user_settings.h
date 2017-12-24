
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED

#define NO_DEV_RANDOM

#define WOLFSSL_USER_CURRTIME
#define SIZEOF_LONG_LONG 8
#define NO_WRITEV

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* #define SINGLE_THREADED     or define RTOS  option */
#define WOLFSSL_CMSIS_RTOS

#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519
#define ED25519_SMALL

#define NO_ERROR_STRINGS
#define NO_BIG_INT

/* Hardware Crypt
#define WOLFSSL_STM32_CUBEMX
#define STM32_CRYPTO
#define STM32_HASH
#define STM32_RNG
#define WOLFSSL_STM32F7
#define STM32_HAL_TIMEOUT 0xFF
*/


/* 
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define WC_RSA_PSS
#define HAVE_HKDF
*/

/* #define NO_FILESYSTEM         or define Filesystem option */
#define NO_WOLFSSL_DIR

/* #define WOLFSSL_USER_IO      or use BSD incompatible TCP stack */
#define WOLFSSL_KEIL_TCP_NET

#define NO_DEV_RANDOM
/* define your Rand gen for the operational use */
#define WOLFSSL_GENSEED_FORTEST
#define HAVE_HASHDRBG
#define USE_WOLFSSL_MEMORY
#define WOLFSSL_MALLOC_CHECK

#define XVALIDATE_DATE(d, f,t) (1)
//#define TIME_OVERRIDES
#include <time.h>
#define XGMTIME(a, b) gmtime(a, b)

unsigned int HAL_GetTick(void);
#define XTIME(a)    HAL_GetTick()

#define HAVE_TIME_T_TYPE
#define HAVE_TM_TYPE

#define WOLFSSL_USER_CURRTIME /* for benchmark */

#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT

/* #define DEBUG_WOLFSSL for Debug Log */
