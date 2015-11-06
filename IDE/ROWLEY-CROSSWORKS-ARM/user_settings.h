/* Configuration */
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_GENERAL_ALIGNMENT   4
#define NO_MAIN_DRIVER
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_WOLFSSL_MEMORY

/* HW Crypto Acceleration */
// See README.md for instructions
//#define FREESCALE_MMCAU   1

/* Benchmark */
#define BENCH_EMBEDDED
#define USE_CERT_BUFFERS_2048

/* Custom functions */
extern int custom_rand_generate(void);
#define CUSTOM_RAND_GENERATE  custom_rand_generate
#define CUSTOM_RAND_TYPE      word32
#define WOLFSSL_USER_CURRTIME

/* Debugging - Optional */
#if 0
#define fprintf(file, format, ...)   printf(format, ##__VA_ARGS__)
#define DEBUG_WOLFSSL
#endif
