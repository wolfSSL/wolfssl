
/* options */
#define SINGLE_THREADED    /* or pthread, Win API, any RTOS */
#define NO_FILESYSTEM      /* for key/cert buffers */
#define WOLFSSL_USER_IO    /* for send/recv  */

/* #define WOLFSSL_USER_TIME for time(), gmtime() */

/*  warning "write a real random seed!!!!, just for testing now"   */
#define NO_DEV_RANDOM
#define CUSTOM_RAND_GENERATE custom_rand_generate
static int custom_rand_generate(void) { return 0 ; }

/* #define NO_MAIN_DRIVER  for test.c/benchmark.c */
/* #define BENCH_EMBEDDED  for benchmark.c        */

#define NO_WRITEV
