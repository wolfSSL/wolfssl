
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM
#define USE_CERT_BUFFERS_2048
#define WOLFSSL_USER_CURRTIME

#define CUSTOM_RAND_GENERATE custom_rand_generate
/*  warning "write a real random seed!!!!, just for testing now"   */
static int custom_rand_generate(void) { return 0 ; }