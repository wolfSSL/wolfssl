//
//  wolfssl_test.c
//  wolfssl-multiplatform
//
//  Created by Brett Nicholas on 7/11/23.
//

#include "wolfssl_test_driver.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "test.h"
#include "benchmark.h"
#include "simple_client_example.h"

typedef struct test_func_args {
    int argc;
    char** argv;
    int return_code;
} test_func_args;



void wolfssl_test(void)
{
    int ret;
    test_func_args args = {0};
    
#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif
    
    printf("Run wolfCrypt Test:\n");
    ret = wolfcrypt_test(&args);
    printf("\nResult of wolfcrypt_test() = %d\n\n", ret);
    
    printf("Run wolfCrypt Benchmark:\n");
    ret = benchmark_test(&args);
    printf("\nResult of benchmark_test() = %d\n\n", ret);
    
    printf("Run simple client test:\n");
    ret = simple_client_example();
    printf("\nResult of simple_client_test() = %d\n\n", ret);
    
}
