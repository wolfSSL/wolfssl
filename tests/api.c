/* api.c API unit tests */
#include <cyassl/ssl.h>

// 0 on success, otherwise fail
int test_CyaSSL_Init(void)
{
    int result = CyaSSL_Init();
    
    if (result) printf("test_CyaSSL_Init(): failed\n");

    return (result);
}

