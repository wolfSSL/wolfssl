#include <stdlib.h>
#include <stdio.h>
#include "wolfssl/wolfcrypt/logging.h"
#include "wolfcrypt/test/test.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wiced.h"

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

void application_start()
{
    func_args args  = { 0 };

    if (wiced_init() ) {
        WPRINT_APP_INFO(("\nError initializing WICED.\n") );
        return;
    }

    if (wolfcrypt_test(&args) != 0) {
        WPRINT_APP_INFO( ("Error in wolfCrypt test.\n") );
        return;
    }
    if (wolfCrypt_Cleanup() ) {
           WPRINT_APP_INFO( ("wolfCrypt error wolcCrypt_Cleanup().\n") );
           return;
    } else {
           WPRINT_APP_INFO( ("wolfCrypt cleanup success.\n") );
    }
}
