/* main.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of CyaSSL.
 *
 * Contact licensing@yassl.com with any questions or comments.
 *
 * http://www.yassl.com
 */


#define PIC32_STARTER_KIT

#include <stdio.h>
#include <stdlib.h>
#include <p32xxxx.h>
#include <plib.h>
#include <sys/appio.h>

/* func_args from test.h, so don't have to pull in other junk */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

/*
 * Main driver for CTaoCrypt tests.
 */
int main(int argc, char** argv) {

    SYSTEMConfigPerformance(80000000);

    DBINIT();
    printf("CTaoCrypt Test:\n");

    func_args args;

    args.argc = argc;
    args.argv = argv;

    ctaocrypt_test(&args);

    if (args.return_code == 0) {
        printf("All tests passed!\n");
    }
    
    return 0;
}

