/* suites.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cyassl/ssl.h>
#include <tests/unit.h>


#define MAX_ARGS 40
#define MAX_COMMAND_SZ 240
#define MAX_SUITE_SZ 80 

#include "examples/client/client.h"
#include "examples/server/server.h"


CYASSL_CTX* cipherSuiteCtx = NULL;

/* if the cipher suite on line is valid store in suite and return 1, else 0 */
static int IsValidCipherSuite(const char* line, char* suite)
{
    int  found = 0;
    int  valid = 0;

    const char* find = "-l ";
    char* begin = strnstr(line, find, MAX_COMMAND_SZ);
    char* end;

    suite[0] = '\0';

    if (begin) {
        begin += 3;

        end = strnstr(begin, " ", MAX_COMMAND_SZ);

        if (end) {
            long len = end - begin;
            if (len > MAX_SUITE_SZ) {
                printf("suite too long!\n");
                return 0;
            }
            memcpy(suite, begin, len);
            suite[len] = '\0';
        }
        else
            strncpy(suite, begin, MAX_SUITE_SZ);

        suite[MAX_SUITE_SZ] = '\0';
        found = 1;
    }

    if (found) {
        if (CyaSSL_CTX_set_cipher_list(cipherSuiteCtx, suite) == SSL_SUCCESS)
            valid = 1;
    }

    return valid;
}


static void execute_test_case(int svr_argc, char** svr_argv,
                              int cli_argc, char** cli_argv, int addNoVerify)
{
    func_args cliArgs = {cli_argc, cli_argv, 0, NULL};
    func_args svrArgs = {svr_argc, svr_argv, 0, NULL};

    tcp_ready   ready;
    THREAD_TYPE serverThread;
    char        commandLine[MAX_COMMAND_SZ];
    char        cipherSuite[MAX_SUITE_SZ+1];
    int         i;
    size_t      added = 0;
    static      int tests = 1;

    commandLine[0] = '\0';
    for (i = 0; i < svr_argc; i++) {
        added += strlen(svr_argv[i]) + 2;
        if (added >= MAX_COMMAND_SZ) {
            printf("server command line too long\n"); 
            break;
        }
        strcat(commandLine, svr_argv[i]);
        strcat(commandLine, " ");
    }
    if (addNoVerify) {
        printf("repeating test with client cert request off\n"); 
        added += 3;   /* -d plus terminator */
        if (added >= MAX_COMMAND_SZ)
            printf("server command line too long\n");
        else
            strcat(commandLine, "-d");
    }
    printf("trying server command line[%d]: %s\n", tests, commandLine);


    if (IsValidCipherSuite(commandLine, cipherSuite) == 0) {
        printf("cipher suite %s not supported in build\n", cipherSuite);
        return;
    }

    commandLine[0] = '\0';
    added = 0;
    for (i = 0; i < cli_argc; i++) {
        added += strlen(cli_argv[i]) + 2;
        if (added >= MAX_COMMAND_SZ) {
            printf("client command line too long\n"); 
            break;
        }
        strcat(commandLine, cli_argv[i]);
        strcat(commandLine, " ");
    }
    printf("trying client command line[%d]: %s\n", tests++, commandLine);

    InitTcpReady(&ready);

    /* start server */
    svrArgs.signal = &ready;
    start_thread(server_test, &svrArgs, &serverThread);
    wait_tcp_ready(&svrArgs);

    /* start client */
    client_test(&cliArgs);

    /* verify results */ 
    if (cliArgs.return_code != 0) {
        printf("client_test failed\n");
        exit(EXIT_FAILURE);
    }

    join_thread(serverThread);
    if (svrArgs.return_code != 0) { 
        printf("server_test failed\n");
        exit(EXIT_FAILURE);
    }

    FreeTcpReady(&ready);

}

static void test_harness(void* vargs)
{
    func_args* args = (func_args*)vargs;
    char* script;
    long  sz, len;
    int   cliMode = 0;   /* server or client command flag, server first */
    FILE* file;
    char* svrArgs[MAX_ARGS];
    int   svrArgsSz;
    char* cliArgs[MAX_ARGS];
    int   cliArgsSz;
    char* cursor;
    char* comment;
    const char* fname = "tests/test.conf";

    if (args->argc == 1) {
        printf("notice: using default file %s\n", fname);
    }
    else if(args->argc != 2) {
        printf("usage: harness [FILE]\n");
        args->return_code = 1;
        return;
    }
    else {
        fname = args->argv[1];
    }

    file = fopen(fname, "r");
    if (file == NULL) {
        fprintf(stderr, "unable to open %s\n", fname);
        args->return_code = 1;
        return;
    }
    fseek(file, 0, SEEK_END);
    sz = ftell(file);
    rewind(file);
    if (sz <= 0) {
        fprintf(stderr, "%s is empty\n", fname);
        fclose(file);
        args->return_code = 1;
        return;
    }

    script = (char*)malloc(sz+1);
    if (script == 0) {
        fprintf(stderr, "unable to allocte script buffer\n");
        fclose(file);
        args->return_code = 1;
        return;
    }

    len = fread(script, 1, sz, file);
    if (len != sz) {
        fprintf(stderr, "read error\n");
        fclose(file);
        free(script);
        args->return_code = 1;
        return;
    }
    
    fclose(file);
    script[sz] = 0;

    cursor = script;
    svrArgsSz = 1;
    svrArgs[0] = args->argv[0];
    cliArgsSz = 1;
    cliArgs[0] = args->argv[0];

    while (*cursor != 0) {
        int do_it = 0;

        switch (*cursor) {
            case '\n':
                /* A blank line triggers test case execution or switches
                   to client mode if we don't have the client command yet */
                if (cliMode == 0)
                    cliMode = 1;  /* switch to client mode processing */
                else
                    do_it = 1;    /* Do It, we have server and client */
                cursor++;
                break;
            case '#':
                /* Ignore lines that start with a #. */
                comment = strsep(&cursor, "\n");
                printf("%s\n", comment);
                break;
            case '-':
                /* Parameters start with a -. They end in either a newline
                 * or a space. Capture until either, save in Args list. */
                if (cliMode)
                    cliArgs[cliArgsSz++] = strsep(&cursor, " \n");
                else
                    svrArgs[svrArgsSz++] = strsep(&cursor, " \n");
                break;
            default:
                /* Anything from cursor until end of line that isn't the above
                 * is data for a paramter. Just up until the next newline in
                 * the Args list. */
                if (cliMode)
                    cliArgs[cliArgsSz++] = strsep(&cursor, "\n");
                else
                    svrArgs[svrArgsSz++] = strsep(&cursor, "\n");
                if (*cursor == 0)  /* eof */
                    do_it = 1; 
        }

        if (svrArgsSz == MAX_ARGS || cliArgsSz == MAX_ARGS) {
            fprintf(stderr, "too many arguments, forcing test run\n");
            do_it = 1;
        }

        if (do_it) {
            execute_test_case(svrArgsSz, svrArgs, cliArgsSz, cliArgs, 0);
            execute_test_case(svrArgsSz, svrArgs, cliArgsSz, cliArgs, 1);
            svrArgsSz = 1;
            cliArgsSz = 1;
            cliMode   = 0;
        }
    }

    free(script);
    args->return_code = 0;
}


int SuiteTest(void)
{
    func_args args;
    char argv0[2][80];
    char* myArgv[2];

    printf(" Begin Cipher Suite Tests\n");

    /* setup */
    myArgv[0] = argv0[0];
    myArgv[1] = argv0[1];
    args.argv = myArgv;
    strcpy(argv0[0], "SuiteTest");

    (void)test_harness;

    cipherSuiteCtx = CyaSSL_CTX_new(CyaTLSv1_2_client_method());
    if (cipherSuiteCtx == NULL) {
        printf("can't get cipher suite ctx\n");
        exit(EXIT_FAILURE);  
    }

#if !defined(NO_RSA)
    /* default case */
    args.argc = 1;
    printf("starting default cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

    /* any extra cases will need another argument */
    args.argc = 2;

#ifdef OPENSSL_EXTRA
    /* add openssl extra suites */
    strcpy(argv0[1], "tests/test-openssl.conf");
    printf("starting openssl extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#if !defined(NO_RSA) && defined(HAVE_NULL_CIPHER)
    /* add rsa null cipher suites */
    strcpy(argv0[1], "tests/test-null.conf");
    printf("starting null cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#ifdef HAVE_HC128 
    /* add hc128 extra suites */
    strcpy(argv0[1], "tests/test-hc128.conf");
    printf("starting hc128 extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#ifdef HAVE_RABBIT
    /* add rabbit extra suites */
    strcpy(argv0[1], "tests/test-rabbit.conf");
    printf("starting rabbit extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#if !defined(NO_PSK) && !defined(NO_AES)
    /* add psk extra suites */
    strcpy(argv0[1], "tests/test-psk.conf");
    printf("starting psk extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
    #ifdef CYASSL_DTLS
        /* add psk dtls extra suites */
        strcpy(argv0[1], "tests/test-psk-dtls.conf");
        printf("starting psk extra cipher suite tests\n");
        test_harness(&args);
        if (args.return_code != 0) {
            printf("error from script %d\n", args.return_code);
            exit(EXIT_FAILURE);  
        }
    #endif
#endif

#if !defined(NO_PSK) && defined(HAVE_NULL_CIPHER) && !defined(NO_OLD_TLS)
    strcpy(argv0[1], "tests/test-psk-null.conf");
    printf("starting psk extra null cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#ifdef CYASSL_LEANPSK
    strcpy(argv0[1], "tests/test-leanpsk.conf");
    printf("starting lean-psk cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#ifdef HAVE_NTRU
    /* add ntru extra suites */
    strcpy(argv0[1], "tests/test-ntru.conf");
    printf("starting ntru extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#ifdef HAVE_ECC
    /* add ecc extra suites */
    strcpy(argv0[1], "tests/test-ecc.conf");
    printf("starting ecc extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
    #ifdef CYASSL_DTLS
        /* add ecc dtls extra suites */
        strcpy(argv0[1], "tests/test-ecc-dtls.conf");
        printf("starting ecc dtls extra cipher suite tests\n");
        test_harness(&args);
        if (args.return_code != 0) {
            printf("error from script %d\n", args.return_code);
            exit(EXIT_FAILURE);  
        }
    #endif
    #ifdef CYASSL_SHA384
        /* add ecc sha384 extra suites */
        strcpy(argv0[1], "tests/test-ecc-sha384.conf");
        printf("starting ecc sha384 extra cipher suite tests\n");
        test_harness(&args);
        if (args.return_code != 0) {
            printf("error from script %d\n", args.return_code);
            exit(EXIT_FAILURE);  
        }
    #endif
    #if defined(CYASSL_DTLS) && defined(CYASSL_SHA384)
        /* add ecc dtls sha384 extra suites */
        strcpy(argv0[1], "tests/test-ecc-dtls-sha384.conf");
        printf("starting ecc dtls sha384 extra cipher suite tests\n");
        test_harness(&args);
        if (args.return_code != 0) {
            printf("error from script %d\n", args.return_code);
            exit(EXIT_FAILURE);  
        }
    #endif
#endif

#ifdef HAVE_AESGCM
    /* add aesgcm extra suites */
    strcpy(argv0[1], "tests/test-aesgcm.conf");
    printf("starting aesgcm extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#if defined(HAVE_AESGCM) && defined(OPENSSL_EXTRA)
    /* add aesgcm openssl extra suites */
    strcpy(argv0[1], "tests/test-aesgcm-openssl.conf");
    printf("starting aesgcm openssl extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

#if defined(HAVE_AESGCM) && defined(HAVE_ECC)
    /* add aesgcm ecc extra suites */
    strcpy(argv0[1], "tests/test-aesgcm-ecc.conf");
    printf("starting aesgcm ecc extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
    #ifdef CYASSL_DTLS
        /* add aesgcm ecc dtls extra suites */
        strcpy(argv0[1], "tests/test-aesgcm-ecc-dtls.conf");
        printf("starting aesgcm ecc dtls extra cipher suite tests\n");
        test_harness(&args);
        if (args.return_code != 0) {
            printf("error from script %d\n", args.return_code);
            exit(EXIT_FAILURE);  
        }
    #endif
#endif

#if defined(HAVE_AESCCM)
    /* add aesccm extra suites */
    strcpy(argv0[1], "tests/test-aesccm.conf");
    printf("starting aesccm cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
    #ifdef HAVE_ECC
        /* add aesccm ecc extra suites */
        strcpy(argv0[1], "tests/test-aesccm-ecc.conf");
        printf("starting aesccm ecc cipher suite tests\n");
        test_harness(&args);
        if (args.return_code != 0) {
            printf("error from script %d\n", args.return_code);
            exit(EXIT_FAILURE);  
        }
        #ifdef CYASSL_DTLS
            /* add aesccm ecc dtls extra suites */
            strcpy(argv0[1], "tests/test-aesccm-ecc-dtls.conf");
            printf("starting aesccm ecc dtls cipher suite tests\n");
            test_harness(&args);
            if (args.return_code != 0) {
                printf("error from script %d\n", args.return_code);
                exit(EXIT_FAILURE);  
            }
        #endif
    #endif
#endif

#ifdef HAVE_CAMELLIA
    /* add camellia suites */
    strcpy(argv0[1], "tests/test-camellia.conf");
    printf("starting camellia suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
    #ifdef OPENSSL_EXTRA
        /* add camellia openssl extra suites */
        strcpy(argv0[1], "tests/test-camellia-openssl.conf");
        printf("starting camellia openssl extra suite tests\n");
        test_harness(&args);
        if (args.return_code != 0) {
            printf("error from script %d\n", args.return_code);
            exit(EXIT_FAILURE);  
        }
    
    #endif
#endif

#ifdef CYASSL_DTLS 
    /* add dtls extra suites */
    strcpy(argv0[1], "tests/test-dtls.conf");
    printf("starting dtls extra cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }
#endif

    printf(" End Cipher Suite Tests\n");

    CyaSSL_CTX_free(cipherSuiteCtx);

    return args.return_code;
}


