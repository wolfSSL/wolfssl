/* suites.c
 *
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
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

#include <stdlib.h>
#include <stdio.h>
#include <cyassl/ssl.h>
#include <tests/unit.h>


#define MAX_ARGS 40
#define MAX_COMMAND_SZ 240


void client_test(void*);
THREAD_RETURN CYASSL_THREAD server_test(void*);


static void execute_test_case(int argc, char** argv)
{
    func_args cliArgs = {argc, argv, 0, NULL};
    func_args svrArgs = {argc, argv, 0, NULL};

    tcp_ready   ready;
    THREAD_TYPE serverThread;
    char        commandLine[MAX_COMMAND_SZ];
    int         i;
    static      int tests = 0;

    commandLine[0] = '\0';
    for (i = 0; i < argc; i++) {
        strcat(commandLine, argv[i]);
        strcat(commandLine, " ");
    }
    printf("trying command line[%d]: %s\n", tests++, commandLine);

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

void test_harness(void* vargs)
{
    func_args* args = (func_args*)vargs;
    char* script;
    long sz, len;
    FILE* file;
    char* testArgs[MAX_ARGS];
    int testArgsSz;
    char* cursor;
    char* comment;
    char* fname = "tests/test.conf";


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
    if (sz == 0) {
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
        args->return_code = 1;
        return;
    }
    
    fclose(file);
    script[sz] = 0;

    cursor = script;
    testArgsSz = 1;
    testArgs[0] = args->argv[0];

    while (*cursor != 0) {
        if (testArgsSz == MAX_ARGS) {
            fprintf(stderr, "too many arguments, forcing test run\n");
            execute_test_case(testArgsSz, testArgs);
            testArgsSz = 1;
        }

        switch (*cursor) {
            case '\n':
                /* A blank line triggers test case execution. */
                execute_test_case(testArgsSz, testArgs);
                testArgsSz = 1;
                cursor++;
                break;
            case '#':
                /* Ignore lines that start with a #. */
                comment = strsep(&cursor, "\n");
                printf("%s\n", comment);
                break;
            case '-':
                /* Parameters start with a -. They end in either a newline
                 * or a space. Capture until either, save in testArgs list. */
                testArgs[testArgsSz++] = strsep(&cursor, " \n");
                break;
            default:
                /* Anything from cursor until end of line that isn't the above
                 * is data for a paramter. Just up until the next newline in
                 * the testArgs list. */
                testArgs[testArgsSz++] = strsep(&cursor, "\n");
                if (*cursor == 0)
                    execute_test_case(testArgsSz, testArgs);
        }
    }

    free(script);
    args->return_code = 0;
}


int SuiteTest(void)
{
    func_args args;
    char argv0[2][32];
    char* myArgv[2];

    printf(" Begin Cipher Suite Tests\n");

    /* setup */
    myArgv[0] = argv0[0];
    myArgv[1] = argv0[1];
    args.argv = myArgv;
    strcpy(argv0[0], "SuiteTest");

    /* default case */
    args.argc = 1;
    printf("starting default cipher suite tests\n");
    test_harness(&args);
    if (args.return_code != 0) {
        printf("error from script %d\n", args.return_code);
        exit(EXIT_FAILURE);  
    }

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

    printf(" End Cipher Suite Tests\n");

    return args.return_code;
}


