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
#include <cyassl/test.h>


#define NO_MAIN_DRIVER
#define MAX_ARGS 40

static void execute_test_case(int argc, char** argv)
{
    func_args cliArgs = {argc, argv, 0, NULL};
    func_args svrArgs = {argc, argv, 0, NULL};
    int i;

    printf("argc = %d\n", argc);
        for (i = 0; i < argc; i++)
            printf(" argv[%d] = %s\n", i, argv[i]);

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
    char argv0[32];
    char* myArgv[1];

    args.argc = 1;
    myArgv[0] = argv0;
    args.argv = myArgv;
    strcpy(argv0, "SuiteTest");

    test_harness(&args);

    return args.return_code;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        StartTCP();

        args.argc = argc;
        args.argv = argv;

        CyaSSL_Init();
#ifdef DEBUG_CYASSL
        CyaSSL_Debugging_ON();
#endif
        if (CurrentDir("client") || CurrentDir("build"))
            ChangeDirBack(2);
   
        test_harness(&args);
        CyaSSL_Cleanup();

        return args.return_code;
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */
