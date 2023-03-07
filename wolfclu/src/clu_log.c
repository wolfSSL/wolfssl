/* clu_log.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfclu/wolfclu/clu_header_main.h>
#include <wolfclu/wolfclu/clu_log.h>

#ifndef WOLCLU_LOG_LINE_WIDTH
#define WOLCLU_LOG_LINE_WIDTH 120
#endif

static int loggingLevel = 0; /* 0 is error level and always print,
                                1 is some extra info, 2 is more verbose and so
                                on */
static int loggingEnabled = 1; /* default to on and at level 0 for errors */
void DefaultLoggingCb(int logLevel, const char *const msgStr);
static wolfCLU_LoggingCb logFunction = DefaultLoggingCb;



/* turn debugging off */
void wolfCLU_OutputOFF(void)
{
    loggingEnabled = 0;
}


void wolfCLU_OutputON(void)
{
    loggingEnabled = 1;
}


void DefaultLoggingCb(int logLevel, const char *const msgStr)
{
    if ((loggingEnabled && loggingLevel <= logLevel) ||
        logLevel == WOLFCLU_E0) {
        fprintf(stderr, "%s\r\n", msgStr);
    }
}


/* our default logger */
void wolfCLU_Log(int logLevel, const char *const fmt, ...)
{
    va_list vlist;
    char    msgStr[WOLCLU_LOG_LINE_WIDTH];

    if (loggingLevel < logLevel)
        return;   /* don't need to output */

    /* format msg */
    va_start(vlist, fmt);
    XVSNPRINTF(msgStr, sizeof(msgStr), fmt, vlist);
    va_end(vlist);

    if (logFunction)
        logFunction(logLevel, msgStr);
}


void wolfCLU_LogErrorQueue(void)
{
    unsigned long err;
    const char* file;
    int line = 0;

    while ((err = wolfSSL_ERR_get_error_line_data(&file, &line,
                                                  NULL, NULL)) != 0) {
        if (file != NULL) {
            WOLFCLU_LOG(WOLFCLU_E0, "Error %s:%d: %s (%ld)", file, line,
                        wolfSSL_ERR_error_string(err, NULL), -err);
        }
        else {
            WOLFCLU_LOG(WOLFCLU_E0, "Error: %s (%ld)",
                        wolfSSL_ERR_error_string(err, NULL), -err);
        }
    }
}


void wolfCLU_LogError(const char *const fmt, ...)
{
    va_list vlist;
    char    msgStr[WOLCLU_LOG_LINE_WIDTH];

    /* format msg */
    va_start(vlist, fmt);
    XVSNPRINTF(msgStr, sizeof(msgStr), fmt, vlist);
    va_end(vlist);

    WOLFCLU_LOG(WOLFCLU_E0, "%s", msgStr);

    wolfCLU_LogErrorQueue();
}
