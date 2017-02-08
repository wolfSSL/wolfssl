/* logging.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/* submitted by eof */

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


#ifdef __cplusplus
    extern "C" {
#endif
    WOLFSSL_API int  wolfSSL_Debugging_ON(void);
    WOLFSSL_API void wolfSSL_Debugging_OFF(void);
#ifdef __cplusplus
    } 
#endif


#ifdef DEBUG_WOLFSSL
    #if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
    volatile char          wc_last_error_file[80];
    volatile unsigned long wc_last_error_line;
    volatile unsigned long wc_last_error;
    #endif

/* Set these to default values initially. */
static wolfSSL_Logging_cb log_function = 0;
static int loggingEnabled = 0;

#endif /* DEBUG_WOLFSSL */


int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb f)
{
#ifdef DEBUG_WOLFSSL
    int res = 0;

    if (f)
        log_function = f;
    else
        res = BAD_FUNC_ARG;

    return res;
#else
    (void)f;
    return NOT_COMPILED_IN;
#endif
}


int wolfSSL_Debugging_ON(void)
{
#ifdef DEBUG_WOLFSSL
    loggingEnabled = 1;
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}


void wolfSSL_Debugging_OFF(void)
{
#ifdef DEBUG_WOLFSSL
    loggingEnabled = 0;
#endif
}


#ifdef DEBUG_WOLFSSL

#if defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #if MQX_USE_IO_OLD
        #include <fio.h>
    #else
        #include <nio.h>
    #endif
#else
    #include <stdio.h>   /* for default printf stuff */
#endif

#ifdef THREADX
    int dc_log_printf(char*, ...);
#endif

static void wolfssl_log(const int logLevel, const char *const logMessage)
{
    if (log_function)
        log_function(logLevel, logMessage);
    else {
        if (loggingEnabled) {
#ifdef THREADX
            dc_log_printf("%s\n", logMessage);
#elif defined(MICRIUM)
        #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
            NetSecure_TraceOut((CPU_CHAR *)logMessage);
        #endif
#elif defined(WOLFSSL_MDK_ARM)
            fflush(stdout) ;
            printf("%s\n", logMessage);
            fflush(stdout) ;
#elif defined(WOLFSSL_LOG_PRINTF)
            printf("%s\n", logMessage);
#elif defined(WOLFSSL_UTASKER)
            fnDebugMsg((char*)logMessage);
            fnDebugMsg("\r\n");
#else
            fprintf(stderr, "%s\n", logMessage);
#endif
        }
    }
}


void WOLFSSL_MSG(const char* msg)
{
    if (loggingEnabled)
        wolfssl_log(INFO_LOG , msg);
}


void WOLFSSL_BUFFER(byte* buffer, word32 length)
{
    #define LINE_LEN 16

    if (loggingEnabled) {
        word32 i;
        char line[80];

        if (!buffer) {
            wolfssl_log(INFO_LOG, "\tNULL");

            return;
        }

        sprintf(line, "\t");

        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                sprintf(line + 1 + i * 3,"%02x ", buffer[i]);
            else
                sprintf(line + 1 + i * 3, "   ");
        }

        sprintf(line + 1 + LINE_LEN * 3, "| ");

        for (i = 0; i < LINE_LEN; i++)
            if (i < length)
                sprintf(line + 3 + LINE_LEN * 3 + i,
                     "%c", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');

        wolfssl_log(INFO_LOG, line);

        if (length > LINE_LEN)
            WOLFSSL_BUFFER(buffer + LINE_LEN, length - LINE_LEN);
    }
}


void WOLFSSL_ENTER(const char* msg)
{
    if (loggingEnabled) {
        char buffer[80];
        sprintf(buffer, "wolfSSL Entering %s", msg);
        wolfssl_log(ENTER_LOG , buffer);
    }
}


void WOLFSSL_LEAVE(const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[80];
        sprintf(buffer, "wolfSSL Leaving %s, return %d", msg, ret);
        wolfssl_log(LEAVE_LOG , buffer);
    }
}


/*
 * When using OPENSSL_EXTRA or DEBUG_WOLFSSL_VERBOSE macro then WOLFSSL_ERROR is
 * mapped to new funtion WOLFSSL_ERROR_LINE which gets the line # and function
 * name where WOLFSSL_ERROR is called at.
 */
#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
void WOLFSSL_ERROR_LINE(int error, const char* func, unsigned int line,
            const char* file, void* usrCtx)
#else
void WOLFSSL_ERROR(int error)
#endif
{
    if (loggingEnabled) {
        char buffer[80];
        #if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
            (void)usrCtx; /* a user ctx for future flexibility */
            (void)func;
            if (error < 0) error = error - (2*error); /* get absolute value */
            wc_last_error      = (unsigned long)error;
            wc_last_error_line = (unsigned long)line;
            XMEMSET((char*)wc_last_error_file, 0, sizeof(file));
            if (XSTRLEN(file) < sizeof(file)) {
	            XSTRNCPY((char*)wc_last_error_file, file, XSTRLEN(file));
            }
            sprintf(buffer, "wolfSSL error occurred, error = %d line:%d file:%s",
                    error, line, file);
        #else
            sprintf(buffer, "wolfSSL error occurred, error = %d", error);
        #endif
        wolfssl_log(ERROR_LOG , buffer);
    }
}

#endif  /* DEBUG_WOLFSSL */

#ifdef USER_DEBUG_WOLFSSL
void USER_WOLFSSL_MSG(const char* msg)
{
#ifdef THREADX
            dc_log_printf("%s\n", msg);
#elif defined(MICRIUM)
        #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
            NetSecure_TraceOut((CPU_CHAR *)msg);
        #endif
#elif defined(WOLFSSL_MDK_ARM)
            fflush(stdout) ;
            printf("%s\n", msg);
            fflush(stdout) ;
#elif defined(WOLFSSL_LOG_PRINTF)
            printf("%s\n", msg);
#else
            fprintf(stderr, "%s\n", msg);
#endif
}

void USER_WOLFSSL_ERROR(int error)
{
    char buffer[80];
    sprintf(buffer, "wolfSSL error occurred, error = %d", error);
    USER_WOLFSSL_MSG(buffer);
}

#endif /* USER_DEBUG_WOLFSSL */