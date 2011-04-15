/* logging.c
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
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

#include "os_settings.h"
#include "logging.h"


/* Set these to default values initially. */
static CyaSSL_Logging_cb log_function = 0;
static int loggingEnabled = 0;


int CyaSSL_SetLoggingCb(CyaSSL_Logging_cb f)
{
    int res = 0;

    if (f)
        log_function = f;
    else
        res = -1;

    return res;
}


int CyaSSL_Debugging_ON(void)
{
#ifdef DEBUG_CYASSL
    loggingEnabled = 1;
    return 0;
#else
    return -1;  /* not compiled in */
#endif
}


void CyaSSL_Debugging_OFF(void)
{
    loggingEnabled = 0;
}


#ifdef DEBUG_CYASSL

#include <stdio.h>   /* for default printf stuff */

#ifdef THREADX
    int dc_log_printf(char*, ...);
#endif

static void log(const int logLevel, const char *const logMessage)
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
#else
            fprintf(stderr, "%s\n", logMessage);
#endif
        }
    }
}


void CYASSL_MSG(const char* msg)
{
    log(INFO_LOG , msg);
}


void CYASSL_ENTER(const char* msg)
{
    if (loggingEnabled) {
        char buffer[80];
        sprintf(buffer, "CyaSSL Entering %s", msg);
        log(ENTER_LOG , buffer);
    }
}


void CYASSL_LEAVE(const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[80];
        sprintf(buffer, "CyaSSL Leaving %s, return %d", msg, ret);
        log(LEAVE_LOG , buffer);
    }
}


void CYASSL_ERROR(int error)
{
    if (loggingEnabled) {
        char buffer[80];
        sprintf(buffer, "CyaSSL error occured, error = %d", error);
        log(ERROR_LOG , buffer);
    }
}

#endif  /* DEBUG_CYASSL */ 
