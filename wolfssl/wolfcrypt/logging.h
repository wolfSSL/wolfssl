/* logging.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* submitted by eof */


#ifndef WOLFSSL_LOGGING_H
#define WOLFSSL_LOGGING_H

/* for reverse compatibility @wc_fips */
#ifndef HAVE_FIPS
    #include <wolfssl/wolfcrypt/types.h>
	#define CYASSL_LEAVE WOLFSSL_LEAVE
	#define CYASSL_ERROR WOLFSSL_ERROR
	#define CYASSL_ENTER WOLFSSL_ENTER
	#define CYASSL_MSG   WOLFSSL_MSG

    /* check old macros possibly declared */
	#if defined(CYASSL_DEBUG) && !defined(DEBUG_WOLFSSL)
        #define DEBUG_WOLFSSL
    #endif

	#ifdef __cplusplus
	    extern "C" {
	#endif
	
	
	enum  CYA_Log_Levels {
	    ERROR_LOG = 0,
	    INFO_LOG,
	    ENTER_LOG,
	    LEAVE_LOG,
	    OTHER_LOG
	};
	
	typedef void (*wolfSSL_Logging_cb)(const int logLevel,
	                                  const char *const logMessage);
	
	WOLFSSL_API int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);
	
	#ifdef DEBUG_WOLFSSL
	
	    void WOLFSSL_ENTER(const char* msg);
	    void WOLFSSL_LEAVE(const char* msg, int ret);
	
	    void WOLFSSL_ERROR(int);
	    void WOLFSSL_MSG(const char* msg);
	
	#else /* DEBUG_WOLFSSL   */
	
	    #define WOLFSSL_ENTER(m)
	    #define WOLFSSL_LEAVE(m, r)
	
	    #define WOLFSSL_ERROR(e)
	    #define WOLFSSL_MSG(m)
	
	#endif /* DEBUG_WOLFSSL  */
	
	#ifdef __cplusplus
	}
	#endif
#else /* if using fips use old logging file */
    #include <cyassl/ctaocrypt/logging.h>
	#define WOLFSSL_LEAVE CYASSL_LEAVE 
	#define WOLFSSL_ERROR CYASSL_ERROR 
	#define WOLFSSL_ENTER CYASSL_ENTER 
	#define WOLFSSL_MSG   CYASSL_MSG
#endif
#endif /* WOLFSSL_MEMORY_H */

