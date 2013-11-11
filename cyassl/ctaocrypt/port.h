/* port.h
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


#ifndef CTAO_CRYPT_PORT_H
#define CTAO_CRYPT_PORT_H


#ifdef __cplusplus
    extern "C" {
#endif


#ifdef USE_WINDOWS_API 
    #ifdef CYASSL_GAME_BUILD
        #include "system/xtl.h"
    #else
        #ifndef WIN32_LEAN_AND_MEAN
            #define WIN32_LEAN_AND_MEAN
        #endif
        #if defined(_WIN32_WCE) || defined(WIN32_LEAN_AND_MEAN)
            /* On WinCE winsock2.h must be included before windows.h */
            #include <winsock2.h>
        #endif
        #include <windows.h>
    #endif
#elif defined(THREADX)
    #ifndef SINGLE_THREADED
        #include "tx_api.h"
    #endif
#elif defined(MICRIUM)
    /* do nothing, just don't pick Unix */
#elif defined(FREERTOS) || defined(CYASSL_SAFERTOS)
    /* do nothing */
#elif defined(EBSNET)
    /* do nothing */
#elif defined(FREESCALE_MQX)
    /* do nothing */
#elif defined(CYASSL_MDK_ARM)
    #if defined(CYASSL_MDK5)
         #include "cmsis_os.h"
    #else
        #include <rtl.h>
    #endif
#else
    #ifndef SINGLE_THREADED
        #define CYASSL_PTHREADS
        #include <pthread.h>
    #endif
    #if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)
        #include <unistd.h>      /* for close of BIO */
    #endif
#endif


#ifdef SINGLE_THREADED
    typedef int CyaSSL_Mutex;
#else /* MULTI_THREADED */
    /* FREERTOS comes first to enable use of FreeRTOS Windows simulator only */
    #ifdef FREERTOS
        typedef xSemaphoreHandle CyaSSL_Mutex;
    #elif defined(CYASSL_SAFERTOS)
        typedef struct CyaSSL_Mutex {
            signed char mutexBuffer[portQUEUE_OVERHEAD_BYTES];
            xSemaphoreHandle mutex;
        } CyaSSL_Mutex;
    #elif defined(USE_WINDOWS_API)
        typedef CRITICAL_SECTION CyaSSL_Mutex;
    #elif defined(CYASSL_PTHREADS)
        typedef pthread_mutex_t CyaSSL_Mutex;
    #elif defined(THREADX)
        typedef TX_MUTEX CyaSSL_Mutex;
    #elif defined(MICRIUM)
        typedef OS_MUTEX CyaSSL_Mutex;
    #elif defined(EBSNET)
        typedef RTP_MUTEX CyaSSL_Mutex;
    #elif defined(FREESCALE_MQX)
        typedef MUTEX_STRUCT CyaSSL_Mutex;
    #elif defined(CYASSL_MDK_ARM)
        #if defined(CYASSL_CMSIS_RTOS)
            typedef osMutexId CyaSSL_Mutex;
        #else
            typedef OS_MUT CyaSSL_Mutex;
        #endif
    #else
        #error Need a mutex type in multithreaded mode
    #endif /* USE_WINDOWS_API */
#endif /* SINGLE_THREADED */

CYASSL_LOCAL int InitMutex(CyaSSL_Mutex*);
CYASSL_LOCAL int FreeMutex(CyaSSL_Mutex*);
CYASSL_LOCAL int LockMutex(CyaSSL_Mutex*);
CYASSL_LOCAL int UnLockMutex(CyaSSL_Mutex*);


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* CTAO_CRYPT_PORT_H */

