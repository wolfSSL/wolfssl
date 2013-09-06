/* port.c
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

#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ctaocrypt/types.h>
#include <cyassl/ctaocrypt/error.h>


#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif



#ifdef SINGLE_THREADED

int InitMutex(CyaSSL_Mutex* m)
{
    (void)m;
    return 0;
}


int FreeMutex(CyaSSL_Mutex *m)
{
    (void)m;
    return 0;
}


int LockMutex(CyaSSL_Mutex *m)
{
    (void)m;
    return 0;
}


int UnLockMutex(CyaSSL_Mutex *m)
{
    (void)m;
    return 0;
}

#else /* MULTI_THREAD */

    #if defined(FREERTOS)

        int InitMutex(CyaSSL_Mutex* m)
        {
            int iReturn;

            *m = ( CyaSSL_Mutex ) xSemaphoreCreateMutex();
            if( *m != NULL )
                iReturn = 0;
            else
                iReturn = BAD_MUTEX_E;

            return iReturn;
        }

        int FreeMutex(CyaSSL_Mutex* m)
        {
            vSemaphoreDelete( *m );
            return 0;
        }

        int LockMutex(CyaSSL_Mutex* m)
        {
            /* Assume an infinite block, or should there be zero block? */
            xSemaphoreTake( *m, portMAX_DELAY );
            return 0;
        }

        int UnLockMutex(CyaSSL_Mutex* m)
        {
            xSemaphoreGive( *m );
            return 0;
        }

    #elif defined(CYASSL_SAFERTOS)

        int InitMutex(CyaSSL_Mutex* m)
        {
            vSemaphoreCreateBinary(m->mutexBuffer, m->mutex);
            if (m->mutex == NULL)
                return BAD_MUTEX_E;

            return 0;
        }

        int FreeMutex(CyaSSL_Mutex* m)
        {
            (void)m;
            return 0;
        }

        int LockMutex(CyaSSL_Mutex* m)
        {
            /* Assume an infinite block */
            xSemaphoreTake(m->mutex, portMAX_DELAY);
            return 0;
        }

        int UnLockMutex(CyaSSL_Mutex* m)
        {
            xSemaphoreGive(m->mutex);
            return 0;
        }


    #elif defined(USE_WINDOWS_API)

        int InitMutex(CyaSSL_Mutex* m)
        {
            InitializeCriticalSection(m);
            return 0;
        }


        int FreeMutex(CyaSSL_Mutex* m)
        {
            DeleteCriticalSection(m);
            return 0;
        }


        int LockMutex(CyaSSL_Mutex* m)
        {
            EnterCriticalSection(m);
            return 0;
        }


        int UnLockMutex(CyaSSL_Mutex* m)
        {
            LeaveCriticalSection(m);
            return 0;
        }

    #elif defined(CYASSL_PTHREADS)

        int InitMutex(CyaSSL_Mutex* m)
        {
            if (pthread_mutex_init(m, 0) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }


        int FreeMutex(CyaSSL_Mutex* m)
        {
            if (pthread_mutex_destroy(m) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }


        int LockMutex(CyaSSL_Mutex* m)
        {
            if (pthread_mutex_lock(m) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }


        int UnLockMutex(CyaSSL_Mutex* m)
        {
            if (pthread_mutex_unlock(m) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }

    #elif defined(THREADX)

        int InitMutex(CyaSSL_Mutex* m)
        {
            if (tx_mutex_create(m, "CyaSSL Mutex", TX_NO_INHERIT) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }


        int FreeMutex(CyaSSL_Mutex* m)
        {
            if (tx_mutex_delete(m) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }


        int LockMutex(CyaSSL_Mutex* m)
        {
            if (tx_mutex_get(m, TX_WAIT_FOREVER) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }


        int UnLockMutex(CyaSSL_Mutex* m)
        {
            if (tx_mutex_put(m) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }

    #elif defined(MICRIUM)

        int InitMutex(CyaSSL_Mutex* m)
        {
            #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
                if (NetSecure_OS_MutexCreate(m) == 0)
                    return 0;
                else
                    return BAD_MUTEX_E;
            #else
                return 0;
            #endif
        }


        int FreeMutex(CyaSSL_Mutex* m)
        {
            #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
                if (NetSecure_OS_FreeMutex(m) == 0)
                    return 0;
                else
                    return BAD_MUTEX_E;
            #else
                return 0;
            #endif
        }


        int LockMutex(CyaSSL_Mutex* m)
        {
            #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
                if (NetSecure_OS_LockMutex(m) == 0)
                    return 0;
                else
                    return BAD_MUTEX_E;
            #else
                return 0;
            #endif
        }


        int UnLockMutex(CyaSSL_Mutex* m)
        {
            #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
                if (NetSecure_OS_UnLockMutex(m) == 0)
                    return 0;
                else
                    return BAD_MUTEX_E;
            #else
                return 0;
            #endif

        }

    #elif defined(EBSNET)

        int InitMutex(CyaSSL_Mutex* m)
        {
            if (rtp_sig_mutex_alloc(m, "CyaSSL Mutex") == -1)
                return BAD_MUTEX_E;
            else
                return 0;
        }

        int FreeMutex(CyaSSL_Mutex* m)
        {
            rtp_sig_mutex_free(*m);
            return 0;
        }

        int LockMutex(CyaSSL_Mutex* m)
        {
            if (rtp_sig_mutex_claim_timed(*m, RTIP_INF) == 0)
                return 0;
            else
                return BAD_MUTEX_E;
        }

        int UnLockMutex(CyaSSL_Mutex* m)
        {
            rtp_sig_mutex_release(*m);
            return 0;
        }

    #elif defined(FREESCALE_MQX)

        int InitMutex(CyaSSL_Mutex* m)
        {
            if (_mutex_init(m, NULL) == MQX_EOK)
                return 0;
            else
                return BAD_MUTEX_E;
        }

        int FreeMutex(CyaSSL_Mutex* m)
        {
            if (_mutex_destroy(m) == MQX_EOK)
                return 0;
            else
                return BAD_MUTEX_E;
        }

        int LockMutex(CyaSSL_Mutex* m)
        {
            if (_mutex_lock(m) == MQX_EOK)
                return 0;
            else
                return BAD_MUTEX_E;
        }

        int UnLockMutex(CyaSSL_Mutex* m)
        {
            if (_mutex_unlock(m) == MQX_EOK)
                return 0;
            else
                return BAD_MUTEX_E;
        }
        
    #elif defined(CYASSL_MDK_ARM)

        int InitMutex(CyaSSL_Mutex* m)
        {
            os_mut_init (m); 
            return 0;
        }

        int FreeMutex(CyaSSL_Mutex* m)
        {
            return(0) ;
        }

        int LockMutex(CyaSSL_Mutex* m)
        {
            os_mut_wait (m, 0xffff);
            return(0) ;
        }

        int UnLockMutex(CyaSSL_Mutex* m)
        {
            os_mut_release (m);
            return 0;
        }
    #endif /* USE_WINDOWS_API */
#endif /* SINGLE_THREADED */

