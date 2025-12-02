/* bsdkm_wc_port.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* included by wolfssl/wolfcrypt/wc_port.h */

#ifndef BSDKM_WC_PORT_H
#define BSDKM_WC_PORT_H

#ifdef WOLFSSL_BSDKM

#include <sys/ctype.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#if !defined(SINGLE_THREADED)
    #include <sys/mutex.h>
#endif /* !SINGLE_THREADED */
#ifndef CHAR_BIT
    #include <sys/limits.h>
#endif /* !CHAR_BIT*/

/* needed to prevent wolfcrypt/src/asn.c version shadowing
 * extern global version from /usr/src/sys/sys/systm.h */
#define version wc_version

#define wc_km_printf printf

/* str and char utility functions */
#define XATOI(s) ({                                         \
      char * endptr = NULL;                                 \
      long   _xatoi_ret = strtol(s, &endptr, 10);           \
      if ((s) == endptr || *endptr != '\0') {               \
        _xatoi_ret = 0;                                     \
      }                                                     \
      (int)_xatoi_ret;                                      \
    })

#if !defined(XMALLOC_OVERRIDE)
    #error bsdkm requires XMALLOC_OVERRIDE
#endif /* !XMALLOC_OVERRIDE */

/* use malloc and free from /usr/include/sys/malloc.h */
extern struct malloc_type M_WOLFSSL[1];

#define XMALLOC(s, h, t) \
    ({(void)(h); (void)(t); malloc(s, M_WOLFSSL, M_WAITOK | M_ZERO);})

#ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
    #define XFREE(p, h, t) \
        ({(void)(h); (void)(t); free(p, M_WOLFSSL);})
#else
    #define XFREE(p, h, t) \
        ({void* _xp; (void)(h); (void)(t); _xp = (p); \
         if(_xp) free(_xp, M_WOLFSSL);})
#endif

#if !defined(SINGLE_THREADED)
    #define WC_MUTEX_OPS_INLINE

    typedef struct wolfSSL_Mutex {
        struct mtx lock;
    } wolfSSL_Mutex;

    static __always_inline int wc_InitMutex(wolfSSL_Mutex * m)
    {
        mtx_init(&m->lock, "wolfssl spinlock", NULL, MTX_SPIN);
        return 0;
    }

    static __always_inline int wc_FreeMutex(wolfSSL_Mutex * m)
    {
        mtx_destroy(&m->lock);
        return 0;
    }

    static __always_inline int wc_LockMutex(wolfSSL_Mutex *m)
    {
        mtx_lock_spin(&m->lock);
        return 0;
    }

    static __always_inline int wc_UnLockMutex(wolfSSL_Mutex* m)
    {
        mtx_unlock_spin(&m->lock);
        return 0;
    }
#endif /* !SINGLE_THREADED */

#if defined(WOLFSSL_HAVE_ATOMIC_H) && !defined(WOLFSSL_NO_ATOMICS)
    #include <machine/atomic.h>
    typedef volatile int wolfSSL_Atomic_Int;
    typedef volatile unsigned int wolfSSL_Atomic_Uint;
    #define WOLFSSL_ATOMIC_INITIALIZER(x) (x)
    #define WOLFSSL_ATOMIC_LOAD(x)  (int)atomic_load_acq_int(&(x))
    #define WOLFSSL_ATOMIC_STORE(x, v)  atomic_store_rel_int(&(x), (v))
    #define WOLFSSL_ATOMIC_OPS
#endif /* WOLFSSL_HAVE_ATOMIC_H && !WOLFSSL_NO_ATOMICS */

#endif /* WOLFSSL_BSDKM */
#endif /* BSDKM_WC_PORT_H */
