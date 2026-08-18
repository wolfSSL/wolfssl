/* caam_linux.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Types and macros the CAAM driver core expects from its environment, for a
 * Linux userspace host. Mirrors caam_qnx.h; see caam_linux.c for the port
 * layer itself. */

#ifndef CAAM_LINUX_H
#define CAAM_LINUX_H

#include <stdint.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>

#define CAAM_MUTEX pthread_mutex_t
#define CAAM_INIT_MUTEX(x) pthread_mutex_init((x), NULL)
#define CAAM_FREE_MUTEX(x) pthread_mutex_destroy((x))
#define CAAM_LOCK_MUTEX(x) pthread_mutex_lock((x))
#define CAAM_UNLOCK_MUTEX(x) pthread_mutex_unlock((x))

#define Error int
#define Value int
#define Boolean int
#define CAAM_ADDRESS uintptr_t
#define Success 1
#define Failure 0
#define INTERRUPT_Panic() do {} while (0)
#define MemoryMapMayNotBeEmpty -1
#define CAAM_WAITING -2
#define NoActivityReady -1
#define MemoryOperationNotPerformed -1
#define CAAM_ARGS_E -3

#ifndef WOLFSSL_CAAM_BUFFER
#define WOLFSSL_CAAM_BUFFER
    typedef struct CAAM_BUFFER {
        int BufferType;
        CAAM_ADDRESS TheAddress;
        int Length;
    } CAAM_BUFFER;
#endif

/* Physical base of the CCSR window and the SEC block inside it. These parts
 * have a 36-bit physical address space, so the value does not fit the 32-bit
 * CAAM_ADDRESS the driver uses for virtual addresses; it is only ever used as
 * an mmap offset inside caam_linux.c. */
#ifndef CAAM_LINUX_CCSR_PHYS
    #define CAAM_LINUX_CCSR_PHYS 0xFFE000000ULL
#endif
#ifndef CAAM_LINUX_SEC_OFFSET
    #define CAAM_LINUX_SEC_OFFSET 0x300000ULL
#endif
#ifndef CAAM_LINUX_SEC_SIZE
    #define CAAM_LINUX_SEC_SIZE 0x10000
#endif

/* Which job ring to claim, as an offset from the SEC base. Ring N sits at
 * (N + 1) * 0x1000. */
#ifndef CAAM_LINUX_JR_OFFSET
    #define CAAM_LINUX_JR_OFFSET 0x1000
#endif

/* Reserved physical DMA pool.
 *
 * The engine cannot use ordinary user pages: they are not physically
 * contiguous and, on a part with more than 4 GB, sit above what a 32-bit
 * descriptor pointer can reach. Boot Linux with mem= so it stops managing the
 * top of DDR and carve engine buffers out of that reserved range instead. */
#ifndef CAAM_LINUX_POOL_PHYS
    #define CAAM_LINUX_POOL_PHYS 0x80000000ULL
#endif
#ifndef CAAM_LINUX_POOL_SZ
    #define CAAM_LINUX_POOL_SZ (256 * 1024)
#endif

#ifndef CAAM_LINUX_MEM_DEV
    #define CAAM_LINUX_MEM_DEV "/dev/mem"
#endif

/* Yield to other threads while polling for job completion. */
#define CAAM_CPU_CHILL() sched_yield()

#endif /* CAAM_LINUX_H */
