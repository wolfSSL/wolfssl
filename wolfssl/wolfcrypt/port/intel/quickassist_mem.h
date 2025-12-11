/* quickassist_mem.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _QUICKASSIST_MEM_H_
#define _QUICKASSIST_MEM_H_

#ifdef HAVE_INTEL_QA

#include <wolfssl/wolfcrypt/port/intel/quickassist.h>

CpaStatus qaeMemInit(void);
void qaeMemDestroy(void);

#ifndef QAT_V2
    #define QAE_PHYS_ADDR  CpaPhysicalAddr
    WOLFSSL_LOCAL QAE_PHYS_ADDR qaeVirtToPhysNUMA(void* pVirtAddress);
#endif


#ifdef WOLFSSL_TRACK_MEMORY
    WOLFSSL_API int InitMemoryTracker(void);
    WOLFSSL_API void ShowMemoryTracker(void);
#endif


WOLFSSL_API void* IntelQaMalloc(size_t size, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
);

WOLFSSL_API void IntelQaFree(void *ptr, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
);

WOLFSSL_API void* IntelQaRealloc(void *ptr, size_t size, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
);

#endif /* HAVE_INTEL_QA */

#endif /* _QUICKASSIST_MEM_H_ */
