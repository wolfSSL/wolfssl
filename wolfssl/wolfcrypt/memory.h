/* memory.h
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


#ifndef WOLFSSL_MEMORY_H
#define WOLFSSL_MEMORY_H

#include <stdlib.h>

/* compatibility and fips @wc_fips */
#ifndef HAVE_FIPS
    #include <wolfssl/wolfcrypt/types.h>
    #define CyaSSL_Malloc_cb     wolfSSL_Malloc_cb
    #define CyaSSL_Free_cb       wolfSSL_Free_cb
    #define CyaSSL_Realloc_cb    wolfSSL_Realloc_cb
    #define CyaSSL_SetAllocators wolfSSL_SetAllocators
    
    /* Public in case user app wants to use XMALLOC/XFREE */
	#define CyaSSL_Malloc  wolfSSL_Malloc
	#define CyaSSL_Free    wolfSSL_Free
	#define CyaSSL_Realloc wolfSSL_Realloc


	typedef void *(*wolfSSL_Malloc_cb)(size_t size);
	typedef void (*wolfSSL_Free_cb)(void *ptr);
	typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size);
	
	
	/* Public set function */
	WOLFSSL_API int wolfSSL_SetAllocators(wolfSSL_Malloc_cb  malloc_function,
	                                    wolfSSL_Free_cb    free_function,
	                                    wolfSSL_Realloc_cb realloc_function);
	
	/* Public in case user app wants to use XMALLOC/XFREE */
	WOLFSSL_API void* wolfSSL_Malloc(size_t size);
	WOLFSSL_API void  wolfSSL_Free(void *ptr);
	WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size);
#else
    #include <cyassl/ctaocrypt/memory.h>
    /* when using fips map wolfSSL to CyaSSL*/
    #define wolfSSL_Malloc_cb     CyaSSL_Malloc_cb
    #define wolfSSL_Free_cb       CyaSSL_Free_cb
    #define wolfSSL_Realloc_cb    CyaSSL_Realloc_cb
    #define wolfSSL_SetAllocators CyaSSL_SetAllocators
    
    /* Public in case user app wants to use XMALLOC/XFREE */
	#define wolfSSL_Malloc  CyaSSL_Malloc
	#define wolfSSL_Free    CyaSSL_Free
	#define wolfSSL_Realloc CyaSSL_Realloc
#endif

#endif /* WOLFSSL_MEMORY_H */

