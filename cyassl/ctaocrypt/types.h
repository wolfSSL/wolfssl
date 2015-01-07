/* types.h
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


#ifndef CTAO_CRYPT_TYPES_H
#define CTAO_CRYPT_TYPES_H

#include <cyassl/ctaocrypt/wc_port.h>
#include <cyassl/ctaocrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

/* compatibility macros */
#define CYASSL_WORD_SIZE    WOLFSSL_WORD_SIZE
#define CYASSL_BIT_SIZE     WOLFSSL_BIT_SIZE
#define CYASSL_MAX_16BIT    WOLFSSL_MAX_16BIT
#define CYASSL_MAX_ERROR_SZ WOLFSSL_MAX_ERROR_SZ
#define cyassl_word wolfssl_word

/* if macros need to be reverted back to previous name for fips */
//    #define WOLFSSL_MAX_ERROR_SZ CYASSL_MAX_ERROR_SZ
//
//    #define WOLFSSL_WORD_SIZE    CYASSL_WORD_SIZE
//    #define WOLFSSL_BIT_SIZE     CYASSL_BIT_SIZE
//    #define WOLFSSL_MAX_16BIT    CYASSL_MAX_16BIT
//    #define WOLFSSL_MAX_ERROR_SZ CYASSL_MAX_ERROR_SZ
//    #define wolfssl_word cyassl_word
///* memory macros */
//    /* when using fips map wolfSSL to CyaSSL*/
//    #define wolfSSL_Malloc_cb     CyaSSL_Malloc_cb
//    #define wolfSSL_Free_cb       CyaSSL_Free_cb
//    #define wolfSSL_Realloc_cb    CyaSSL_Realloc_cb
//    #define wolfSSL_SetAllocators CyaSSL_SetAllocators
//
//    /* Public in case user app wants to use XMALLOC/XFREE */
//	#define wolfSSL_Malloc  CyaSSL_Malloc
//	#define wolfSSL_Free    CyaSSL_Free
//	#define wolfSSL_Realloc CyaSSL_Realloc

#endif /* CTAO_CRYPT_TYPES_H */

