/* visibility.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Visibility control macros */

#if !defined(WOLF_CRYPT_VISIBILITY_H && CTAO_CRYPT_VISIBILITY_H)
#define WOLF_CRYPT_VISIBILITY_H


/* CYASSL_API is used for the public API symbols.
        It either imports or exports (or does nothing for static builds)

   CYASSL_LOCAL is used for non-API symbols (private).
*/
#define BUILDING_WOLFSSL BUILDING_CYASSL
#if defined(BUILDING_WOLFSSL)
    #if defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFSSL_API   __attribute__ ((visibility("default")))
        #define CYASSL_API WOLFSSL_API
        #define WOLFSSL_LOCAL __attribute__ ((visibility("hidden")))
        #define CYASSL_LOCAL WOLFSSL_LOCAL
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFSSL_API   __global
        #define CYASSL_API WOLFSSL_API
        #define WOLFSSL_LOCAL __hidden
        #define CYASSL_LOCAL WOLFSSL_LOCAL
    #elif defined(_MSC_VER)
        #define CYASSL_DLL WOLFSSL_DLL
        #ifdef WOLFSSL_DLL
            #define WOLFSSL_API extern __declspec(dllexport)
            #define CYASSL_API WOLFSSL_API
        #else
            //#define CYASSL_API
            #define WOLFSSL_API
            #define CYASSL_API WOLFSSL_API
        #endif
        #define WOLFSSL_LOCAL
        #define CYASSL_LOCAL WOLFSSL_LOCAL
    #else
        #define WOLFSSL_API
        #define CYASSL_API WOLFSSL_API
        #define WOLFSSL_LOCAL
        #define CYASSL_LOCAL WOLFSSL_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* BUILDING_CYASSL */
    #if defined(_MSC_VER)
        #define CYASSL_DLL WOLFSSL_DLL
        #ifdef WOLFSSL_DLL
            #define WOLFSSL_API extern __declspec(dllimport)
            #define CYASSL_API WOLFSSL_API
        #else
            #define WOLFSSL_API
            #define CYASSL_API WOLFSSL_API
        #endif
        #define WOLFSSL_LOCAL
        #define CYASSL_LOCAL WOLFSSL_LOCAL
    #else
        #define WOLFSSL_API
        #define CYASSL_API WOLFSSL_API
        #define WOLFSSL_LOCAL
        #define CYASSL_LOCAL WOLFSSL_LOCAL
    #endif
#endif /* BUILDING_WOLFSSL */


#endif /* WOLF_CRYPT_VISIBILITY_H */

