/* visibility.h
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

/* Visibility control macros */

#ifndef CTAO_CRYPT_VISIBILITY_H
#define CTAO_CRYPT_VISIBILITY_H

#include <wolfssl/wolfcrypt/visibility.h>
/* fips compatibility @wc_fips */
//#ifdef HAVE_FIPS
//    #define WOLFSSL_API   CYASSL_API
//	#define WOLFSSL_LOCAL CYASSL_LOCAL
//#else
    #define CYASSL_API   WOLFSSL_API
	#define CYASSL_LOCAL WOLFSSL_LOCAL
//#endif /* HAVE_FIPS */
#endif /* CTAO_CRYPT_VISIBILITY_H */

