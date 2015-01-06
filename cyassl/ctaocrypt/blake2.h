/* blake2.h
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


#ifdef HAVE_BLAKE2

#ifndef CTAOCRYPT_BLAKE2_H
#define CTAOCRYPT_BLAKE2_H

#include <wolfssl/wolfcrypt/blake2.h>

/* for blake2 reverse compatibility */
#ifndef HAVE_FIPS
    #define InitBlake2b   wc_InitBlake2b
    #define Blake2bUpdate wc_Blake2bUpdate
    #define Blake2bFinal  wc_Blake2bFinal
#endif

#endif  /* CTAOCRYPT_BLAKE2_H */
#endif  /* HAVE_BLAKE2 */

