/* wolfssl_library.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


/* This is a sample include directory library using wolfSSL.
 *
 * Do not explicitly include wolfSSL user_settings.h here.
 *
 * Be sure to include these files in all libraries that reference
 * wolfssl in this order: */

#include <Arduino.h>
#include "wolfssl.h"

 #ifndef _WOLFSSL_LIBRARY_H_
 #define _WOLFSSL_LIBRARY_H_

#ifdef __cplusplus
extern "C" {
#endif

int wolfssl_library_sample();

#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSL_LIBRARY_H_ */
