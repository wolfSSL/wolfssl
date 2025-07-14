/* wolfssl.h
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

/* Edit with caution. This is an Arduino-library specific header for wolfSSL */

#ifndef WOLFSSL_USER_SETTINGS
    /* Should already be defined in settings.h for #if defined(ARDUINO) */
    #define WOLFSSL_USER_SETTINGS
#endif

#include <Arduino.h>

/* wolfSSL user_settings.h must be included from settings.h
 * Make all configurations changes in user_settings.h
 * Do not edit wolfSSL `settings.h` or `config.h` files.
 * Do not explicitly include user_settings.h in any source code.
 * Each Arduino sketch that uses wolfSSL must have: #include "wolfssl.h"
 * C/C++ source files can use: #include <wolfssl/wolfcrypt/settings.h>
 * The wolfSSL "settings.h" must be included in each source file using wolfSSL.
 * The wolfSSL "settings.h" must be listed before any other wolfSSL include.
 */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#ifndef WOLFSSL_ARDUINO_H
#define WOLFSSL_ARDUINO_H

/* Declare a helper function to be used in wolfssl/wolfcrypt/logging.c */
int wolfSSL_Arduino_Serial_Print(const char* const s);

#endif /* WOLFSSL_ARDUINO_H */
