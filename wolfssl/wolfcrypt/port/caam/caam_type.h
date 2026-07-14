/* caam_type.h
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

/* Single definition of CAAM_ADDRESS, the type used to hold an address handed to
 * or returned from the CAAM.
 *
 * struct ecc_key stores CAAM addresses, so its layout depends on this type.
 * Keep the definition here, selected only from build configuration macros, so
 * that every translation unit in a build agrees on it no matter which of the
 * CAAM headers it happens to include, and in which order.
 *
 * This header intentionally has no wolfSSL dependencies; the standalone QNX
 * driver build includes it without settings.h. Whatever includes it is expected
 * to have already pulled in settings.h if it needs the configuration macros.
 */

#ifndef WOLF_CRYPT_CAAM_TYPE_H
#define WOLF_CRYPT_CAAM_TYPE_H

#include <stdint.h>

#ifndef CAAM_ADDRESS
    #ifdef WOLFSSL_SECO_CAAM
        #define CAAM_ADDRESS intptr_t
    #else
        #define CAAM_ADDRESS uintptr_t
    #endif
#endif

#endif /* WOLF_CRYPT_CAAM_TYPE_H */
