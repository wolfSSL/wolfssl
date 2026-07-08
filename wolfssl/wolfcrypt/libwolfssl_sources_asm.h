/* libwolfssl_sources_asm.h
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

/* In wolfSSL library sources, #include this file before any other #includes, to
 * assure BUILDING_WOLFSSL is defined.
 *
 * This file also includes the common headers needed by all sources.
 */

#ifndef LIBWOLFSSL_SOURCES_ASM_H
#define LIBWOLFSSL_SOURCES_ASM_H

#if defined(TEST_LIBWOLFSSL_SOURCES_INCLUSION_SEQUENCE) && \
    defined(WOLF_CRYPT_SETTINGS_H) &&                      \
    !defined(LIBWOLFSSL_SOURCES_H)
    #error settings.h included before libwolfssl_sources_asm.h.
#endif

#ifndef BUILDING_WOLFSSL
    #define BUILDING_WOLFSSL
#endif

#if defined(HAVE_CONFIG_H) && !defined(WC_CONFIG_H_INCLUDED)
    #include <config.h>
    #define WC_CONFIG_H_INCLUDED
#endif

/* Generated assembly is guarded by the same feature macros as the C sources
 * (e.g. WOLFSSL_SHA512).  In an autoconf build those macros are not in config.h
 * - they live in wolfssl/options.h - so pull them in here, before settings.h,
 * so the assembler sees the same configuration as the compiler.  This is a
 * custom configuration method (options.h consumed directly), so tell settings.h
 * not to warn about options.h in a library object. */
#if defined(HAVE_CONFIG_H) && !defined(WOLFSSL_USER_SETTINGS)
    #ifndef WOLFSSL_CUSTOM_CONFIG
        #define WOLFSSL_CUSTOM_CONFIG
    #endif
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#endif /* LIBWOLFSSL_SOURCES_ASM_H */
