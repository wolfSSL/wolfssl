/* cryptocb_provider.h
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
 *
 * Public API header for the external crypto callback provider.
 * Only these 3 symbols are exported; all others are hidden.
 */

#ifndef CRYPTOCB_PROVIDER_H
#define CRYPTOCB_PROVIDER_H

/* Forward declaration - avoid including wolfSSL headers in public API */
struct wc_CryptoInfo;

/* Visibility macros for exported symbols */
#if defined(__GNUC__) && __GNUC__ >= 4
    #define CRYPTOCB_PROVIDER_API __attribute__((visibility("default")))
#else
    #define CRYPTOCB_PROVIDER_API
#endif

/**
 * The crypto callback function to register with wolfSSL.
 *
 * @param devId  Device ID passed to crypto operations
 * @param info   Crypto operation information structure
 * @param ctx    User context (unused by this provider)
 * @return 0 on success, CRYPTOCB_UNAVAILABLE if not supported,
 *         negative error code on failure
 */
CRYPTOCB_PROVIDER_API int external_provider_callback(
    int devId, struct wc_CryptoInfo* info, void* ctx);

#endif /* CRYPTOCB_PROVIDER_H */
