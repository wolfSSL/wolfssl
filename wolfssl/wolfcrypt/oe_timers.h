/* oe_timers.h
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

/*

DESCRIPTION
Operational-environment timer facilities.  Both this header and its
implementation, wolfcrypt/src/oe_timers.c, sit OUTSIDE the FIPS module
boundary: src/include.am lists oe_timers.c after wolfcrypt_last.c, so its .text
falls beyond wolfCrypt_FIPS_last() and the in-core integrity hash does not
cover it.

They are kept in their own files, named for the operational environment rather
than for any one consumer, so that the module's own headers declare nothing
that lives outside the module.  A new platform is supported by adding an arm to
oe_timers.c; no byte inside the boundary changes.

*/

#ifndef WOLF_CRYPT_OE_TIMERS_H
#define WOLF_CRYPT_OE_TIMERS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_ENTROPY_MEMUSE

#ifdef __cplusplus
    extern "C" {
#endif

/* Read the operational environment's high resolution counter.
 *
 * Resolved at link time: exactly one definition per build, selected by the
 * build-time ladder in oe_timers.c.  There is no runtime selection and no
 * function pointer.
 *
 * @return  64-bit counter value.
 */
WOLFSSL_LOCAL word64 wc_OE_TimeHiRes(void);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* HAVE_ENTROPY_MEMUSE */

#endif /* WOLF_CRYPT_OE_TIMERS_H */
