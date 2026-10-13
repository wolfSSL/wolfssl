/* rng_driver.h
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

#ifndef RNG_DRIVER_H
#define RNG_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

/* TrngBase: mapped from the "inside-secure,safexcel-eip76" rng device tree node
 * CpAceBase: mapped from the "ti,am64-sa2ul" sa2ul device tree node
 * Must be called before rng_driver_init()/rng_driver_read(). */
void rng_driver_set_base(volatile void *TrngBase, volatile void *CpAceBase);

/* Returns 0 on success */
int rng_driver_init(void);

/* Returns 0 on success, -1 on failure (base not set or timeout) */
int rng_driver_read(unsigned char* output, unsigned int sz);

#ifdef __cplusplus
}
#endif

#endif /* RNG_DRIVER_H */
