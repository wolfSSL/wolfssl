/* user_settings.h
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

/* Minimal multi-threaded settings. run.sh selects the RTOS with
 * -DWOLFSSL_CMSIS_RTOS or -DWOLFSSL_CMSIS_RTOSv2. WOLFSSL_MDK_ARM is
 * intentionally not defined: this is a GCC CMSIS-RTOS build. */
#ifndef WOLFSSL_CMSIS_RTOS_REPRO_USER_SETTINGS_H
#define WOLFSSL_CMSIS_RTOS_REPRO_USER_SETTINGS_H

#define NO_FILESYSTEM
#define WOLFSSL_NO_SOCK
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Intentionally NOT defined: SINGLE_THREADED, WOLFSSL_MDK_ARM */

#endif
