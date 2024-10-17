/* time_helper.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* common Espressif time_helper v5.6.3.001 */

#ifndef _TIME_HELPER_H_
#define _TIME_HELPER_H_

/* ESP-IDF uses a 64-bit signed integer to represent time_t starting from
 * release v5.0 See: Espressif api-reference/system/system_time
 */

#ifdef __cplusplus
extern "C" {
#endif

/* a function to show the current data and time */
int esp_show_current_datetime(void);

/* worst case, if GitHub time not available, used fixed time */
int set_fixed_default_time(void);

/* set time from string (e.g. GitHub commit time) */
/* When not using the new esp-sdk-lib.h helpers: */
/* int set_time_from_string(char* time_buffer); */

/* set time from NTP servers,
 * also initially calls set_fixed_default_time or set_time_from_string */
int set_time(void);

/* wait NTP_RETRY_COUNT seconds before giving up on NTP time */
int set_time_wait_for_ntp(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef _TIME_HELPER_H */
