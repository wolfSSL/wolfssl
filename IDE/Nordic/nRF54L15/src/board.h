/* board.h
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

#ifndef BOARD_H
#define BOARD_H

#include <stdint.h>

void     board_init(void);
uint32_t board_cycles(void);
uint32_t board_clock_hz(void);
/* One line with the state of the cycle counter and the debug signals. */
void     board_debug_report(void);

/* TAMPC: stop the automatic chip reset on an internal tamper event, and read
 * the tamper status (STATUS, EVENTS_TAMPER, PROTECT.CRACENTAMP.STATUS). */
void     board_tamper_reset_disable(void);
uint32_t board_tamper_status(uint32_t* events, uint32_t* cracenTamp);

#endif /* BOARD_H */
