/* wolfssl-arduino.cpp
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

#include <Arduino.h>
#include "wolfssl.h"

/* Function to allow wolfcrypt to use Arduino Serial.print for debug messages.
 * See wolfssl/wolfcrypt/logging.c */

#if defined(__AVR__)
#include <avr/pgmspace.h>  /* Required for PROGMEM handling on AVR */
#endif

int wolfSSL_Arduino_Serial_Print(const char* const s)
{
    /* Reminder: Serial.print is only available in C++ */
    int is_progmem = 0;

#if defined(__AVR__)
    const char* t;
    t = s;

    /* Safely check if `s` is in PROGMEM, 0x8000 is typical for AVR flash */
    if (reinterpret_cast<uint16_t>(t) >= 0x8000) {
        while (pgm_read_byte(t)) {
            Serial.write(pgm_read_byte(t++));
        }
        Serial.println();
        is_progmem = 1;
    }
#endif

    /* Print normally for non-AVR boards or RAM-stored strings */
    if (!is_progmem) {
        Serial.println(s);
    }

    return 0;
};
