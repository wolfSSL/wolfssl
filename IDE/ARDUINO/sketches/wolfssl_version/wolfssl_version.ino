/* wolfssl_server.ino
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <Arduino.h>

 /* wolfSSL user_settings.h must be included from settings.h
  * Make all configurations changes in user_settings.h
  * Do not edit wolfSSL `settings.h` or `config.h` files.
  * Do not explicitly include user_settings.h in any source code.
  * Each Arduino sketch that uses wolfSSL must have: #include "wolfssl.h"
  * C/C++ source files can use: #include <wolfssl/wolfcrypt/settings.h>
  * The wolfSSL "settings.h" must be included in each source file using wolfSSL.
  * The wolfSSL "settings.h" must appear before any other wolfSSL include.
  */
#include <wolfssl.h>
#include <wolfssl/version.h>

/* Choose a monitor serial baud rate: 9600, 14400, 19200, 57600, 74880, etc. */
#define SERIAL_BAUD 115200

/* Arduino setup */
void setup() {
    Serial.begin(SERIAL_BAUD);
    while (!Serial) {
        /* wait for serial port to connect. Needed for native USB port only */
    }
    Serial.println(F(""));
    Serial.println(F(""));
    Serial.println(F("wolfSSL setup complete!"));
}

/* Arduino main application loop. */
void loop() {
    Serial.print("wolfSSL Version: ");
    Serial.println(LIBWOLFSSL_VERSION_STRING);
    delay(60000);
}
