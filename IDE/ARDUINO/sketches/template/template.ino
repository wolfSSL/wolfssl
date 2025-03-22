/* template.ino
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

/* This is Arduino reference sketch example 2 of 2: multiple file .ino   */
/* See also template.ino project example using a single file project.    */

/* Do not insert attempts at appending wolfssl user_settings.h here.
 * All wolfssl settings needed by wolfSSL must be in the user_settings.h */
#include <wolfssl.h>

/* settings.h is included from Arduino `wolfssl.h`, but a good practice to
 * include before any other wolfssl headers. As a reminder here: */
#include <wolfssl/wolfcrypt/settings.h>

/* Include a simple wolfSSL header to this example: */
#include <wolfssl/version.h>

/* There's a wolfSSL_Arduino_Serial_Print() for logging messages in wolfssl. */
#include <wolfssl/wolfcrypt/logging.h>

/* Include files (.c, .cpp, .h) typically in the same directory as the sketch;
 * The wolfssl_helper is an example of this: */
#include "wolfssl_helper.h"

/* Arduino library header files are typically not in an `include` directory;
 * The wolfssl_library is an example of a library directory: */
#include "wolfssl_library/wolfssl_library.h"
#include "wolfssl_library/src/wolfssl_library.cpp"  /* Force compilation */

/* Choose a monitor serial baud rate: 9600, 14400, 19200, 57600, 74880, etc. */
#define SERIAL_BAUD 115200

/*****************************************************************************/
/*****************************************************************************/
/* Arduino setup()                                                           */
/*****************************************************************************/
/*****************************************************************************/
void setup() {
    Serial.begin(SERIAL_BAUD);
    while (!Serial) {
        /* wait for serial port to connect. Needed for native USB port only */
        delay(10);
    }
    /* See https://github.com/wolfSSL/wolfssl/blob/master/examples/configs/user_settings_arduino.h  */
    /* Various historical versions have differing features enabled. */
#ifdef WOLFSSL_USER_SETTINGS_ID
    /* Print the release version at runtime for reference. */
    Serial.println(WOLFSSL_USER_SETTINGS_ID);
#else
    /* Introduced after v5.7.6, or otherwise missing from user_settings.h  */
    Serial.println("A WOLFSSL_USER_SETTINGS_ID not found.");
#endif

    Serial.println(F("wolfSSL setup complete!!"));
    Serial.println(F(""));
    Serial.println(F(""));
}

/*****************************************************************************/
/*****************************************************************************/
/* Arduino loop()                                                            */
/*****************************************************************************/
/*****************************************************************************/
void loop() {
    int ret;
    Serial.println("\nLOOP!\n\n");

    Serial.print("wolfSSL Version: ");
    Serial.println(LIBWOLFSSL_VERSION_STRING);

    /* A project-level include.
     * These files typically WILL be visible automatically in the Arduino IDE */
    ret = wolfssl_helper_sample();
    Serial.printf("- wolfssl_helper_sample ret = %d\r\n", ret);

    /* A local library directory.
     * These files typically WILL NOT be visible in the Arduino IDE */
    ret = wolfssl_library_sample();
    Serial.printf("- wolfssl_library_sample ret = %d\r\n", ret);

    /* This next section demonstrates wolfSSL logging. Logging is toggled
     * on or off for each Arduino loop() iteration. WOLFSSL_MSG() only
     * prints messages when debugging is turned on. */

    /* Internal wolfssl_log() uses wolfSSL_Arduino_Serial_Print() */
    Serial.println("");
    Serial.println("Example wolfSSL_Arduino_Serial_Print():");
    wolfSSL_Arduino_Serial_Print("Hello from wolfSSL_Arduino_Serial_Print");

    /* WOLFSSL_MSG uses wolfssl_log() for conditional messages. */
    Serial.println("The next line is conditional depending on debug state:");
    WOLFSSL_MSG("Hello from wolfssl_log");
    Serial.println("");

    ret = WOLFSSL_IS_DEBUG_ON();
    if (ret == 0) {
        Serial.println(""); /* nothing would have printed in WOLFSSL_MSG */
        Serial.println("WOLFSSL_IS_DEBUG_ON is not set (debugging off)");

        Serial.println("Calling wolfSSL_Debugging_ON()");
        wolfSSL_Debugging_ON();
    }
    else {
        Serial.println("WOLFSSL_IS_DEBUG_ON is set (debugging on)");

        Serial.println("Calling wolfSSL_Debugging_OFF()");
        wolfSSL_Debugging_OFF();
    }

    delay(60000);
}
