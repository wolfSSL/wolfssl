#include <Arduino.h>
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
