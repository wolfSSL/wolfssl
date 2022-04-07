# MSP430 Example

This example was designed to be used with the MSP430F5359/MSP430F5659 but can be ported to any similar MSP platform. It will take ~50KB of ROM space and a 8KB of statically allocated RAM (nearly half for constants).

The example runs at 8MHz and executes a benchmark of ECC key generations, shared secrets and 1KB ChaCha20/Poly1305 encryption.

At 8MHz the ECC steps will take 13-15 seconds each and 1000 iterations of ChaCha20/Poly1305 will take about 45 seconds.

## Hardware Setup

A basic development board / ISP combination will work fine, such as the MSP-TS430PZ100 series with the MSP-FET430 series programmer.

The example will output text via UART 1, on the MSP430 which is port 8 bits 2&3 (pins 60/61) on the MSP430F5359. The UART will run at 57600 baud.

In addition every second port 1 bit 1 will be toggled on/off (typically an LED would be here).

## IDE setup

When setting up the IDE, copy the wolfSSL source code to your project's directory and add all the .c and .h files from `wolfcrypt/src` to your project.

Use the `main.c` provided here and copy the `user_settings.h` file to the `wolfssl/wolfcrypt` subdirectory of wolfSSL.

You will need to set at least 700 bytes of stack, no heap is required. It will need the memory model to set to "medium". You will also need to change the "Library Configuration" to "Full DLIB" so the `printf()` functions work correctly.

Make sure to add the definition `WOLFSSL_USER_SETTINGS` to the preprocessor settings in your project to that `user_settings.h` is loaded in. You will also need to add the wolfSSL root directory to the "Additional include directories".

From here you can set any optimizer settings you need.
