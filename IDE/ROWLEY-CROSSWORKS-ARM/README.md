# Rowley CrossWorks ARM Project for wolfSSL and wolfCrypt

This directory contains a CrossWorks solution named wolfssl.hzp.

Inside are three projects:

1. libwolfssl: 
This generates a library file named "libwolfssl_ARM_Debug/libwolfssl_v7em_t_le_eabi.a"
2. benchmark: 
This is a sample benchmark application. It runs the "benchmark_test" suite repeatedly until a failure occurs.
3. test: 
This is a sample test application. It runs "wolfcrypt_test" suite suite repeatedly until a failure occurs.

# Prerequisits

You will need to install the "Freescale Kinetis CPU Support Package" in the 
Rowley Package Manager under Tools -> Pacakge Manager.

# Harware Support

All hardware functions are defined in `kinetis_hw.c` and are currently setup for a Freescale Kinetis K64 Coretx-M4 microcontroller. This file can be customized to work with other Kinetis microcontrollers by editing the top part of the file. Testing for this project was done with the Freescale Kinetis `MK64FN1M0xxx12` using the `TWR-K64F120M`.

To create support for a new ARM microcontroller the functions in `hw.h` will need to be implemented.

Also you will need to configure the ARM Architecture and ARM Core Type in the "Solution Properties" -> "ARM". 
Also the "Target Processor" in each of the projects ("Project Properties" -> "Target Processor")

## Hardware Crypto Acceleration

To enable Freescale MMCAU:

1. [Download the MMCAU library](http://www.freescale.com/products/arm-processors/kinetis-cortex-m/k-series/k7x-glcd-mcus/crypto-acceleration-unit-cau-and-mmcau-software-library:CAUAP).
2. Copy the `lib_mmcau.a` and `cau_api.h` files into the project.
3. Enable the `FREESCALE_MMCAU` define in `user_settings.h` and make sure its value is `1`.
4. Add the `lib_mmcau.a` file to `Source Files` in the application project.

# Project Files

* `arm_startup.c`: Handles startup from `reset_handler`. Disabled watchdog, initializes sections, initializes heap, starts harware and starts main.
* `benchmark_main.c`: The main function entrypoint for benchmark application.
* `hw.h`: The hardware API interface. These hardware interface functions are required for all platforms.
* `kinetis_hw.c`: The most basic hardware implementation required for Kinetis.
* `test_main.c`: The main function entrypoint for test application.
* `user_libc.c`: Defines stubs for functions required by libc. It also wraps hardware functions for UART, RTC and Random Number Generator (RNG).
* `user_settings.h`: This is the custom user configuration file for WolfSSL.

# Functions required by the WolfSSL Library

If you are writting your own application, the following functions need to be implemented to support the WolfSSL library:

* `double current_time(int reset)`: Returns a doulbe as seconds.milliseconds.
* `int custom_rand_generate(void)`: Returns a 32-bit randomly generated number.
