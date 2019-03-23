# ESP-IDF port
## Overview
 ESP-IDF development framework with wolfSSL by setting *WOLFSSL_ESPIDF* definition

Including the following examples:

* simple tls_client/server
* crypt test
* crypt benchmark

 The *user_settings.h* file enables some of the hardened settings.

## Requirements
 1. ESP-IDF development framework  
    [https://docs.espressif.com/projects/esp-idf/en/latest/get-started/]

    Note: This expects to use Linux version.

## Setup
 1. Run *setup.sh* to deploy files into ESP-IDF tree
 2. Find Wolfssl files at /path/to/esp-idf/components/wolfssl/
 3. Find Example programs under /path/to/esp-idf/examples/protocols/wolfssl_xxx
 4. Uncomment out #define WOLFSSL_ESPIDF in /path/to/wolfssl/wolfssl/wolfcrypt/settings.h  
    Uncomment out #define WOLFSSL_ESPWROOM32 in /path/to/wolfssl/wolfssl/wolfcrypt/settings.h

## Configuration
 1. The *user_settings.h* can be found in /path/to/esp-idf/components/wolfssl/include/user_settings.h

## Build examples
 1. See README in each example folder

## Support
 For question please email [support@wolfssl.com]

 Note: This is tested with "Ubuntu 18.04.1 LTS" and ESP32-WROOM-32.
