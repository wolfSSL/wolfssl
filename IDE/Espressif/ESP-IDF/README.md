# ESP-IDF port
## Overview
 ESP-IDF development framework with wolfSSL by setting *WOLFSSL_ESPIDF* definition

Including the following examples:

* Simple [tls_client](./examples/wolfssl_client/)/[server](./examples/wolfssl_server/)
* Cryptographic [test](./examples/wolfssl_test/)
* Cryptographic [benchmark](./examples/wolfssl_benchmark/)

 The *user_settings.h* file enables some of the hardened settings.

## Requirements
 1. [ESP-IDF development framework](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/)

    Note: This expects to use Linux version.

## Setup for Linux
 1. Run `setup.sh` at _/path/to_`/wolfssl/IDE/Espressif/ESP-IDF/` to deploy files into ESP-IDF tree  
    For Windows : Run `setup_win.bat` at `.\IDE\Espressif\ESP-IDF\`
    
 2. Find Wolfssl files at _/path/to/esp_`/esp-idf/components/wolfssl/`
 
 3. Find [Example programs](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples) under _/path/to/esp_`/esp-idf/examples/protocols/wolfssl_xxx` (where xxx is the project name)

 4. Uncomment out `#define WOLFSSL_ESPIDF` in _/path/to/esp_`/esp-idf/components/wolfssl/wolfssl/wolfcrypt/settings.h`  
    Uncomment out `#define WOLFSSL_ESPWROOM32` in _/path/to/esp_`/esp-idf/components/wolfssl/wolfssl/wolfcrypt/settings.h`
    
    for example the default:
    `~/esp/esp-idf/components/wolfssl/wolfssl/wolfcrypt/settings.h`

## Configuration
 1. The `user_settings.h` can be found in _/path/to/esp_`/esp-idf/components/wolfssl/include/user_settings.h`

## Build examples
 1. See README in each example folder

## Support
 For question please email [support@wolfssl.com]

 Note: This is tested with :  
   - OS: Ubuntu 18.04.1 LTS and Microsoft Windows 10 Pro 10.0.19041 and well as WSL Ubuntu
   - ESP-IDF: v4.4-dev-4031-gef98a363e3-dirty and v4.0.1-dirty 
   - Module : ESP32-WROOM-32