# DEMO program with ATECC608A on ESP-WROOM-32SE
## Overview
 Running demo programs with ATECC608A on 32SE by setting *WOLFSSL_ESPWROOM32SE* definition

Including the following examples:

* simple tls_client/tls_server
* crypt benchmark

 The *user_settings.h* file enables some of the hardened settings. 
 
## Requirements
 1. ESP-IDF development framework  
    [https://docs.espressif.com/projects/esp-idf/en/latest/get-started/]

 2. Microchip CryptoAuthentication Library  
    [https://github.com/MicrochipTech/cryptoauthlib]
    
## Setup
 1. wolfSSL under ESP-IDF. Please see [README.md](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md)
 2. CryptoAuthentication Library under ESP-IDF. Please see [README.md](https://github.com/miyazakh/cryptoauthlib_esp_idf/blob/master/README.md)
 
 3. Uncomment out #define WOLFSSL_ESPWROOM32SE in /path/to/wolfssl/wolfssl/wolfcrypt/settings.h
 
    Note : Need to enable WOLFSSL_ESPIDF  
    Note : crypt test will fail if enabled WOLFSSL_ESPWROOM32SE
 
## Configuration
 1. The *user_settings.h* can be found in /path/to/esp-idf/components/wolfssl/include/user_settings.h

## Build examples
 1. See README in each example folder

## Support
 For question please email [support@wolfssl.com]

 Note: This is tested with the following condition:
 
- Model    : ESP32-WROOM-32SE  
- ESP-IDF  : v3.3-beta1-39-g6cb37ecc5(commit hash : 6cb37ecc5)  
- CryptAuthLib: commit hash : c6b176e
- OS       : Ubuntu 18.04.1 LTS (Bionic Beaver)
