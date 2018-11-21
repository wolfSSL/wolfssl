# ESP32 Port

Support for the ESP32-WROOM-32 on-board crypto hardware acceleration for symmetric AES and SHA1/SHA256/SHA384/SHA512.

NOTE: RSA has not supported yet.

## ESP32 Acceleration

For detail about ESP32 HW Acceleration, you can find in [Technical Reference Manual](https://espressif.com/sites/default/files/documentation/esp32_technical_reference_manual_en.pdf)

### Building

To enable hw acceleration :

Uncomment out #define WOLFSSL_ESPIDF in /path/to/wolfssl/wolfssl/wolfcrypt/settings.h  
Uncomment out #define WOLFSSL_ESPWROOM32 in /path/to/wolfssl/wolfssl/wolfcrypt/settings.h

To disable portions of the hardware acceleration you can optionally define:  

```
/* Disabled SHA and AES acceleration */
#define NO_ESP32WROOM32_CRYPT
/* Disabled AES acceleration */
#define NO_WOLFSSL_ESP32WROOM32_CRYPT_AES
/* Disabed SHA acceleration */
#define NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH
```

### Coding

In your application you must include <wolfssl/wolfcrypt/settings.h> before any other wolfSSL headers. If building the sources directly we recommend defining `WOLFSSL_USER_SETTINGS` and adding your own `user_settings.h` file. You can find a good reference for this in `IDE/GCC-ARM/Header/user_settings.h`.


### Benchmarks

Software only implementation :


```
AES-128-CBC-enc      1 MB took 1.001 seconds,    1.146 MB/s
AES-128-CBC-dec      1 MB took 1.017 seconds,    1.104 MB/s
AES-192-CBC-enc      1 MB took 1.018 seconds,    1.055 MB/s
AES-192-CBC-dec      1 MB took 1.006 seconds,    1.019 MB/s
AES-256-CBC-enc   1000 KB took 1.000 seconds, 1000.000 KB/s
AES-256-CBC-dec    975 KB took 1.007 seconds,  968.222 KB/s
AES-128-GCM-enc    350 KB took 1.055 seconds,  331.754 KB/s
AES-128-GCM-dec    350 KB took 1.055 seconds,  331.754 KB/s
AES-192-GCM-enc    325 KB took 1.013 seconds,  320.829 KB/s
AES-192-GCM-dec    325 KB took 1.013 seconds,  320.829 KB/s
AES-256-GCM-enc    325 KB took 1.041 seconds,  312.200 KB/s
AES-256-GCM-dec    325 KB took 1.041 seconds,  312.200 KB/s
SHA                  6 MB took 1.003 seconds,    5.720 MB/s
SHA-256              2 MB took 1.003 seconds,    2.483 MB/s
SHA-384              1 MB took 1.002 seconds,    1.218 MB/s
SHA-512              1 MB took 1.000 seconds,    1.221 MB/s
HMAC-SHA             6 MB took 1.000 seconds,    5.664 MB/s
HMAC-SHA256          2 MB took 1.002 seconds,    2.461 MB/s
HMAC-SHA384          1 MB took 1.017 seconds,    1.200 MB/s
HMAC-SHA512          1 MB took 1.017 seconds,    1.200 MB/s
```

Hardware Acceleration :


```
AES-128-CBC-enc      6 MB took 1.002 seconds,    6.018 MB/s
AES-128-CBC-dec      5 MB took 1.002 seconds,    5.336 MB/s
AES-192-CBC-enc      6 MB took 1.003 seconds,    6.012 MB/s
AES-192-CBC-dec      5 MB took 1.004 seconds,    5.325 MB/s
AES-256-CBC-enc      6 MB took 1.003 seconds,    6.012 MB/s
AES-256-CBC-dec      5 MB took 1.004 seconds,    5.325 MB/s
AES-128-GCM-enc    350 KB took 1.001 seconds,  349.650 KB/s
AES-128-GCM-dec    350 KB took 1.001 seconds,  349.650 KB/s
AES-192-GCM-enc    350 KB took 1.015 seconds,  344.828 KB/s
AES-192-GCM-dec    350 KB took 1.015 seconds,  344.828 KB/s
AES-256-GCM-enc    350 KB took 1.022 seconds,  342.466 KB/s
AES-256-GCM-dec    350 KB took 1.022 seconds,  342.466 KB/s
SHA                 14 MB took 1.001 seconds,   14.073 MB/s
SHA-256             15 MB took 1.000 seconds,   15.259 MB/s
SHA-384             18 MB took 1.000 seconds,   17.529 MB/s
SHA-512             18 MB took 1.000 seconds,   17.529 MB/s
HMAC-SHA            14 MB took 1.001 seconds,   13.805 MB/s
HMAC-SHA256         15 MB took 1.000 seconds,   14.966 MB/s
HMAC-SHA384         17 MB took 1.000 seconds,   16.968 MB/s
HMAC-SHA512         17 MB took 1.001 seconds,   16.951 MB/s
```

Condition  :  
- Model    : ESP32-WROOM-32  
- CPU Speed: 240Mhz  
- ESP-IDF  : v3.3-beta1-39-g6cb37ecc5(commit hash : 6cb37ecc5)  
- OS       : Ubuntu 18.04.1 LTS (Bionic Beaver)

## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
