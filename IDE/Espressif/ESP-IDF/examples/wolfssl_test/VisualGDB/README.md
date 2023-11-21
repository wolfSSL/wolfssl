# wolfSSL Project Files for Visual Studio 2022 with VisualGDB Extension

Include in the respective project `./VisualGDB` directory are [VisualGDB](https://visualgdb.com/) project files.
Individual project files are included for convenience to new users, as there are [difficulties switching between ESP-IDF Versions or Chipsets](https://sysprogs.com/w/forums/topic/difficulties-switching-espressif-esp-idf-version-or-chipset/) using the VisualGDB extension.

The naming convention for project files is: `[project name]_IDF_[Version]_[chipset].vgdbproj`. The solution files (filename[.sln]) often will contain shortcuts to commonly used source and configuration files used by the respective project.


-------- |------------- |------------- |
ChipSet  | ESP-IDF v4.4 | ESP-IDF v5.0 |
-------- |------------- |------------- |
ESP32    |      x       |              |
ESP32-S2 |              |              |
ESP32-S3 |      x       |      x       |
ESP32-C3 |      x       |      x       |
ESP32-C6 |              |              |


The default directories are:

- `C:\SysGCC` - The root directory install of VisualGDB
- `C:\SysGCC\esp32` - The default for ESP-IDF v5.x
- `C:\SysGCC\esp32-8.4` - Many need to manually select this name for ESP-IDF v4.x install
- `C:\SysGCC\esp8266`- The default for ESP8266

## Resources

- [wolfSSL Website](https://www.wolfssl.com/)

- [wolfSSL Wiki](https://github.com/wolfSSL/wolfssl/wiki)

- [FIPS 140-2/140-3 FAQ](https://wolfssl.com/license/fips)

- [wolfSSL Documentation](https://wolfssl.com/wolfSSL/Docs.html)

- [wolfSSL Manual](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-toc.html)

- [wolfSSL API Reference](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-17-wolfssl-api-reference.html)

- [wolfCrypt API Reference](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-18-wolfcrypt-api-reference.html)

- [TLS 1.3](https://www.wolfssl.com/docs/tls13/)

- [wolfSSL Vulnerabilities](https://www.wolfssl.com/docs/security-vulnerabilities/)

- [Additional wolfSSL Examples](https://github.com/wolfssl/wolfssl-examples)

## Support

For questions please email [support@wolfssl.com](mailto:support@wolfssl.com)

<--  edit 5.6.0001 see https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/wolfssl_benchmark/VisualGDB -->
