# ESP-IDF port

NOTICE: These Espressif examples have been created and tested with the latest stable release branch of 
[ESP-IDF V4](https://docs.espressif.com/projects/esp-idf/en/v4.4.1/esp32/get-started/index.html)
and have not yet been upgraded to the master branch V5. 
See the latest [migration guides](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/migration-guides/index.html).

## Overview

 ESP-IDF development framework with wolfSSL by setting *WOLFSSL_ESPIDF* definition

Including the following examples:

* Simple [TLS client](./examples/wolfssl_client/)/[server](./examples/wolfssl_server/)
* Cryptographic [test](./examples/wolfssl_test/)
* Cryptographic [benchmark](./examples/wolfssl_benchmark/)

 The *user_settings.h* file enables some of the hardened settings.

## Requirements

 1. [ESP-IDF development framework](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/)

## wolfSSL as an Espressif component

There are various methods available for using wolfSSL as a component:

* Managed Component - easiest to get started.
* Local component directory - best for development.
* Install locally - least flexible, but project is fully self-contained.

## Espressif Managed Components

Visit https://components.espressif.com/components/wolfssl/wolfssl and see the instructions. Typically:

```
idf.py add-dependency "wolfssl/wolfssl^5.6.0-stable"
```

## Standard local component:

See the [template example](./examples/template/README.md). Simply created a `wolfssl` directory in the
local project `components` directory and place the [CMakeLists.txt](./examples/template/components/CMakeLists.txt)
file there. Then add a `components/wolfssl/include` directory and place the [user_settings.h](/examples/template/components/wolfssl/include/user_settings.h)
file there. If wolfSSL is in a structure such as `./workspace/wolfssl` with respect to your project at `./workspace/wolfssl`,
then the cmake file should automatically find the wolfSSL source code. Otherwise set the cmake `WOLFSSL_ROOT` variable
in the top-level CMake file. Examples:

```cmake
    set(WOLFSSL_ROOT  "C:/some-path/wolfssl")
    set(WOLFSSL_ROOT  "c:/workspace/wolfssl-[username]")
    set(WOLFSSL_ROOT  "/mnt/c/somepath/wolfssl")
```

See the specific examples for additional details.

## Setup for Linux (wolfSSL local copy)

 1. Run `setup.sh` at _/path/to_`/wolfssl/IDE/Espressif/ESP-IDF/` to deploy files into ESP-IDF tree  
 2. Find Wolfssl files at _/path/to/esp_`/esp-idf/components/wolfssl/`
 3. Find [Example Programs](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples) under _/path/to/esp_`/esp-idf/examples/protocols/wolfssl_xxx` (where xxx is the project name)

## Setup for Windows

 1. Run ESP-IDF Command Prompt (cmd.exe) or Run ESP-IDF PowerShell Environment
 2. Run `setup_win.bat` at `.\IDE\Espressif\ESP-IDF\`
 3. Find Wolfssl files at _/path/to/esp_`/esp-idf/components/wolfssl/`
 4. Find [Example programs](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples) under _/path/to/esp_`/esp-idf/examples/protocols/wolfssl_xxx` (where xxx is the project name)

## Setup for VisualGDB

### Clone a specific version:

```
C:\SysGCC\esp32\esp-idf>git clone -b v5.0.2 --recursive https://github.com/espressif/esp-idf.git v5.0.2
```

## Configuration

 1. The `user_settings.h` can be found in _/path/to/esp_`/esp-idf/components/wolfssl/include/user_settings.h`

## Build examples

 1. See README in each example folder

## Support

 For question please email [support@wolfssl.com]

 Note: This is tested with :  
   - OS: Ubuntu 20.04.3 LTS
   - Microsoft Windows 10 Pro 10.0.19041 
   - WSL Ubuntu

   - ESP-IDF: ESP-IDF v4.3.2
   - Module : ESP32-WROOM-32

## JTAG Debugging

All of the examples are configured to use either the on-board JTAG (when available) or
the open source [Tigard multi-protocol tool for hardware hacking](https://github.com/tigard-tools/tigard).

VisualGDB users should find the configuration file in the `interface\ftdi` directory:

```
C:\Users\%USERNAME%\AppData\Local\VisualGDB\EmbeddedDebugPackages\com.sysprogs.esp32.core\share\openocd\scripts\interface\ftdi
```
