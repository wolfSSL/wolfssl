# ESP-IDF Port

These Espressif examples have been created and tested with the latest stable release branch of
ESP-IDF v5.2, v5.3 and the master branch

The prior version 4.4 ESP-IDF is still supported, however version 5.2 or greater is recommended.
Espressif has [a list of all ESP-IDF versions](Espressifversions.html).

See the latest Espressif Migration Guides.

## Examples

Included are the following [examples](./examples/README.md):

* Bare-bones [Template](./examples/template/README.md)
* Simple [TLS Client](./examples/wolfssl_client/README.md) / [TLS Server](./examples/wolfssl_server/README.md)
* Cryptographic [Test](./examples/wolfssl_test/README.md)
* Cryptographic [Benchmark](./examples/wolfssl_benchmark/README.md)

## Important Usage Details

The wolfSSL code specific to the Espressif ESP-IDF development framework
is gated in code with the `WOLFSSL_ESPIDF` definition. This is enabled
automatically when the `WOLFSSL_USER_SETTINGS` is defined. The recommended
method is to have this line in the main `CMakeLists.txt` file as shown in the
[example](./examples/template/main/CMakeLists.txt):

```cmake
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")
```

When defining `WOLFSSL_USER_SETTINGS`, this tells the `settings.h` file to
looks for the wolfSSL `user_settings.h` in the project as described below.

### File: `sdkconfig.h`

The Espressif `sdkconfig.h`, generated automatically from your `sdkconfig`
file at [build](Espressif api-guides/build-system.html)
time, should be included before any other files.

### File: `user_settings.h`

The `user_settings.h` file enables some of the hardened security settings. There are also some
default configuration items in the wolfssl `settings.h`. With the latest version of
wolfSSL, some of these defaults can be disabled with `NO_ESPIDF_DEFAULT` and customized
in your project `user_settings.h` as desired.

The `user_settings.h` include file should not be explicitly included in an project source files. Be
sure to include `settings.h` (which pulls in `user_settings.h`) before any other wolfSSL include files.

A new project should also include a compiler option suc as `CFLAGS +=-DWOLFSSL_USER_SETTINGS"` to ensure
the `user_settings.h` is included properly. See the [template example](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/examples/template/main/main.c).

```
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif
```

See the respective project directory:

  `[project-dir]/components/wolfssl/user_settings.h`

A typical project will _not_ directly reference the `user_settings.h` file.
Here's an example to be included at the top of a given source file:

```c
/* ESP-IDF */
#include <esp_log.h>
#include "sdkconfig.h"

/* wolfSSL */
#include <wolfssl/wolfcrypt/settings.h> /* references user_settings.h */
/* Do not explicitly include wolfSSL user_settings.h */
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
```

Prior versions of the wolfSSL Espressif library expected the `user_settings.h` to be in the root wolfssl folder in a directory
called `/include`. This method, while possible, is no longer recommended.

Be sure to *not* have a `user_settings.h` in _both_ the local project and the wolfssl `include` directories.

### File: `wolfssl/wolfcrypt/settings.h`

The wolfSSL  built-in `settings.h` references your project `user_settings.h`. The
`settings.h` should _not_ be edited directly. Any wolfSSL settings should be adjusted in your local project
`user_settings.h` file.

The `settings.h` has some SoC-target-specific settings, so be sure to `#include "sdkconfig.h"` at the beginning
of your source code, particularly before the `#include <wolfssl/wolfcrypt/settings.h>` line.

## Requirements

 1. [ESP-IDF development framework](https://github.com/espressif/esp-idf)

## wolfSSL as an Espressif component

There are various methods available for using wolfSSL as a component:

* Managed Component - easiest to get started.
* Local component directory - best for development.
* Install locally - least flexible, but project is fully self-contained.

## Espressif Managed Components

Visit https://www.wolfssl.com/wolfssl-now-available-in-espressif-component-registry/ and see the instructions. Typically:

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

This is an alternate method for installation. It is recommended to use the new `CMakeLists.txt` to point to wolfSSL source code.

 1. Run `setup.sh` at _/path/to_`/wolfssl/IDE/Espressif/ESP-IDF/` to deploy files into ESP-IDF tree
 2. Find Wolfssl files at _/path/to/esp_`/esp-idf/components/wolfssl/`
 3. Find [Example Programs](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples) under _/path/to/esp_`/esp-idf/examples/protocols/wolfssl_xxx` (where xxx is the project name)


```
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2
. $WRK_IDF_PATH/export.sh

./setup.sh
```

## Setup for Windows

This is an alternate method for installation. It is recommended to use the new `CMakeLists.txt` to point to wolfSSL source code.

 1. Run ESP-IDF Command Prompt (cmd.exe) or Run ESP-IDF PowerShell Environment
 2. Run `setup_win.bat` at `.\IDE\Espressif\ESP-IDF\`
 3. Find Wolfssl files at _/path/to/esp_`/esp-idf/components/wolfssl/`
 4. Find [Example programs](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples) under _/path/to/esp_`/esp-idf/examples/protocols/wolfssl_xxx` (where xxx is the project name)

## Setup for VisualGDB

See the local project `./VisualGDB` for sample project files. For single-step JTAG debugging on boards that do not
have a built-in JTAG port, the wolfSSL examples use the open source [Tigard board](https://github.com/tigard-tools/tigard#readme).

See also the [gojimmypi blog](https://gojimmypi.github.io/Tigard-JTAG-SingleStep-Debugging-ESP32/) on using the Tigard
to JTAG debug the ESP32.

### Clone a specific version:

```
C:\SysGCC\esp32\esp-idf>git clone -b v5.0.2 --recursive https://github.com/espressif/esp-idf.git v5.0.2
```

## Configuration

 1. The `user_settings.h` can be found in `[project]/components/wolfssl/include/user_settings.h`.

## Configuration (Legacy IDF install)

 1. The `user_settings.h` can be found in _/path/to/esp_`/esp-idf/components/wolfssl/include/user_settings.h`

## Build examples

 1. See README in each example folder.

## Support

 For question please email [support@wolfssl.com]

 Note: This is tested with :
   - OS: Ubuntu 20.04.3 LTS
   - Microsoft Windows 10 Pro 10.0.19041 / Windows 11 Pro 22H2 22621.2715
   - Visual Studio 2022 17.7.6 with VisualGDB 5.6R9 (build 4777)
   - WSL 1 Ubuntu 22.04.3 LTS
   - ESP-IDF: ESP-IDF v5.2
   - SoC Module : all those supported in ESP-IDF v5.2

## JTAG Debugging Notes

All of the examples are configured to use either the on-board JTAG (when available) or
the open source [Tigard multi-protocol tool for hardware hacking](https://github.com/tigard-tools/tigard).

VisualGDB users should find the configuration file in the `interface\ftdi` directory:

```
C:\Users\%USERNAME%\AppData\Local\VisualGDB\EmbeddedDebugPackages\com.sysprogs.esp32.core\share\openocd\scripts\interface\ftdi
```

For reference, the `tigard.cfg` looks like this:

```
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Tigard: An FTDI FT2232H-based multi-protocol tool for hardware hacking.
# https://github.com/tigard-tools/tigard

adapter driver ftdi

ftdi device_desc "Tigard V1.1"
ftdi vid_pid 0x0403 0x6010

ftdi channel 1

ftdi layout_init 0x0038 0x003b
ftdi layout_signal nTRST -data 0x0010
ftdi layout_signal nSRST -data 0x0020

# This board doesn't support open-drain reset modes since its output buffer is
# always enabled.
reset_config srst_push_pull trst_push_pull

```

## Windows long paths

Check "Long Paths Enabled" in Windows registry.

Please set registry HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled to 1.

The operation requires Administrator privileges. Command:

```powershell
powershell -Command "&{ Start-Process -FilePath reg 'ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f' -Verb runAs}"
```
