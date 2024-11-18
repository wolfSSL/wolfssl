# wolfSSL Espressif Component

This is the directory for wolfSSL as an Espressif ESP-IDF component.

Other options are available, such as installing wolfSSL as a local _project_ component using the [Managed Component](https://www.wolfssl.com/wolfssl-now-available-in-espressif-component-registry/).

Enabling this wolfSSL ESP-IDF component allows other ESP-IDF libraries such as those that depend on [ESP-TLS](https://github.com/espressif/esp-idf/tree/master/components/esp-tls)
to also use the wolfSSL library. (See [github.com/wolfSSL/wolfssl](https://github.com/wolfSSL/wolfssl))

The wolfSSL source code is not included here. Instead, the `idf.py menuconfig` option can be used to configure the
`sdkconfig` file setting: `CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT` to point to the desired wolfSSL code.

## Directory Contents

This directory must contain, at a minimum:

- `CMakeLists.txt`
- `./include/user_settings.h`

The directory should also contain:
- `Kconfig`
- `component.mk`

The directory may contain wolfSSL source, for example with a [Managed Component](https://www.wolfssl.com/wolfssl-now-available-in-espressif-component-registry/),
or if the `setup.sh` script was used from [wolfSSL/IDE/Espressif/ESP-IDF](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF).


Under normal circumstances when the wolfSSL source is not included here, the `CMakeLists.txt` will search for it in this order:

- A hard-coded `WOLFSSL_ROOT` cmake variable.
- `WOLFSSL_ROOT` Environment Variable
- The `CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT` value in the `sdkconfig` file, from the `Kconfig` option.
- Any parent directories, up to the root (if this directory is in the ESP-IDF components)
- Any parent directories, up to the root (if this directory is a project component)

While recursing up the directory tree, the following names of wolfSSL directories will be considered:

- `wolfssl-[current user name]`
- `wolfssl-master`
- `wolfssl`

## Getting Started

See the `Espressif Getting Started Guide`.

```
# Set environment variable to ESP-IDF location
# For example, VisualGDB in WSL
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2
WRK_IDF_PATH=/mnt/c/SysGCC/esp32-master/esp-idf/v5.3-master

# Or wherever the ESP-IDF is installed:
WRK_IDF_PATH=~/esp/esp-idf

echo "Run export.sh from ${WRK_IDF_PATH}"
. ${WRK_IDF_PATH}/export.sh

cd [your project]

idf.py menuconfig
```

Enable wolfSSL to be used in the ESP-TLS:

```
Component config  --->
    ESP-TLS  --->
        Choose SSL/TLS library for ESP-TLS (See help for more Info)
            (X) wolfSSL (License info in wolfSSL directory README)
```

Adjust wolfSSL settings, such as path to source code as needed:

```
Component config  --->
    wolfSSL  --->
        [*] Include wolfSSL in ESP-TLS
        [*] Use the specified wolfssl for ESP-TLS
        (~/workspace/wolfssl) Enter a path for wolfSSL source code
```

## Configuration

All settings for wolfSSL are adjusted in the [include/user_settings.h](./include/user_settings.h) file.

The `user_settings.h` file should not be included directly. Instead, `#include <wolfssl/wolfcrypt/settings.h>`
before any other wolfSSL headers, like this:


```c
/* ESP-IDF */
#include <esp_log.h>
#include "sdkconfig.h"

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
#if defined(WOLFSSL_USER_SETTINGS)
    #include <wolfssl/wolfcrypt/settings.h>
    #if defined(WOLFSSL_ESPIDF)
        #include <wolfssl/version.h>
        #include <wolfssl/wolfcrypt/types.h>
        #include <wolfcrypt/test/test.h>
        #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
        #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
    #else
        #error "Problem with wolfSSL user_settings. "           \
               "Check components/wolfssl/include "              \
               "and confirm WOLFSSL_USER_SETTINGS is defined, " \
               "typically in the component CMakeLists.txt"
    #endif
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif
```

## Examples

See the wolfSSL examples:

- [wolfSSL Core Examples](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples)
- [wolfSSL Additional Examples](https://github.com/wolfSSL/wolfssl-examples/tree/master/ESP32)
- [wolfSSH Core Examples](https://github.com/wolfSSL/wolfssh/tree/master/ide/Espressif/ESP-IDF/examples)
- [wolfSSH Additional Examples](https://github.com/wolfSSL/wolfssh-examples/tree/main/Espressif)
- [wolfMQTT Examples](https://github.com/wolfSSL/wolfMQTT/tree/master/IDE/Espressif/ESP-IDF/examples)

## Platforms

The ESP-IDF wolfSSL is also available for PlatformIO:

- [Release wolfSSL](https://registry.platformio.org/search?q=owner%3Awolfssl)
- [Staging / Preview wolfSSL](https://registry.platformio.org/search?q=owner%3Awolfssl-staging)

The wolfSSL library can also be used for Espressif with Arduino:

- [arduino.cc/reference/en/libraries/wolfssl](https://www.arduino.cc/reference/en/libraries/wolfssl/)
- [github.com/wolfSSL/Arduino-wolfSSL](https://github.com/wolfSSL/Arduino-wolfSSL)


## Additional Information

- [wolfSSL Documentation](https://www.wolfssl.com/documentation/manuals/wolfssl/index.html) and [docs/espressif](https://www.wolfssl.com/docs/espressif/)
- [wolfSSL FAQ](https://www.wolfssl.com/docs/frequently-asked-questions-faq/)
- [wolfSSL Products](https://www.wolfssl.com/products/)
- [www.wolfssl.com/espressif](https://www.wolfssl.com/espressif/)
- [More...](https://www.wolfssl.com/?s=espressif)

## Contact

Have a specific request or questions? We'd love to hear from you! Please contact us at support@wolfssl.com or open an issue on GitHub.

## Licensing and Support

wolfSSL (formerly known as CyaSSL) and wolfCrypt are either licensed for use under the GPLv2 (or at your option any later version) or a standard commercial license. For our users who cannot use wolfSSL under GPLv2 (or any later version), a commercial license to wolfSSL and wolfCrypt is available.

See the LICENSE.txt, visit wolfssl.com/license, contact us at licensing@wolfssl.com or call +1 425 245 8247

View Commercial Support Options: [wolfssl.com/products/support-and-maintenance](wolfssl.com/products/support-and-maintenance)

