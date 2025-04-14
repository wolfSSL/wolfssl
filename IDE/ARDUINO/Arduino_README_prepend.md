# Arduino wolfSSL Library

This library is restructured from [wolfSSL](https://github.com/wolfSSL/wolfssl/) Release ${WOLFSSL_VERSION} for the Arduino platform.

The Official wolfSSL Arduino Library is found in [The Library Manager index](http://downloads.arduino.cc/libraries/library_index.json).

See the [Arduino-wolfSSL logs](https://downloads.arduino.cc/libraries/logs/github.com/wolfSSL/Arduino-wolfSSL/) for publishing status.

Instructions for installing and using libraries can be found in the [Arduino docs](https://docs.arduino.cc/software/ide-v1/tutorials/installing-libraries/).

## wolfSSL Configuration

As described in the [Getting Started with wolfSSL on Arduino](https://www.wolfssl.com/getting-started-with-wolfssl-on-arduino/), wolfSSL features are enabled and disabled in the `user_settings.h` file.

The `user_settings.h` file is found in the `<Arduino>/libraries/wolfssl/src` directory.

For Windows this is typically `C:\Users\%USERNAME%\Documents\Arduino\libraries\wolfssl\src`

For Mac: `~/Documents/Arduino/libraries/wolfssl/src`

For Linux: `~/Arduino/libraries/wolfssl/src`

Tips for success:

- The `WOLFSSL_USER_SETTINGS` macro must be defined project-wide. (see [wolfssl.h](https://github.com/wolfSSL/wolfssl/blob/master/IDE/ARDUINO/wolfssl.h))
- Apply any customizations only to `user_settings.h`;  Do not edit wolfSSL `settings.h` or `configh.h` files.
- Do not explicitly include `user_settings.h` in any source file.
- For every source file that uses wolfssl, include `wolfssl/wolfcrypt/settings.h` before any other wolfSSL include, typically via `#include "wolfssl.h"`.
- See the [wolfSSL docs](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html) for details on build configuration macros.

## wolfSSL Examples

Additional wolfSSL examples can be found at:

- https://github.com/wolfSSL/wolfssl/tree/master/IDE/ARDUINO

- https://github.com/wolfSSL/wolfssl/tree/master/examples

- https://github.com/wolfSSL/wolfssl-examples/

## Arduino Releases

This release of wolfSSL is version [5.7.6](https://github.com/wolfSSL/wolfssl/releases/tag/v5.7.6-stable).

See GitHub for [all Arduino wolfSSL releases](https://github.com/wolfSSL/Arduino-wolfSSL/releases).

The first Official wolfSSL Arduino Library was `5.6.6-Arduino.1`: a slightly modified, post [release 5.6.6](https://github.com/wolfSSL/wolfssl/releases/tag/v5.6.6-stable) version update.

The `./wolfssl-arduino.sh INSTALL` [script](https://github.com/wolfSSL/wolfssl/tree/master/IDE/ARDUINO) can be used to install specific GitHub versions as needed.
