# wolfSSL Arduino Examples

There are currently two example Arduino sketches:

* [wolfssl_client](./wolfssl_client/README.md): Basic TLS listening client.
* [wolfssl_server](./wolfssl_server/README.md): Basic TLS server.

Examples have been most recently confirmed operational on the
[Arduino IDE](https://www.arduino.cc/en/software) 2.2.1.

For examples on other platforms, see the [IDE directory](https://github.com/wolfssl/wolfssl/tree/master/IDE).
Additional examples can be found on [wolfSSL/wolfssl-examples](https://github.com/wolfSSL/wolfssl-examples/).

## Using wolfSSL

The typical include will look something like this:

```
#include <Arduino.h>

 /* wolfSSL user_settings.h must be included from settings.h
  * Make all configurations changes in user_settings.h
  * Do not edit wolfSSL `settings.h` or `configh.h` files.
  * Do not explicitly include user_settings.h in any source code.
  * Each Arduino sketch that uses wolfSSL must have: #include "wolfssl.h"
  * C/C++ source files can use: #include <wolfssl/wolfcrypt/settings.h>
  * The wolfSSL "settings.h" must be included in each source file using wolfSSL.
  * The wolfSSL "settings.h" must appear before any other wolfSSL include.
  */
#include <wolfssl.h>
#include <wolfssl/version.h>
```

For more details, see [IDE/ARDUINO/README.md](https://github.com/wolfSSL/wolfssl/blob/master/IDE/ARDUINO/README.md)
