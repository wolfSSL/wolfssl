# wolfSSL Arduino Examples

There are currently five example Arduino sketches:

NOTE: Moving; See https://github.com/wolfSSL/wolfssl-examples/pull/499

* `template`: Reference template wolfSSL example, including optional VisualGDB project files.
* `wolfssl_AES_CTR`: Basic AES CTR Encryption / Decryption example.
* `wolfssl_client`: Basic TLS listening client.
* `wolfssl_server`: Basic TLS server.
* `wolfssl_version`: Bare-bones wolfSSL example.

Examples have been most recently confirmed operational on the
[Arduino IDE](https://www.arduino.cc/en/software) 2.2.1.

For examples on other platforms, see the [IDE directory](https://github.com/wolfssl/wolfssl/tree/master/IDE).
Additional wolfssl examples can be found at [wolfSSL/wolfssl-examples](https://github.com/wolfSSL/wolfssl-examples/).

## Using wolfSSL

The typical include will look something like this:

```
#include <Arduino.h>

 /* wolfSSL user_settings.h must be included from settings.h
  * Make all configurations changes in user_settings.h
  * Do not edit wolfSSL `settings.h` or `config.h` files.
  * Do not explicitly include user_settings.h in any source code.
  * Each Arduino sketch that uses wolfSSL must have: #include "wolfssl.h"
  * C/C++ source files can use: #include <wolfssl/wolfcrypt/settings.h>
  * The wolfSSL "settings.h" must be included in each source file using wolfSSL.
  * The wolfSSL "settings.h" must appear before any other wolfSSL include.
  */
#include <wolfssl.h>

/* settings.h is typically included in wolfssl.h, but here as a reminder: */
#include <wolfssl/wolfcrypt/settings.h>

/* Any other wolfSSL includes follow:*
#include <wolfssl/version.h>
```

## Configuring wolfSSL

See the `user_settings.h` in the Arduino library `wolfssl/src` directory. For Windows users this is typically:

```
C:\Users\%USERNAME%\Documents\Arduino\libraries\wolfssl\src
```

WARNING: Changes to the library `user_settings.h` file will be lost when upgrading wolfSSL using the Arduino IDE.

## Troubleshooting

If compile problems are encountered, for example:

```
ctags: cannot open temporary file : File exists
exit status 1

Compilation error: exit status 1
```

Try deleting the Arduino cache directory:

```
C:\Users\%USERNAME%\AppData\Local\arduino\sketches
```

For VisualGDB users, delete the project `.vs`, `Output`, and `TraceReports` directories.

## More Information

For more details, see [IDE/ARDUINO/README.md](https://github.com/wolfSSL/wolfssl/blob/master/IDE/ARDUINO/README.md)
