# ESP32 Port

Support for the ESP32 on-board cryptographic hardware acceleration for symmetric AES, SHA1/SHA256/SHA384/SHA512 and RSA primitive including mul, mulmod and exptmod.

* ESP32 - Supported
* ESP32S2 - Supported
* ESP32S3 - Supported
* ESP32C2 - Software only (contact support to request hardware acceleration)
* ESP32C3 - Supported
* ESP32C6 - Supported
* ESP32H2 - Software only (contact support to request hardware acceleration)

## ESP32 Acceleration

More details about ESP32 HW Acceleration can be found in:

* `esp32_technical_reference_manual_en.pdf`
* `esp32-s2_technical_reference_manual_en.pdf`
* `esp32-s3_technical_reference_manual_en.pdf`
* `esp8684_technical_reference_manual_en.pdf`
* `esp32-c3_technical_reference_manual_en.pdf`
* `esp32-c6_technical_reference_manual_en.pdf`
* `esp32-h2_technical_reference_manual_en.pdf`

### Building

Simply run `ESP-IDF.py` in any of the [Espressif/ESP-IDF/Examples](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples).
See the respective project README files. Examples are also available using wolfssl as a [Managed Component](https://www.wolfssl.com/wolfssl-now-available-in-espressif-component-registry/).

Hardware acceleration is enabled by default. All settings should be adjusted in the respective project component
`user_settings.h` file. See the example in [template example](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/examples/template/components/wolfssl/include/user_settings.h).
In particular, comment out the `NO_[feature_name]` macros to enable hardware encryption:

    /* #define NO_ESP32_CRYPT                 */
    /* #define NO_WOLFSSL_ESP32_CRYPT_HASH    */
    /* #define NO_WOLFSSL_ESP32_CRYPT_AES     */
    /* #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */

To disable specific portions of the hardware acceleration you can optionally define:

```c
/* Disable all SHA, AES and RSA acceleration */
#define NO_ESP32_CRYPT

/* Disable only AES acceleration */
#define NO_WOLFSSL_ESP32_CRYPT_AES

/* Disabled only SHA acceleration */
#define NO_WOLFSSL_ESP32_CRYPT_HASH

/* Disabled only RSA Primitive acceleration */
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
```

See the [wolfcrypt/port/Espressif/esp32-crypt.h](https://github.com/wolfSSL/wolfssl/blob/master/wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h)
for more details on fine tuning and debugging options.

### Coding

In your application you must include `<wolfssl/wolfcrypt/settings.h>` before any other wolfSSL headers.
If building the sources directly we recommend defining `WOLFSSL_USER_SETTINGS` (typically defined in the `CMakeLists.txt`)
and adding your own `user_settings.h` file. You can find a good reference in the [Espressif examples](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples)
as well as other examples such as [IDE/GCC-ARM/Header/user_settings.h](https://github.com/wolfSSL/wolfssl/blob/master/IDE/GCC-ARM/Header/user_settings.h).

To view disassembly, add `__attribute__((section(".iram1")))` decorator. Foe example:

To view disassembly, add `__attribute__((section(".iram1")))` decorator. Foe example:

```
static int __attribute__((section(".iram1"))) memblock_peek(volatile u_int32_t mem_address)
```

### VisualGDB

Each project example has a `VisuaGDB` directory with sample project files for [Sysprogs VisualGDB](https://visualgdb.com).

For installing multiple toolchains, see the [documentation](https://visualgdb.com/documentation/espidf/).

The library naming format used at wolfSSL:

```
HKEY_CURRENT_USER\Software\Sysprogs\GNUToolchains
```

| Registry String Value Name       | Value Data             |
| -------------------------------- |----------------------- |
| `SysGCC-xtensa-lx106-elf-8.4.0`  | `C:\SysGCC\esp8266`    |
| `SysGCC-xtensa-esp32-elf-8.4.0`  | `C:\SysGCC\esp32-8.4`  |
| `SysGCC-xtensa-esp32-elf-13.2.0` | `C:\SysGCC\esp32`      |
| `SysGCC-xtensa-esp32-elf-12.4.0` | `C:\SysGCC\esp32-12.4` |
| `SysGCC-xtensa-esp32-elf-11.2.0` | `C:\SysGCC\esp32-11.2` |

Note the latest toolchain value is the default install name of `C:\SysGCC\esp32`.


### Benchmarks

w/ `USE_FAST_MATH` and `WOLFSSL_SMALL_STACK` options

Software only implementation :

```
AES-128-CBC-enc      1 MB took 1.001 seconds,    1.146 MB/s
AES-128-CBC-dec      1 MB took 1.017 seconds,    1.104 MB/s
AES-192-CBC-enc      1 MB took 1.018 seconds,    1.055 MB/s
AES-192-CBC-dec      1 MB took 1.006 seconds,    1.019 MB/s
AES-256-CBC-enc   1000 KB took 1.000 seconds, 1000.000 KB/s
AES-256-CBC-dec    975 KB took 1.007 seconds,  968.222 KB/s
AES-128-GCM-enc    350 KB took 1.055 seconds,  331.754 KB/s
AES-128-GCM-dec    350 KB took 1.054 seconds,  332.068 KB/s
AES-192-GCM-enc    325 KB took 1.013 seconds,  320.829 KB/s
AES-192-GCM-dec    325 KB took 1.013 seconds,  320.829 KB/s
AES-256-GCM-enc    325 KB took 1.041 seconds,  312.200 KB/s
AES-256-GCM-dec    325 KB took 1.041 seconds,  312.200 KB/s
SHA                  6 MB took 1.004 seconds,    5.714 MB/s
SHA-256              2 MB took 1.006 seconds,    1.747 MB/s
SHA-384              1 MB took 1.011 seconds,    1.159 MB/s
SHA-512              1 MB took 1.009 seconds,    1.161 MB/s
HMAC-SHA             6 MB took 1.001 seconds,    5.634 MB/s
HMAC-SHA256          2 MB took 1.000 seconds,    1.733 MB/s
HMAC-SHA384          1 MB took 1.004 seconds,    1.046 MB/s
HMAC-SHA512          1 MB took 1.002 seconds,    1.048 MB/s
RSA     2048 public         16 ops took 1.056 sec, avg 66.000 ms, 15.152 ops/sec
RSA     2048 private         2 ops took 2.488 sec, avg 1244.000 ms, 0.804 ops/sec
ECC      256 key gen         4 ops took 1.101 sec, avg 275.250 ms, 3.633 ops/sec
ECDHE    256 agree           4 ops took 1.098 sec, avg 274.500 ms, 3.643 ops/sec
ECDSA    256 sign            4 ops took 1.111 sec, avg 277.750 ms, 3.600 ops/sec
ECDSA    256 verify          2 ops took 1.099 sec, avg 549.500 ms, 1.820 ops/sec
```

Hardware Acceleration :


```
AES-128-CBC-enc      6 MB took 1.004 seconds,    5.958 MB/s
AES-128-CBC-dec      5 MB took 1.002 seconds,    5.287 MB/s
AES-192-CBC-enc      6 MB took 1.004 seconds,    5.958 MB/s
AES-192-CBC-dec      5 MB took 1.002 seconds,    5.287 MB/s
AES-256-CBC-enc      6 MB took 1.001 seconds,    5.951 MB/s
AES-256-CBC-dec      5 MB took 1.004 seconds,    5.277 MB/s
AES-128-GCM-enc    375 KB took 1.067 seconds,  351.453 KB/s
AES-128-GCM-dec    375 KB took 1.067 seconds,  351.453 KB/s
AES-192-GCM-enc    350 KB took 1.010 seconds,  346.535 KB/s
AES-192-GCM-dec    350 KB took 1.009 seconds,  346.878 KB/s
AES-256-GCM-enc    350 KB took 1.016 seconds,  344.488 KB/s
AES-256-GCM-dec    350 KB took 1.016 seconds,  344.488 KB/s
SHA                 14 MB took 1.000 seconds,   14.062 MB/s
SHA-256             15 MB took 1.000 seconds,   15.234 MB/s
SHA-384             17 MB took 1.000 seconds,   17.383 MB/s
SHA-512             18 MB took 1.001 seconds,   17.512 MB/s
HMAC-SHA            14 MB took 1.000 seconds,   13.818 MB/s
HMAC-SHA256         15 MB took 1.001 seconds,   14.951 MB/s
HMAC-SHA384         17 MB took 1.001 seconds,   16.683 MB/s
HMAC-SHA512         17 MB took 1.000 seconds,   16.943 MB/s
RSA     2048 public         20 ops took 1.017 sec, avg 50.850 ms, 19.666 ops/sec
RSA     2048 private         4 ops took 1.059 sec, avg 264.750 ms, 3.777 ops/sec
ECC      256 key gen         4 ops took 1.092 sec, avg 273.000 ms, 3.663 ops/sec
ECDHE    256 agree           4 ops took 1.089 sec, avg 272.250 ms, 3.673 ops/sec
ECDSA    256 sign            4 ops took 1.101 sec, avg 275.250 ms, 3.633 ops/sec
ECDSA    256 verify          2 ops took 1.092 sec, avg 546.000 ms, 1.832 ops/sec
```

Condition  :
- Model    : ESP32-WROOM-32
- CPU Speed: 240Mhz
- ESP-IDF  : v3.3-beta1-39-g6cb37ecc5(commit hash : 6cb37ecc5)
- OS       : Ubuntu 18.04.1 LTS (Bionic Beaver)

## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
