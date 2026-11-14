# ESP32 Port

Support for the ESP32 on-board cryptographic hardware acceleration for symmetric AES, SHA1/SHA256/SHA384/SHA512 and RSA primitive including mul, mulmod and exptmod.

* ESP32 - Supported
* ESP32S2 - Supported
* ESP32S3 - Supported
* ESP32C2 - Software only (contact support to request hardware acceleration)
* ESP32C3 - Supported
* ESP32C5 - Supported
* ESP32C6 - Supported
* ESP32H2 - Software only (contact support to request hardware acceleration)

ESP32-C5 hardware acceleration requires ESP-IDF 6.x and includes SHA384,
SHA512, SHA512/224 and SHA512/256; these algorithms are not disabled for
ESP32-C5 in `user_settings.h`. Older IDF releases build in software-only mode.

### ESP32-C5 ECC and ECDSA

The ESP32-C5 port additionally supports general ECC operations for SECP192R1,
SECP256R1 and SECP384R1, transparent ECDSA signature verification, and opaque
ECDSA signing and public-key export using eFuse or Key Manager keys. Private
keys used by the opaque interface remain in the hardware; only the public key
is exported.

ECDSA signing with an ordinary wolfCrypt private key is performed by wolfCrypt
software, with the ECC point multiplication accelerated by the ESP32-C5
hardware. Transparent ECDSA verification uses the hardware directly.

The following optional macros disable the corresponding ESP32-C5 hardware
support:

* `NO_WOLFSSL_ESP32_CRYPT_ECC`: disable general ECC point multiplication.
* `NO_WOLFSSL_ESP32_CRYPT_ECDSA`: disable hardware ECDSA verification and
  opaque ECDSA support.
* `NO_WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE`: disable only opaque eFuse and Key
  Manager support, leaving transparent verification enabled.

Opaque ECDSA support requires the ESP-IDF `esp_security` and `mbedtls`
components, and both of these ESP-IDF configuration options:

```text
CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN=y
CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY=y
```

**wolfSSL never burns eFuses.** eFuse and Key Manager provisioning must be
performed independently as a separate, deliberate manual step before using
opaque keys. The library only uses keys that have already been provisioned.

## ESP32 Acceleration

More details about ESP32 HW Acceleration can be found in:

* `esp32_technical_reference_manual_en.pdf`
* `esp32-s2_technical_reference_manual_en.pdf`
* `esp32-s3_technical_reference_manual_en.pdf`
* `esp8684_technical_reference_manual_en.pdf`
* `esp32-c3_technical_reference_manual_en.pdf`
* `esp32-c5_technical_reference_manual_en.pdf`
* `esp32-c6_technical_reference_manual_en.pdf`
* `esp32-h2_technical_reference_manual_en.pdf`

### Building

Simply run `ESP-IDF.py` in any of the [Espressif/ESP-IDF/Examples](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples).

For an optional on-device eFuse ECDSA test, first provision a throwaway
P-256 key with the `ECDSA_KEY_P256` purpose in a dedicated, empty KEY block,
then define `WOLFSSL_ESP32C5_TEST_EFUSE_BLOCK` to that block number. The test
signs and verifies repeatedly with the original and a copied opaque key,
exports the public key, and checks that private-key export is rejected. It
never provisions, erases, or write-protects eFuse. Do not use production keys
for this test.

A separate `WOLFSSL_ESP32C5_TEST_KM` option deploys a random, throwaway P-256
key through the Key Manager AES mode using a software init key, then checks
signing, verification and private-export rejection. This test uses no NVS and
does not burn eFuse.

`WOLFSSL_ESP32C5_TEST_SHA_COPY` verifies SHA-224, SHA-384 and SHA-512/224
active hardware copies by continuing both source and destination contexts and
comparing known digests. `WOLFSSL_ESP32C5_TEST_SHA_LOCK` repeatedly abandons
active SHA-224/256/384/512 contexts without finalizing them and verifies in
hardware mode that later hashes reacquire the engine. It requires all four hash
algorithms and their hardware acceleration; other configurations return
`NOT_COMPILED_IN` instead of passing through software fallback. Define
`WOLFSSL_ESP32C5_TEST_MULTITHREADED` as well to exercise the FreeRTOS
same-task owner path instead of the example's default `SINGLE_THREADED` build.
`WOLFSSL_ESP32C5_TEST_ECC_CURVES` checks SECP192R1, PRIME192V2 and PRIME192V3
key generation, signing and verification; it also requires `HAVE_ECC192`,
`ECC_MIN_KEY_SZ=192`, `HAVE_ECC_SECPR2` and `HAVE_ECC_SECPR3`. These tests need
no eFuse or Key Manager access. Keep all optional hardware tests disabled
except on a dedicated test board.

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
