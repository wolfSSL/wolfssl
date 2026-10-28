Zephyr Project Port
===================

## Overview

This port is for the Zephyr RTOS Project, available [here](https://www.zephyrproject.org/).

It provides the following zephyr code.

- modules/crypto/wolfssl
    - wolfssl library code
- modules/crypto/wolfssl/zephyr/
    - Configuration and CMake files for wolfSSL as a Zephyr module
- modules/crypto/wolfssl/zephyr/samples/wolfssl_test
    - wolfCrypt test application
- modules/crypto/wolfssl/zephyr/samples/wolfssl_bench
    - wolfCrypt benchmark application
- modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_sock
    - socket based sample of TLS
- modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_thread
    - socket based sample of TLS using threads

## How to setup as a Zephyr Module

### Modify your project's west manifest

Add wolfssl as a project to your west.yml:
```
manifest:
  remotes:
    # <your other remotes>
    - name: wolfssl
      url-base: https://github.com/wolfssl

  projects:
    # <your other projects>
    - name: wolfssl
      path: modules/crypto/wolfssl
      revision: master
      remote: wolfssl
```

If you are using the Nordic nRF Connect SDK with Zephyr, the sdk-nrf manifest
file is located at: `vX.X.X/nrf/west.yml`. On OSX the default installation
location for the nRF Connect SDK is at `/opt/nordic/ncs/vX.X.X`.

Update west's modules:

```bash
west update
```

Now west recognizes 'wolfssl' as a module, and will include it's Kconfig and
CMakeFiles.txt in the build system.

If using the Nordic nRF Connect SDK, to get access to a terminal with west
tool access, open "nRF Connect for Desktop", then "Toolchain Manager",
and finally next to the SDK version you are using click the drop down arrow,
then "Open Terminal".

## Build and Run wolfCrypt Test Application

If you want to run build apps without running `west zephyr-export` then it is
possible by setting the `CMAKE_PREFIX_PATH` variable to the location of the
zephyr sdk and building from the `zephyr` directory. For example:

```
CMAKE_PREFIX_PATH=/path/to/zephyr-sdk-<VERSION> west build -p always -b qemu_x86 ../modules/crypto/wolfssl/zephyr/samples/wolfssl_test/
```

build and execute `wolfssl_test`

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/crypto/wolfssl/zephyr/samples/wolfssl_test
west build -t run
```

## Build with a wolfCrypt FIPS v5 bundle

In a tree holding a v5 FIPS bundle, select it in `prj.conf`:

```
CONFIG_WOLFCRYPT_FIPS=y
CONFIG_WOLFCRYPT_FIPS_V5=y
CONFIG_WOLFCRYPT_FIPS_V5_2_3=y
CONFIG_LINKER_SORT_BY_ALIGNMENT=n
```

Leave `CONFIG_WOLFCRYPT_FIPS_V5_2_3` out for a 5.2.1 bundle. Every FIPS
boundary needs `CONFIG_LINKER_SORT_BY_ALIGNMENT=n`, which Zephyr defaults on:
the integrity check hashes the boundary as two ranges, and sorting input
sections by alignment moves code out of them, so the build stops while it is
set.

With 5.2.3, `user_settings.h` takes the algorithm set of
`--enable-fips=v5.2.3` from `user_settings-fips-v5.2.3.h`; the TLS and
certificate options still follow Kconfig. Both v5 bundles seed the DRBG from
the `zephyr,entropy` device, or else the Zephyr CSPRNG, and a board with
neither fails the build unless `CONFIG_TEST_RANDOM_GENERATOR` is set. Under
FIPS v2, v5 and v6 `CONFIG_WOLFCRYPT_ASM` accelerates only the SP math: those
boundaries keep their AES and SHA assembly in a form this module does not
build.

## Build and Run wolfCrypt Benchmark Application

build and execute `wolfssl_benchmark`

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/crypto/wolfssl/zephyr/samples/wolfssl_benchmark
west build -t run
```

### Build and Run wolfSSL example `wolfssl_tls_sock`

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_sock
west build -t run
```

### Build and Run wolfSSL example `wolfssl_tls_thread`

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_thread
west build -t run
```

## How to setup wolfSSL support for Zephyr TLS Sockets and RNG

wolfSSL can also be used as the underlying implementation for the default Zephyr TLS socket interface.
With this enabled, all existing applications using the Zephyr TLS sockets will now use wolfSSL inside
for all TLS operations. This will also enable wolfSSL as the default RNG implementation. To enable this
feature, use the patch file and instructions found here:

https://github.com/wolfSSL/osp/tree/master/zephyr

