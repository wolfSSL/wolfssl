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
    - wolfcrypt unit test application
- modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_sock
    - socket based sample of TLS
- modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_thread
    - socket based sample of TLS using threads

## How to setup as a Zephyr Module

### Modify your project's west manifest

Add wolfssl as a project:
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

Update west's modules:

```bash
west update
```

Now west recognizes 'wolfssl' as a module, and will include it's Kconfig and CMakeFiles.txt in the build system.

## Build & test

build and execute wolfssl_test

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/crypto/wolfssl/zephyr/samples/wolfssl_test
west build -t run
```

### Run wolfSSL example wolfssl_tls_sock

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_sock
west build -t run
```

### Run wolfSSL example wolfssl_tls_thread

```
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/crypto/wolfssl/zephyr/samples/wolfssl_tls_thread
west build -t run
```

