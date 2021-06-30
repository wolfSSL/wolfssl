Zephyr Project Port
===================

## Overview

This port is for Zephyr Project available [here](https://www.zephyrproject.org/).

It provides the following zephyr code.

- modules/crypto/wolfssl
    - wolfssl library code
- zephyr/modules/crypto/wolfssl
    - Configuration and make files for wolfSSL
- zephyr/samples/modules/wolfssl_test
    - wolfcrypt unit test application
- zephyr/samples/modules/wolfssl_tls_sock
    - socket based sample of TLS
- zephyr/samples/modules/wolfssl_tls_thread
    - socket based sample of TLS using threads

## How to setup

### deploy wolfssl source to zephyr project
Specify the path of the zephyr project and execute  `wolfssl/IDE/zephyr/setup.sh`.

```bash
./IDE/zephyr/setup.sh　/path/to/zephyrproject
```

This script will deploy wolfssl's library code, configuration and samples as described in the Overview to the zephyr project.

## build & test

build and execute wolfssl_test

```
cd [zephyrproject]
west build -p auto -b qemu_x86 zephyr/samples/modules/wolfssl_test
west build -t run
```

