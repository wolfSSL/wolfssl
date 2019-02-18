Zephyr Project Port
===================

## Overview

This port is for Zephyr Project available [here](https://www.zephyrproject.org/).

It provides the following zephyr code.

- zephyr/ext/lib/crypto/wolfssl
    - wolfssl library
- zephyr/samples/crypto/wolfssl_test
    - wolfcrypt unit test application
- zephyr/samples/crypto/wolfssl_tls_sock
    - socket based sample of TLS
- zephyr/samples/crypto/wolfssl_tls_thread
    - socket based sample of TLS using threads

## How to setup

### delopy wolfssl source to mynewt project
Specify the path of the mynewt project and execute  `wolfssl/IDE/mynewt/setup.sh`.

```bash
./IDE/zephyr/setup.sh　/path/to/zephyrproject
```

This script will deploy wolfssl's library code and samples as described in the Overview to the zephyr project.

## build & test

build and execute wolfssl_test

```
cd [zephyrproject]/zephyr/samples/crypto/wolfssl_test
mkdir build && cd build
cmake -GNinja -DBOARD=qemu_x86 ..
ninja
ninja run
```

