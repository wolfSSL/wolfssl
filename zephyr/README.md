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

## How to setup - automated

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


## How to setup - step by step

export ZEPHYR_DIR=<Zephyr project directory>
export WOLFSSL_DIR=<wolfSSL directory>

### Install wolfSSL library code

```
(cd lib; ./install_lib.sh $ZEPHYR_DIR)
```

or

```
mkdir -p $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/library/src
mkdir -p $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/library/wolfcrypt/src
mkdir -p $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/include

cp -r lib/* $ZEPHYR_DIR/modules/crypto/wolfssl
mv $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/zephyr $ZEPHYR_DIR/modules/crypto/wolfssl/zephyr

cp -rf $WOLFSSL_DIR/src/*.c $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/library/src/
cp -rf $WOLFSSL_DIR/wolfcrypt/src/*.c $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/library/wolfcrypt/src/
cp -rf $WOLFSSL_DIR/wolfcrypt/src/*.i $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/library/wolfcrypt/src/
cp -rf $WOLFSSL_DIR/wolfcrypt/src/*.S $ZEPHYR_DIR/modules/crypto/wolfssl/wolfssl/library/wolfcrypt/src/

cp lib/user_settings.h $ZEPHYR_DIR/modules/crypto/wolfssl/include
cp -rf $WOLFSSL_DIR/wolfssl $ZEPHYR_DIR/modules/crypto/wolfssl/include
rm -f $ZEPHYR_DIR/modules/crypto/wolfssl/include/wolfssl/options.h
touch $ZEPHYR_DIR/modules/crypto/wolfssl/include/wolfssl/options.h
rm -rf $ZEPHYR_DIR/modules/crypto/wolfssl/include/wolfssl/wolfcrypt/port
```

### Install wolfSSL mdule (build system hooks)

```
(cd module; ./install_module.sh $ZEPHYR_DIR)
```

or

```
mkdir $ZEPHYR_DIR/zephyr/modules/crypto/wolfssl;
cp module/* $ZEPHYR_DIR/zephyr/modules/crypto/wolfssl/
```

### Add wolfSSL to west

Add the following lines in 'projects' to: $ZEPHYR_DIR/zephyr/west.yml 

```
    - name: wolfssl
      path: modules/crypto/wolfssl
```

### Install wolfSSL example wolfssl_test

```
(cd wolfssl_test; ./install_test.sh $ZEPHYR_DIR)
```

or

```
cp wolfssl_test $ZEPHYR_DIR/zephyr/samples/modules
mkdir $ZEPHYR_DIR/zephyr/samples/modules/src
cp $WOLFSSL_DIR/wolfcrypt/test/test.c $ZEPHYR_DIR/zephyr/samples/modules/src
cp $WOLFSSL_DIR/wolfcrypt/test/test.h $ZEPHYR_DIR/zephyr/samples/modules/src
```

### Install wolfSSL example wolfssl_tls_sock

```
(cd wolfssl_tls_sock; ./install_sample.sh $ZEPHYR_DIR)
```

or

```
cp wolfssl_tls_sock $ZEPHYR_DIR/zephyr/samples/modules
```

### Install wolfSSL example wolfssl_tls_thread

```
(cd wolfssl_tls_thread; ./install_sample.sh $ZEPHYR_DIR)
```

or

```
cp wolfssl_tls_thread $ZEPHYR_DIR/zephyr/samples/modules
```

