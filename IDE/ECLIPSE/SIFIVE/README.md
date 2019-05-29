# SiFive RISC-V HiFive Port
## Overview
You can enable the wolfSSL support for RISC-V using the `#define WOLFSSL_SIFIVE_RISC_V`.

## Prerequisites
1. Follow the instructions on the SiFive GitHub [here](https://github.com/sifive/freedom-e-sdk) and SiFive website [here](https://www.sifive.com/) to download the freedom-e-sdk and software tools.
3. Run a simple hello application on your development board to confirm that your board functions as expected and the communication between your computer and the board works.

## Usage
You can start with a wolfcrypt example project to integrate the wolfSSL source code.
wolfSSL supports a compile-time user configurable options in the `IDE/ECLIPSE/SIFIVE/user_settings.h` file.

The `IDE/ECLIPSE/SIFIVE/main.c` example application provides a function to run the selected examples at compile time through the following two #defines in user_settings.h. You can define these macro options to disable the test run.
```
- #undef NO_CRYPT_TEST
- #undef NO_CRYPT_BENCHMARK
```
## Tested Configurations
- SHA-1
- SHA-256
- AES CBC
- ECC sign/verify/shared secret with fast math library

## Setup
### Setting up the SDK with wolfSSL
1. Download the wolfSSL source code or a zip file from GitHub and place it under your SDK `$HOME` directory. You can also copy or simlink to the source.
```
  For example,
  $ cd $HOME
  $ git clone --depth=1 https://github.com/wolfSSL/wolfssl.git

```
2. Copy the wolfcrypt example project into your `freedom-e-sdk/software` directory.

```
  $ cp -rf ~/wolfssl/IDE/ECLIPSE/SIFIVE ~/freedom-e-sdk/software/wolfcrypt
```

3. Edit your `~/freedom-e-sdk/scripts/standalone.mk` and add the following line after the last RISCV_CFLAGS entry:

```
  RISCV_CFLAGS += -I$(WOLFSSL_SRC_DIR) -I$(WOLFSSL_SRC_DIR)/IDE/ECLIPSE/SIFIVE -DWOLFSSL_USER_SETTINGS
```

4. WOLFSSL_SRC_DIR variable must be set in the environment when GNU make is started.

```
  $ export WOLFSSL_SRC_DIR=~/wolfssl
```

5. Setup your riscv64 compiler 

```
  $ export RISCV_OPENOCD_PATH=/opt/riscv-openocd
```
6. (Optional) Setup OpenOCD if your target supports it:

```
  $ export RISCV_OPENOCD_PATH=/opt/riscv-openocd
```
## Building and Running

You can build from source or create a static library.

1. Using command-line:

```
  $ cd freedom-e-sdk
  $ make PROGRAM=wolfcrypt TARGET=sifive-hifive1-revb CONFIGURATION=debug clean software upload
```
This example cleans, builds and uploads the software on the sifive-hifive1-revb target but you can also combine and build for any of the supported targets. 

Review the test results on the target console.

2. Building a static library for RISC-V using a cross-compiler:

```
$ cd $WOLFSSL_SRC_DIR

$./configure --host=riscv64-unknown-elf  \
CC=riscv64-unknown-elf-gcc \
AR=riscv64-unknown-elf-ar \
AS=riscv64-unknown-elf-as \
RANLIB=$RISCV_PATH/bin/riscv64-unknown-elf-gcc-ranlib \
LD=riscv64-unknown-elf-ld \
CXX=riscv64-unknown-elf-g++ \
--disable-examples --enable-static --disable-shared \
CFLAGS="-march=rv32imac -mabi=ilp32 -mcmodel=medlow -ffunction-sections -fdata-sections -I~/freedom-e-sdk/bsp/sifive-hifive1/install/include -O0 -g -DNO_FILESYSTEM -DWOLFSSL_NO_SOCK -DNO_WRITEV -DWOLFCRYPT_ONLY -DWOLFSSL_SIFIVE_RISC_V"

$make
$sudo make install
```
You can now build and link your software to the wolfSSL libwolfssl.a static library.

### `wolfcrypt_test()`
wolfcrypt_test() prints a message on the target console similar to the following output:
```
wolfCrypt Test Started
error    test passed!
base64   test passed!
asn      test passed!
SHA      test passed!
SHA-256  test passed!
Hash     test passed!
HMAC-SHA test passed!
HMAC-SHA256 test passed!
GMAC     test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-GCM  test passed!
RANDOM   test passed!
ECC      test passed!
ECC buffer test passed!
logging  test passed!
mutex    test passed!
Test complete
...
wolfCrypt Test Completed
```
### `benchmark_test()`
benchmark_test() prints a message on the target console similar to the following output.
TARGET=sifive-hifive1-revb:
```
------------------------------------------------------------------------------
 wolfSSL version 4.0.0
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                 25 KB took 3.000 seconds,    8.333 KB/s
AES-128-CBC-enc     25 KB took 16.000 seconds,    1.562 KB/s
AES-128-CBC-dec     25 KB took 17.000 seconds,    1.471 KB/s
AES-192-CBC-enc     25 KB took 19.000 seconds,    1.316 KB/s
AES-192-CBC-dec     25 KB took 18.000 seconds,    1.389 KB/s
AES-256-CBC-enc     25 KB took 20.000 seconds,    1.250 KB/s
AES-256-CBC-dec     25 KB took 21.000 seconds,    1.190 KB/s
AES-128-GCM-enc     25 KB took 30.000 seconds,    0.833 KB/s
AES-128-GCM-dec     25 KB took 30.000 seconds,    0.833 KB/s
AES-192-GCM-enc     25 KB took 32.000 seconds,    0.781 KB/s
AES-192-GCM-dec     25 KB took 32.000 seconds,    0.781 KB/s
AES-256-GCM-enc     25 KB took 34.000 seconds,    0.735 KB/s
AES-256-GCM-dec     25 KB took 34.000 seconds,    0.735 KB/s
SHA                 50 KB took 1.000 seconds,   50.000 KB/s
SHA-256             25 KB took 1.000 seconds,   25.000 KB/s
HMAC-SHA            50 KB took 1.000 seconds,   50.000 KB/s
HMAC-SHA256         25 KB took 1.000 seconds,   25.000 KB/s
ECC      256 key gen         1 ops took 11.000 sec, avg 11000.000 ms, 0.091 ops/sec
ECDHE    256 agree           2 ops took 22.000 sec, avg 11000.000 ms, 0.091 ops/sec
ECDSA    256 sign            2 ops took 23.000 sec, avg 11500.000 ms, 0.087 ops/sec
ECDSA    256 verify          2 ops took 45.000 sec, avg 22500.000 ms, 0.044 ops/sec
Benchmark complete
```
TARGET=sifive-hifive1
```
------------------------------------------------------------------------------
 wolfSSL version 4.0.0
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                 25 KB took 2.000 seconds,   12.500 KB/s
AES-128-CBC-enc     25 KB took 17.000 seconds,    1.471 KB/s
AES-128-CBC-dec     25 KB took 17.000 seconds,    1.471 KB/s
AES-192-CBC-enc     25 KB took 18.000 seconds,    1.389 KB/s
AES-192-CBC-dec     25 KB took 18.000 seconds,    1.389 KB/s
AES-256-CBC-enc     25 KB took 20.000 seconds,    1.250 KB/s
AES-256-CBC-dec     25 KB took 20.000 seconds,    1.250 KB/s
AES-128-GCM-enc     25 KB took 31.000 seconds,    0.806 KB/s
AES-128-GCM-dec     25 KB took 30.000 seconds,    0.833 KB/s
AES-192-GCM-enc     25 KB took 33.000 seconds,    0.758 KB/s
AES-192-GCM-dec     25 KB took 33.000 seconds,    0.758 KB/s
AES-256-GCM-enc     25 KB took 34.000 seconds,    0.735 KB/s
AES-256-GCM-dec     25 KB took 35.000 seconds,    0.714 KB/s
SHA                 50 KB took 1.000 seconds,   50.000 KB/s
SHA-256             25 KB took 1.000 seconds,   25.000 KB/s
HMAC-SHA            25 KB took 1.000 seconds,   25.000 KB/s
HMAC-SHA256         25 KB took 1.000 seconds,   25.000 KB/s
ECC      256 key gen         1 ops took 12.000 sec, avg 12000.000 ms, 0.083 ops/sec
ECDHE    256 agree           2 ops took 24.000 sec, avg 12000.000 ms, 0.083 ops/sec
ECDSA    256 sign            2 ops took 25.000 sec, avg 12500.000 ms, 0.080 ops/sec
ECDSA    256 verify          2 ops took 48.000 sec, avg 24000.000 ms, 0.042 ops/sec
Benchmark complete
```
## Known Caveats
- If you find the wolfcrypt test stuck on early_trap_vector error, it is like related to memory issues
- Using the `__stack_size` default value of 0x400 will not be enough for the ECC test to pass.
The `IDE/ECLIPSE/SIFIVE/Makefile` overwrites the value with 0x1000 (4 KBytes)
- Enabling RSA will cause the ECC test to fail due to memory shortage

## References
The test results were collected from a SiFive reference platform target with the following hardware, software and tool chains:
- HiFive1 Rev A/Rev B: HiFive1 Development Board with the Freedom Everywhere SoC, E300
- freedom-e-sdk
- wolfssl [latest version](https://github.com/wolfSSL/wolfssl)

For more information or questions, please email [support@wolfssl.com](mailto:support@wolfssl.com)
