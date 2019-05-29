# SiFive RISC-V HiFive1 Port

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
SiFive HiFive1 Demo
Setting clock to 320MHz
Actual Clock 320MHz

error    test passed!
MEMORY   test passed!
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
```
### `benchmark_test()`

benchmark_test() prints a message on the target console similar to the following output.

TARGET=sifive-hifive1-revb:

```
------------------------------------------------------------------------------
 wolfSSL version 4.0.0
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                 12 MB took 1.000 seconds,   11.666 MB/s
AES-128-CBC-enc     50 KB took 1.659 seconds,   30.131 KB/s
AES-128-CBC-dec     50 KB took 1.657 seconds,   30.183 KB/s
AES-192-CBC-enc     50 KB took 1.839 seconds,   27.189 KB/s
AES-192-CBC-dec     50 KB took 1.836 seconds,   27.230 KB/s
AES-256-CBC-enc     25 KB took 1.010 seconds,   24.759 KB/s
AES-256-CBC-dec     25 KB took 1.008 seconds,   24.791 KB/s
AES-128-GCM-enc     25 KB took 1.508 seconds,   16.576 KB/s
AES-128-GCM-dec     25 KB took 1.510 seconds,   16.559 KB/s
AES-192-GCM-enc     25 KB took 1.605 seconds,   15.573 KB/s
AES-192-GCM-dec     25 KB took 1.607 seconds,   15.558 KB/s
AES-256-GCM-enc     25 KB took 1.699 seconds,   14.716 KB/s
AES-256-GCM-dec     25 KB took 1.700 seconds,   14.702 KB/s
SHA                  2 MB took 1.014 seconds,    1.589 MB/s
SHA-256            425 KB took 1.009 seconds,  421.068 KB/s
HMAC-SHA             1 MB took 1.013 seconds,    1.325 MB/s
HMAC-SHA256        425 KB took 1.018 seconds,  417.420 KB/s
ECC      256 key gen         2 ops took 1.393 sec, avg 696.503 ms, 1.436 ops/sec
ECDHE    256 agree           2 ops took 1.386 sec, avg 692.917 ms, 1.443 ops/sec
ECDSA    256 sign            2 ops took 1.406 sec, avg 703.064 ms, 1.422 ops/sec
ECDSA    256 verify          2 ops took 2.773 sec, avg 1386.597 ms, 0.721 ops/sec
Benchmark complete
```

## Tested Configurations
- SHA-1
- SHA-256
- AES CBC/GCM
- ECC 256 sign/verify/shared secret with fast math library

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
