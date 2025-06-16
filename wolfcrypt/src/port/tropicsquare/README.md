# wolfSSL TROPIC01 Secure Element Integration Guide

![wolfSSL+TROPIC01](https://img.shields.io/badge/wolfSSL-TROPIC01-blue)


Integration guide for using Tropic Square's TROPIC01 secure element with wolfSSL/wolfCrypt cryptography library.

## Table of Contents
- [wolfSSL TROPIC01 Secure Element Integration Guide](#wolfssl-tropic01-secure-element-integration-guide)
  - [Table of Contents](#table-of-contents)
  - [TROPIC01 Secure Element with an open architecture](#tropic01-secure-element-with-an-open-architecture)
  - [Hardware Overview](#hardware-overview)
    - [TROPIC01 Specifications](#tropic01-specifications)
    - [Available Evaluation and Development Kits](#available-evaluation-and-development-kits)
    - [Get samples](#get-samples)
  - [Build Configuration](#build-configuration)
    - [Pre-requirements](#pre-requirements)
    - [Keys installation](#keys-installation)
    - [Build TROPIC01 SDK (libtropic)](#build-tropic01-sdk-libtropic)
    - [Build wolfSSL](#build-wolfssl)
    - [Build test application](#build-test-application)

## TROPIC01 Secure Element with an open architecture

The TROPIC01 secure element is built with tamper-proof technology and advanced attack countermeasures to ensure robust asset protection, securing electronic devices against a wide range of potential attacks. It securely supplies and stores the cryptographic keys of embedded solutions.
The TROPIC01 datasheet is available via [this link](https://github.com/tropicsquare/tropic01/blob/main/doc/datasheet/ODD_tropic01_datasheet_revA6.pdf)

## Hardware Overview

### TROPIC01 Specifications
- **Crypto Accelerators**:
  - Elliptic curve cryptography
  - Ed25519 EdDSA signing
  - P-256 ECDSA signing
  - Diffie-Hellman X25519 key exchange
  - Keccak-based PIN authentication engine
- **Tamper Resistance**:
  - Voltage glitch detector
  - Temperature detector
  - Electromagnetic pulse detector
  - Laser detector
  - Active shield
- **Interface to Host MCU/MPU**:
  - SPI
  - Encrypted channel with forward secrecy
- **Entropy Source**:
  - Physically Unclonable Function (PUF)
  - True Random Number Generator (TRNG)

### Available Evaluation and Development Kits
- USB Stick with TROPIC01 ([here](https://github.com/tropicsquare/tropic01?tab=readme-ov-file#usb-stick-with-tropic01))
- Raspberry PI shield ([here](https://github.com/tropicsquare/tropic01?tab=readme-ov-file#rpi-shield-ts1501))
- Arduino shield ([here](https://github.com/tropicsquare/tropic01?tab=readme-ov-file#arduino-shield-ts14))

### Get samples
To get samples and DevKits, please fill in [this form](https://tropicsquare.com/tropic01-samples#form)

## Build Configuration

### Pre-requirements
1. Get one of the targeted hardware platforms. For example, Linux PC + TROPIC01 USB stick or Raspberry PI 3/4/5 + TROPIC01 RPI shield
2. Install toolchain (incl. compiler or cross-compiler). For example,  GNU Toolchain (gcc) or ARM cross-compiling toolchain (armv8-rpi3-linux-gnueabihf)
3. Install CMake and Autotools
4. Install Git

  Some guidelines for RPi are available [here](https://earthly.dev/blog/cross-compiling-raspberry-pi/)

Also, for Raspberry PI, there are a few more steps:

1.  In raspi-config go to "Interface Options" and enable SPI
2.  Install wiringPI:

```sh
$ wget https://github.com/WiringPi/WiringPi/releases/download/3.14/wiringpi_3.14_arm64.deb
$ sudo apt install ./wiringpi_3.14_arm64.deb
```

### Keys installation

For the integration with wolfSSL, there are a few pre-defined slots for the secure keys storage (the slots mapping might be changed in tropic01.h):
```sh
TROPIC01_AES_KEY_RMEM_SLOT 0 // slot in R-memory for AES key
TROPIC01_AES_IV_RMEM_SLOT 1 // slot in R-memory for AES IV
TROPIC01_ED25519_PUB_RMEM_SLOT_DEFAULT 2 // slot in R-memory for ED25519 Public key
TROPIC01_ED25519_PRIV_RMEM_SLOT_DEFAULT 3 //slot in R-memory for ED25519 Private key
TROPIC01_ED25519_ECC_SLOT_DEFAULT 1 // slot in ECC keys storage for both public and private keys
PAIRING_KEY_SLOT_INDEX_0 0 //pairing keys slot
```
All R-memory based keys must be pre-provisioned in the TROPIC01 Secure Element separately. For example, it might be done with the libtropic-util tool available [here] (https://github.com/tropicsquare/libtropic-util)

### Build TROPIC01 SDK (libtropic)

wolfSSL uses the "TROPIC01 SDK" (aka libtropic) to interface with TROPIC01. This SDK can be cloned from the TropicSquare GitHub https://github.com/tropicsquare/libtropic

Once the repo was downloaded, please follow [this guideline](https://github.com/tropicsquare/libtropic/blob/master/docs/index.md#integration-examples) on how to configure and build TROPIC01 SDK

Or run the following commands:
```sh
  $ git clone https://github.com/tropicsquare/libtropic.git
  $ cd libtropic
  $ mkdir build && cd build
  $ cmake -DLT_USE_TREZOR_CRYPTO=1 ..
  $ make
```

### Build wolfSSL
1. Clone wolfSSL from the wolfSSL GitHub (https://github.com/wolfSSL/wolfssl)

2. Make sure that the version of wolfSSL supports TROPIC01 - check if the folder wolfssl/wolfcrypt/src/port/tropicsquare exists

3. To compile wolfSSL with TROPIC01 support using Autoconf/configure:

```sh
$ cd wolfssl
$ ./autogen.sh
$ ./configure --with-tropic01=PATH --enable-cryptocb --enable-static --disable-crypttests --disable-examples --disable-shared --enable-ed25519
$ make
$ sudo make install
```
where PATH is an absolute path to the libtropic folder, for example

    --with-tropic01=/home/pi/git/libtropic

For the debugging output, add

    --enable-debug

### Build test application

The test application for Raspberry Shield and USB stick can be cloned from the TropicSquare GitHub https://github.com/tropicsquare/tropic01-wolfssl-test

To build and run the test application, please run the following commands

```sh
$ git clone git@github.com:tropicsquare/tropic01-wolfssl-test.git
$ cd tropic01-wolfssl-test
```
If necessary, open and edit the Makefile in this folder

Set correct values for CC and LIBTROPIC_DIR variables, for example:

    CC = gcc

    LIBTROPIC_DIR = /home/pi/git/libtropic

Then run the following commands to build and run the test application for the USB stick:

```sh
$ make
$ ./lt-wolfssl-test
```
or for Raspberry PI shield (make sure you fulfill all prerequisites first):


```sh
$ make RPI_SPI=1
$ ./lt-wolfssl-test
```

In case of success, the output of the test application should look like this:

```sh
wolfSSL Crypto Callback Test Application
========================================
wolfSSL Entering wolfCrypt_Init
TROPIC01: Crypto device initialized successfully
wolfCrypt initialized successfully
Registering crypto callback with device ID 481111...
Crypto callback registered successfully
RNG_HEALTH_TEST_CHECK_SIZE = 128
sizeof(seedB_data)         = 128
TROPIC01: CryptoCB: SEED generation request (52 bytes)
TROPIC01: GetRandom: Requesting 52 bytes
TROPIC01: GetRandom: Completed with ret=0
TROPIC01: CryptoCB: RNG generation request (32 bytes)
TROPIC01: GetRandom: Requesting 32 bytes
TROPIC01: GetRandom: Completed with ret=0
Generated 32 random bytes:
94F589E8 9C59B5A2 C8426FB6 9C548623
358551CE 07238D37 EBF7FEE5 42BEB299

RNG test completed successfully

AES test starting:
TROPIC01: CryptoCB: AES request
TROPIC01: Get AES Key: Retrieving key from slot 1
TROPIC01: Get AES Key: Key retrieved successfully
Plain message:
01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
Encrypted message:
89 44 11 3E 2E 07 52 9C CB 5F B1 70 7E 9C 42 D6
AES test completed successfully

ED25519 COMPREHENSIVE TESTING SUITE

=== Ed25519 Key Generation Test ===
✓ Ed25519 key structure initialized successfully
TROPIC01: CryptoCB: RNG generation request (32 bytes)
TROPIC01: GetRandom: Requesting 32 bytes
TROPIC01: GetRandom: Completed with ret=0
✓ Ed25519 key pair generated successfully
Generated Public Key (32 bytes):
5D28BB98 AF86844E 5C2D48B6 473EA116
0A98B568 3313915D 1565C540 AA3EB250
✓ Ed25519 key generation test completed successfully

=== Ed25519 Message Signing Test ===
DEV_ID: 481111
TROPIC01: CryptoCB: RNG generation request (64 bytes)
TROPIC01: GetRandom: Requesting 64 bytes
TROPIC01: GetRandom: Completed with ret=0
Test Message (64 bytes):
000CD9C2 0FA2E218 67737744 4550F217
5082408B 9F21F92B 06A570C4 C18AA073
1B23836F 1CDC760B 7242F8A7 83B8EC9A
BF9E6D84 2E605AA1 0A168E88 FDEF38DA
TROPIC01: CryptoCB: ED25519 signing request
TROPIC01: Get ECC Key: Retrieving key from slot 3
TROPIC01: Get ECC Key: Key retrieved successfully
✓ Message signed successfully
Signature length: 64 bytes
Generated Signature (64 bytes):
AE4B42CF 46F8F369 4F559390 0EDDA701
A73A562B 3D03F429 8706309D 63E2120B
82B2A91F 6D7A7519 0CD62215 CABE3183
433F4125 2CC017EB BD1E59A1 4A22CC09
✓ Ed25519 message signing test completed successfully
wolfSSL Entering wolfCrypt_Cleanup
```



