# ARM® TrustZone® CryptoCell 310 Port
## Overview
ARM® TrustZone® CryptoCell 310 is a security subsystem which provides root of trust (RoT) and cryptographic services for a device.
You can enable the wolfSSL support for ARM CryptoCell using the `#define WOLFSSL_CRYPTOCELL`, The CryptoCell APIs are distributed as part of the Nordic nRF5 SDKs [here](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v15.0.0%2Fgroup__cryptocell__api.html) .

## Prerequisites
1. Follow the Nordic website [here](https://www.nordicsemi.com/Software-and-Tools/Software/nRF5-SDK) to download the Nordic nRF5-SDK and software tools.
2. Install the SEGGER Embedded Studio IDE.
3. Run a simple blinky application on your Nordic nRF52840 (PCA10056) development board to confirm that your board functions as expected and the communication between your computer and the board works.

## Usage
You can start with a wolfcrypt SEGGER embedded studio (ses) example project to integrate the wolfSSL source code.
wolfSSL supports a compile-time user configurable options in the `IDE/CRYPTOCELL/user_settings.h` file.

The `IDE/CRYPTOCELL/main.c` example application provides a function to run the selected examples at compile time through the following two #defines in user_settings.h. You can define these macro options to disable the test run.
```
- #undef NO_CRYPT_TEST
- #undef NO_CRYPT_BENCHMARK
```

## Supported features
- SHA-256
- AES CBC
- CryptoCell 310 RNG
- RSA sign/verify and RSA key gen (2048 bit in PKCSv1.5 padding mode)
- RSA encrypt/decrypt
- ECC sign/verify/shared secret
- ECC key import/export and key gen pairs
- Hardware RNG
- RTC for benchmark timing source

Note: All Cryptocell features are not supported. The wolfcrypt RSA API allows import and export of Private/Public keys in DER format. However, this is not possible with key pairs generated with Cryptocell because the importing/exporting Cryptocell keys has not been implemented yet.

## Build options

**`WOLFSSL_NO_RSA_SW`**

Builds RSA with no wolfCrypt software implementation: the software modular
exponentiation, the prime search behind `wc_MakeRsaKey()` and the software key
consistency check (`wc_CheckRsaKey()`, forced off along with
`WOLFSSL_RSA_KEY_CHECK`) are left out of the build, and CryptoCell performs
every RSA operation. When RSA-PSS is not enabled, the PKCS#1 padding
generation and the OAEP/PSS mask-generation and un-padding helpers are dropped
as well; on a CC310 build that takes `rsa.o` from roughly 12.8 KB to 6.1 KB.

This works because the CryptoCell arms in `rsa.c` already hand all four padded
operations to CRYS (`cc310_RsaPublicEncrypt()`, `cc310_RsaSSL_Sign()`,
`cc310_RsaPublicDecrypt()`, `cc310_RsaSSL_Verify()`), generate keys on-chip
with `cc310_RSA_GenerateKeyPair()`, and pad and unpad inside CRYS rather than
on the host.

The raw, unpadded operation (`wc_RsaFunction()` and `wc_RsaDirect()`) has no
CRYS equivalent and returns `NOT_COMPILED_IN`.

Keep in mind that the CryptoCell RSA offload is PKCS#1 v1.5 only. OAEP, PSS and
unpadded requests are not offloaded, so under this macro they have no provider
and return `NOT_COMPILED_IN`; without it they use the wolfCrypt software path,
which needs a key whose private material is in software (a key pair generated
by `cc310_RSA_GenerateKeyPair()` exports only its public part). Prefer PKCS#1
v1.5 on a CryptoCell build.

**`WOLFSSL_NO_ECC_SW`**

The ECC counterpart is accepted on CryptoCell but has no effect: `ecc.c` already
excludes the software ECC implementation - the projective point arithmetic, the
scalar multiplication, the software signer and ECDH, and `wc_ecc_make_pub()` -
for this port unconditionally, so there is nothing left for the macro to remove.
It is in the allow-list only so that a build setting both
`WOLFSSL_NO_RSA_SW` and `WOLFSSL_NO_ECC_SW` for a hardware-only public-key
target is not rejected. What the macro *does* rule out on any port is
`WOLFCRYPT_HAVE_ECCSI`, `WOLFCRYPT_HAVE_SAKKE` and
`WOLFSSL_PUBLIC_ECC_ADD_DBL`, and it drops `EC_POINT_add()`, `EC_POINT_mul()` and
`ECDH_compute_key()` from an `OPENSSL_EXTRA` build, the same way
`WOLFSSL_ATECC508A` does, leaving `EC_POINT_is_at_infinity()` and the
Jacobian-to-affine conversion present but always reporting failure.

Both macros are also available for the NXP SE05x port; see
`wolfcrypt/src/port/nxp/README_SE050.md`.

## Setup
### Setting up Nordic SDK with wolfSSL
1. Download the wolfSSL source code or a zip file from GitHub and place it under your SDK `InstallFolder/external/` directory. You can also copy or simlink to the source.
```
  For example,

  $cd ~/nRF5_SDK_15.2.0_9412b96/external
  $git clone --depth=1 https://github.com/wolfSSL/wolfssl.git

  Or, assuming you have already cloned the wolfSSL source code under ~/wolfssl.

  $cd ~/nRF5_SDK_15.2.0_9412b96/external
  $ln -s  ~/wolfssl wolfssl
```
2. Copy the example project from [here](https://github.com/tmael/nRF5_SDK/tree/master/examples/crypto/nrf_cc310/wolfcrypt) into your `nRF5_SDK_15.2.0_9412b96/examples/crypto/nrf_cc310/` directory.
```
  $git clone https://github.com/tmael/nRF5_SDK.git
  $cd ~/nRF5_SDK_15.2.0_9412b96/examples/crypto/nrf_cc310

  $cp -rf ~/nRF5_SDK/examples/crypto/nrf_cc310/wolfcrypt .
  OR
  $ln -s ~/nRF5_SDK/examples/crypto/nrf_cc310/wolfcrypt wolfcrypt
```
3. Launch the SEGGER Embedded Studio IDE
4. In the main menu, go to File >Open Solutions to open the example solution. Browse to the location containing the wolfcrypt code `/examples/crypto/nrf_cc310/wolfcrypt/pca10056/blank/ses/wolfcrypt_pca10056.emProject` and choose Open.

## Building and Running
In the main menu, go to Build > Rebuild your project, then load and run your image on your nRF52840 target platform. Review the test results on the console output.

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
AES      test passed!
RANDOM   test passed!
RSA      test passed!
ECC      test passed!
ECC buffer test passed!
logging  test passed!
mutex    test passed!
wolfCrypt Test Completed
```
### `benchmark_test()`
benchmark_test() prints a message on the target console similar to the following output.
```
Benchmark Test Started
------------------------------------------------------------------------------
 wolfSSL version 3.15.7
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                  5 MB took 1.000 seconds,    4.858 MB/s
AES-128-CBC-enc     17 MB took 1.001 seconds,   17.341 MB/s
AES-128-CBC-dec     17 MB took 1.000 seconds,   17.285 MB/s
SHA                425 KB took 1.040 seconds,  408.654 KB/s
SHA-256             26 MB took 1.000 seconds,   25.903 MB/s
HMAC-SHA           425 KB took 1.049 seconds,  405.148 KB/s
HMAC-SHA256         24 MB took 1.000 seconds,   23.877 MB/s
RSA     1024 key gen         2 ops took 1.579 sec, avg 789.500 ms, 1.267 ops/sec
RSA     2048 key gen         1 ops took 9.695 sec, avg 9695.000 ms, 0.103 ops/sec
RSA     2048 public        328 ops took 1.001 sec, avg 3.052 ms, 327.672 ops/sec
RSA     2048 private         4 ops took 1.713 sec, avg 428.250 ms, 2.335 ops/sec
ECC      256 key gen        55 ops took 1.017 sec, avg 18.491 ms, 54.081 ops/sec
ECDHE    256 agree          56 ops took 1.017 sec, avg 18.161 ms, 55.064 ops/sec
ECDSA    256 sign           50 ops took 1.004 sec, avg 20.080 ms, 49.801 ops/sec
ECDSA    256 verify         48 ops took 1.028 sec, avg 21.417 ms, 46.693 ops/sec
Benchmark Test Completed
```

## References
The test results were collected from an nRF52840 reference platform target with the following software and tool chains:
- Nordic nRF52840 development board (PCA10056 1.0.0 2018.49 683529999).
- nRF5_SDK_15.2.0_9412b96
- SEGGER Embedded Studio for ARM, Release 4.12  Build 2018112601.37855 Linux x64Segger J-Link software
- gcc-arm-none-eabi-8-2018-q4-major
- wolfssl [latest version](https://github.com/wolfSSL/wolfssl)

For more information or questions, please email [support@wolfssl.com](mailto:support@wolfssl.com)
