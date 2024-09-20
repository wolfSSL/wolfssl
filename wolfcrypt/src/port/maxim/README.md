wolfSSL using Analog Devices MAXQ1065, MAX1080, MAX32665 or MAX32666
================================================

## Overview

wolfSSL can be configured to use the MAXQ1065 or MAX1080 cryptographic
controllers. wolfSSL can also be configure to utilize the TPU
(crypto accelerator), MAA (math accelerator), and TRNG available on select
MAX32665 and MAX32666 microcontroller.

Product datasheets, user guides and other resources can be found at
Analog Devices website:

https://www.analog.com

# MAX32665/MAX32666
## Build and Usage

wolfSSL supports the [Maxim SDK](https://github.com/analogdevicesinc/msdk), to
utilize the TPU and MAA located on the devices.

Building is supported by adding `#define WOLFSSL_MAX3266X` to `user_settings.h`.
wolfSSL supports the usage of the older style API Maxim provides with the
`#define WOLFSSL_MAX3266X_OLD` to `user_settings.h`.

When using `WOLFSSL_MAX3266X` or `WOLFSSL_MAX3266X_OLD` you will also need to
add `#define WOLFSSL_SP_MATH_ALL` to `user_settings.h`.

If you want to be more specific on what hardware acceleration you want to use,
this can be done by adding any combination of these defines:
```
#define MAX3266X_RNG    - Allows usage of TRNG device
#define MAX3266X_AES    - Allows usage of TPU for AES Acceleration
#define MAX3266X_SHA    - Allows usage of TPU for Hash Acceleration
#define MAX3266X_MATH   - Allows usage of MAA for MOD based Math Acceleration
```
For this you will still need to use `#define WOLFSSL_MAX3266X` or `#define WOLFSSL_MAX3266X_OLD`.
When you use a specific hardware define like `#define MAX3266X_RNG` this will
mean only the TRNG device is being used, and all other operations will use the
default software implementations.

The other prerequisite is that a change needs to be made to the Maxim SDK. This
is to use the MAA Math Accelerator, this change only needs to be made if you are
using `#define WOLFSSL_MAX3266X` or `define WOLFSSL_MAX3266X_OLD` by themselves
or you are specifying `#define MAX3266X_MATH`. This is only needed if you are
not using the latest Maxim SDK.

In the SDK you will need to find the underlying function that
`MXC_TPU_MAA_Compute()` from `tpu.h` compute calls in the newer SDK. In the
older SDK this function is called `MAA_Compute()` in `maa.h`. In the underlying
function you will need to this:

```
MXC_SETFIELD(tpu->maa_ctrl, MXC_F_TPU_REVA_MAA_CTRL_CLC, clc);
```
to
```
MXC_SETFIELD(tpu->maa_ctrl, MXC_F_TPU_REVA_MAA_CTRL_CLC,
                clc << MXC_F_TPU_REVA_MAA_CTRL_CLC_POS);
```

This bug has been reported to Analog Devices and a PR has been made
[here](https://github.com/analogdevicesinc/msdk/pull/1104)
if you want to know more details on the issue, or use a patch.


## Supported Algos
Using these defines will replace software implementations with a call to the
hardware.

`#define MAX3266X_RNG`
- Uses entropy from TRNG to seed HASHDRBG

`#define MAX3266X_AES`:

- AES-CBC: 128, 192, 256
- AES-ECB: 128, 192, 256

`#define MAX3266X_SHA`:

- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512

Please note that when using `MAX3266X_SHA` there will be a limitation when
attempting to do a larger sized hash as the SDK for the hardware currently
expects a the whole msg buffer to be given.

`#define MAX3266X_MATH` (Replaces math operation calls for algos
like RSA and ECC key generation):

- mod:      `a mod m = r`
- addmod:   `(a+b)mod m = r`
- submod:   `(a-b)mod m = r`
- mulmod:   `(a*b)mod m = r`
- sqrmod:   `(b^2)mod m = r`
- exptmod:  `(b^e)mod m = r`

## Crypto Callback Support
This port also supports using the Crypto Callback functionality in wolfSSL.
When `WOLF_CRYPTO_CB` is defined in `user_settings.h` along with
`WOLFSSL_MAX3266X` or `WOLFSSL_MAX3266X_OLD` it will build the library to allow
the ability to switch between hardware and software implementations.

Crypto Callbacks only support using the hardware for these Algorithms:

- AES ECB: 128, 192, 256
- AES CBC: 128, 192, 256
- SHA-1
- SHA-256
- SHA-384
- SHA-512

When using `WOLF_CRYPTO_CB` and `WOLFSSL_MAX3266X` or `WOLFSSL_MAX3266X_OLD`,
`MAX3266X_MATH` is turned off and is is currently not supported to use with
`WOLF_CRYPTO_CB`.

The Hardware of the port will be used by default when no devId is set.
To use software versions of the support Callback Algorithms the devId will need
to be set to `INVALID_DEVID`.

For more information about Crypto Callbacks and how to use them please refer to
the [wolfSSL manual](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter06.html).

## Extra Information
For more Verbose info you can use `#define DEBUG_WOLFSSL` in combination with
`#define MAX3266X_VERBOSE` to see if errors are occurring during the hardware
setup/

To reproduce benchmark numbers you can use `#define MAX3266X_RTC`.
Do note that this will only work with `#define WOLFSSL_MAX3266X` and not
`#define WOLFSSL_MAX3266X_OLD`. This is only meant for benchmark reproduction
and not for any other application. Please implement your own rtc/time code for
anything else.

For more information about the TPU, MAA, and TRNG please refer to the
[MAX32665/MAX32666 User Guide: UG6971](https://www.analog.com/media/en/technical-documentation/user-guides/max32665max32666-user-guide.pdf)

# MAXQ1065/MAX1080
## Build and Usage

Please use the appropriate SDK or Evkit to build wolfSSL.

Instructions for setting up the hardware and various other utilities and
prerequisite software and then building and using wolfSSL can be found in the
MAXQ SDK. The SDK is available upon request to Analog Devices.

The Evkit comes with all the other necessary utility software and scripts and
some prerequisite instructions such as how to copy the headers and library
files to the correct location. Once those instructions are followed, you are
ready to build wolfSSL.

To build for MAXQ1065 the following is sufficient:

```
./configure --enable-cryptocb --disable-extended-master --enable-psk \
            --enable-aesccm --enable-debug --disable-tls13 \
            --with-maxq10xx=MAXQ1065
make all
sudo make install
```
To build for MAXQ1080 the following is sufficient:

```
./configure --enable-cryptocb --disable-extended-master --enable-psk \
            --enable-aesccm --enable-debug --with-maxq10xx=MAXQ108x
make all
sudo make install
```

## Example Code

You can find a very simple example client application in our wolfssl-examples
repo on github:

https://github.com/wolfSSL/wolfssl-examples/tree/master/maxq10xx

NOTE: It assumes you have built wolfSSL using the SDK or Evkit.

