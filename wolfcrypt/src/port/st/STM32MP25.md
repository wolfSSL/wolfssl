# wolfSSL STM32MP25

The board will boot in Linux as default when you put in the supplied SD card. If you plug in an Ethernet cable, it will get a DHCP and you can ssh as `root` with no password.

These instructions discuss how to cross-compile for the STM32MP25 when it is running OpenSTLinux.

## SDK

You can download the OpenSTLinux compiler / SDK from here:

https://www.st.com/en/embedded-software/stm32mp2dev.html#get-software

Note that the x86 package is a gzip of a `.tar.gz`.

Once extracted, run the `.sh` file as root, it will install in `/opt/st`.

## Compiling wolfSSL for ARM ASM

The following sets up the build environment (CC, CFLAGS, etc...):

```sh
source /opt/st/stm32mp2/5.0.3-openstlinux-6.6-yocto-scarthgap-mpu-v24.11.06/environment-setup-cortexa35-ostl-linux
```

Then this configure command will enable support for the ARM optimized assembly:

```sh
./configure --host=aarch64-linux-gnueabi --enable-sp-asm  --enable-armasm  --enable-all-asm
```

## Compiling wolfSSL for cryptodev

As before, setup build environment:

```sh
source /opt/st/stm32mp2/5.0.3-openstlinux-6.6-yocto-scarthgap-mpu-v24.11.06/environment-setup-cortexa35-ostl-linux
```

The include path for cryptodev doesn't get added automatically, so this needs adding manually:

```sh
export CFLAGS="$CFLAGS -I /opt/st/stm32mp2/5.0.3-openstlinux-6.6-yocto-scarthgap-mpu-v24.11.06/sysroots/cortexa35-ostl-linux/usr/src/debug/cryptodev-module/1.13+git/"
```

Then configure:

```sh
./configure --host=aarch64-linux-gnueabi --enable-sp-asm --enable-devcrypto
```

On the STM32, run `modprobe cryptodev` before executing.

## Benchmarks

### Software

```
------------------------------------------------------------------------------
 wolfSSL version 5.7.6
------------------------------------------------------------------------------
Math:   Multi-Precision: Wolf(SP) word-size=64 bits=4096 sp_int.c
        Single Precision: ecc 256 384 521 rsa/dh 2048 3072 4096 asm sp_arm64.c
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
RNG                         20 MiB took 1.272 seconds,   15.718 MiB/s
AES-128-CBC-enc             30 MiB took 1.043 seconds,   28.760 MiB/s
AES-128-CBC-dec             30 MiB took 1.032 seconds,   29.078 MiB/s
AES-192-CBC-enc             25 MiB took 1.011 seconds,   24.740 MiB/s
AES-192-CBC-dec             30 MiB took 1.194 seconds,   25.130 MiB/s
AES-256-CBC-enc             25 MiB took 1.151 seconds,   21.730 MiB/s
AES-256-CBC-dec             25 MiB took 1.131 seconds,   22.110 MiB/s
AES-128-GCM-enc             20 MiB took 1.167 seconds,   17.132 MiB/s
AES-128-GCM-dec             20 MiB took 1.167 seconds,   17.137 MiB/s
AES-192-GCM-enc             20 MiB took 1.277 seconds,   15.662 MiB/s
AES-192-GCM-dec             20 MiB took 1.277 seconds,   15.659 MiB/s
AES-256-GCM-enc             15 MiB took 1.039 seconds,   14.439 MiB/s
AES-256-GCM-dec             15 MiB took 1.039 seconds,   14.439 MiB/s
GMAC Table 4-bit            42 MiB took 1.003 seconds,   41.876 MiB/s
CHACHA                     130 MiB took 1.015 seconds,  128.047 MiB/s
CHA-POLY                    95 MiB took 1.013 seconds,   93.815 MiB/s
MD5                        130 MiB took 1.013 seconds,  128.367 MiB/s
POLY1305                   355 MiB took 1.011 seconds,  351.276 MiB/s
SHA                         80 MiB took 1.044 seconds,   76.622 MiB/s
SHA-224                     40 MiB took 1.130 seconds,   35.390 MiB/s
SHA-256                     40 MiB took 1.130 seconds,   35.406 MiB/s
SHA-384                     65 MiB took 1.032 seconds,   62.985 MiB/s
SHA-512                     65 MiB took 1.032 seconds,   63.008 MiB/s
SHA-512/224                 65 MiB took 1.032 seconds,   62.995 MiB/s
SHA-512/256                 65 MiB took 1.032 seconds,   63.007 MiB/s
SHA3-224                    55 MiB took 1.025 seconds,   53.643 MiB/s
SHA3-256                    55 MiB took 1.074 seconds,   51.195 MiB/s
SHA3-384                    45 MiB took 1.122 seconds,   40.122 MiB/s
SHA3-512                    30 MiB took 1.053 seconds,   28.493 MiB/s
HMAC-MD5                   130 MiB took 1.018 seconds,  127.760 MiB/s
HMAC-SHA                    80 MiB took 1.044 seconds,   76.632 MiB/s
HMAC-SHA224                 40 MiB took 1.130 seconds,   35.392 MiB/s
HMAC-SHA256                 40 MiB took 1.130 seconds,   35.407 MiB/s
HMAC-SHA384                 65 MiB took 1.036 seconds,   62.720 MiB/s
HMAC-SHA512                 65 MiB took 1.032 seconds,   62.996 MiB/s
PBKDF2                       4 KiB took 1.002 seconds,    4.242 KiB/s
RSA     2048   public      3900 ops took 1.012 sec, avg 0.259 ms, 3855.639 ops/sec
RSA     2048  private       200 ops took 1.720 sec, avg 8.598 ms, 116.307 ops/sec
DH      2048  key gen       226 ops took 1.001 sec, avg 4.431 ms, 225.666 ops/sec
DH      2048    agree       300 ops took 1.328 sec, avg 4.427 ms, 225.890 ops/sec
ECC   [      SECP256R1]   256  key gen      6800 ops took 1.000 sec, avg 0.147 ms, 6797.480 ops/sec
ECDHE [      SECP256R1]   256    agree      1900 ops took 1.018 sec, avg 0.536 ms, 1867.187 ops/sec
ECDSA [      SECP256R1]   256     sign      4700 ops took 1.018 sec, avg 0.217 ms, 4615.200 ops/sec
ECDSA [      SECP256R1]   256   verify      1800 ops took 1.028 sec, avg 0.571 ms, 1750.500 ops/sec
Benchmark complete
```

### Hardware (devcrypto)

```
------------------------------------------------------------------------------
 wolfSSL version 5.7.6
------------------------------------------------------------------------------
Math:   Multi-Precision: Wolf(SP) word-size=64 bits=4096 sp_int.c
        Single Precision: ecc 256 384 521 rsa/dh 2048 3072 4096 asm sp_arm64.c
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
RNG                          5 MiB took 6.168 seconds,    0.811 MiB/s
AES-128-CBC-enc             75 MiB took 1.053 seconds,   71.205 MiB/s
AES-128-CBC-dec             75 MiB took 1.055 seconds,   71.063 MiB/s
AES-192-CBC-enc             75 MiB took 1.051 seconds,   71.370 MiB/s
AES-192-CBC-dec             75 MiB took 1.050 seconds,   71.405 MiB/s
AES-256-CBC-enc             75 MiB took 1.049 seconds,   71.472 MiB/s
AES-256-CBC-dec             75 MiB took 1.051 seconds,   71.332 MiB/s
AES-128-GCM-enc             10 MiB took 1.828 seconds,    5.469 MiB/s
AES-128-GCM-dec             10 MiB took 1.829 seconds,    5.468 MiB/s
AES-192-GCM-enc             10 MiB took 1.828 seconds,    5.470 MiB/s
AES-192-GCM-dec             10 MiB took 1.829 seconds,    5.468 MiB/s
AES-256-GCM-enc             10 MiB took 1.827 seconds,    5.475 MiB/s
AES-256-GCM-dec             10 MiB took 1.829 seconds,    5.468 MiB/s
GMAC Table 4-bit            44 MiB took 1.000 seconds,   43.707 MiB/s
CHACHA                      75 MiB took 1.051 seconds,   71.348 MiB/s
CHA-POLY                    55 MiB took 1.035 seconds,   53.139 MiB/s
MD5                        135 MiB took 1.016 seconds,  132.876 MiB/s
POLY1305                   225 MiB took 1.010 seconds,  222.817 MiB/s
SHA                         85 MiB took 1.019 seconds,   83.452 MiB/s
SHA-256                     40 MiB took 1.108 seconds,   36.086 MiB/s
SHA-384                     65 MiB took 1.011 seconds,   64.305 MiB/s
SHA-512                     65 MiB took 1.011 seconds,   64.282 MiB/s
SHA-512/224                 65 MiB took 1.011 seconds,   64.317 MiB/s
SHA-512/256                 65 MiB took 1.013 seconds,   64.193 MiB/s
SHA3-224                    50 MiB took 1.065 seconds,   46.929 MiB/s
SHA3-256                    45 MiB took 1.014 seconds,   44.375 MiB/s
SHA3-384                    35 MiB took 1.023 seconds,   34.225 MiB/s
SHA3-512                    25 MiB took 1.051 seconds,   23.782 MiB/s
HMAC-MD5                   135 MiB took 1.011 seconds,  133.567 MiB/s
HMAC-SHA                    85 MiB took 1.017 seconds,   83.575 MiB/s
HMAC-SHA256                 40 MiB took 1.085 seconds,   36.882 MiB/s
HMAC-SHA384                 65 MiB took 1.014 seconds,   64.118 MiB/s
HMAC-SHA512                 65 MiB took 1.009 seconds,   64.413 MiB/s
PBKDF2                     576 bytes took 1.003 seconds,  574.070 bytes/s
RSA     2048   public      1800 ops took 1.058 sec, avg 0.588 ms, 1701.863 ops/sec
RSA     2048  private       200 ops took 1.721 sec, avg 8.604 ms, 116.218 ops/sec
DH      2048  key gen       222 ops took 1.003 sec, avg 4.517 ms, 221.370 ops/sec
DH      2048    agree       300 ops took 1.326 sec, avg 4.422 ms, 226.160 ops/sec
ECC   [      SECP256R1]   256  key gen      4400 ops took 1.000 sec, avg 0.227 ms, 4398.670 ops/sec
ECDHE [      SECP256R1]   256    agree      1900 ops took 1.018 sec, avg 0.536 ms, 1866.172 ops/sec
ECDSA [      SECP256R1]   256     sign      3400 ops took 1.017 sec, avg 0.299 ms, 3344.432 ops/sec
ECDSA [      SECP256R1]   256   verify      1800 ops took 1.027 sec, avg 0.571 ms, 1752.662 ops/sec
Benchmark complete
```

