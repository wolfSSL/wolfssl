# STM Benchmarks

* [STM32H753ZI](#stm32h753zi)
* [STM32WB55](#stm32wb55)
* [STM32WL55](#stm32wl55)
* [STM32F437](#stm32f437)
* [STM32L4A6Z](#stm32l4a6z)
* [STM32L562E](#stm32l562e)
* [STM32F777](#stm32f777)
* [STM32U585](#stm32u585)
* [STM32H563ZI](#stm32h563zi)
* [STM32G071RB](#stm32g071rb)


## STM32H753ZI

Supports RNG, AES CBC/GCM and SHA-2 acceleration.
Note: HW RNG on for all tests

Board: NUCLEO-H753ZI
CPU: Cortex-M7 at 480 MHz
IDE: STM32CubeIDE
RTOS: FreeRTOS

### STM32H753ZI (STM Crypto/Hash Acceleration, -Os, SP-ASM Cortex-M)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                875 KB took 1.019 seconds,  858.685 KB/s
AES-128-CBC-enc     10 MB took 1.000 seconds,   10.400 MB/s
AES-128-CBC-dec     10 MB took 1.000 seconds,   10.327 MB/s
AES-192-CBC-enc     10 MB took 1.000 seconds,   10.425 MB/s
AES-192-CBC-dec     10 MB took 1.000 seconds,   10.278 MB/s
AES-256-CBC-enc     10 MB took 1.000 seconds,   10.376 MB/s
AES-256-CBC-dec     10 MB took 1.000 seconds,   10.278 MB/s
AES-128-GCM-enc      9 MB took 1.000 seconds,    8.789 MB/s
AES-128-GCM-dec      9 MB took 1.000 seconds,    8.716 MB/s
AES-192-GCM-enc      9 MB took 1.000 seconds,    8.740 MB/s
AES-192-GCM-dec      9 MB took 1.000 seconds,    8.691 MB/s
AES-256-GCM-enc      9 MB took 1.000 seconds,    8.765 MB/s
AES-256-GCM-dec      9 MB took 1.000 seconds,    8.691 MB/s
CHACHA               4 MB took 1.000 seconds,    4.443 MB/s
CHA-POLY             3 MB took 1.004 seconds,    3.040 MB/s
POLY1305            13 MB took 1.000 seconds,   12.671 MB/s
SHA-256              9 MB took 1.000 seconds,    8.691 MB/s
HMAC-SHA256          8 MB took 1.000 seconds,    8.496 MB/s
RSA     2048 public         82 ops took 1.019 sec, avg 12.427 ms, 80.471 ops/sec
RSA     2048 private         4 ops took 1.749 sec, avg 437.250 ms, 2.287 ops/sec
DH      2048 key gen         5 ops took 1.000 sec, avg 200.000 ms, 5.000 ops/sec
DH      2048 agree           6 ops took 1.200 sec, avg 200.000 ms, 5.000 ops/sec
ECC      256 key gen       121 ops took 1.000 sec, avg 8.264 ms, 121.000 ops/sec
ECDHE    256 agree          56 ops took 1.016 sec, avg 18.143 ms, 55.118 ops/sec
ECDSA    256 sign           78 ops took 1.007 sec, avg 12.910 ms, 77.458 ops/sec
ECDSA    256 verify         36 ops took 1.004 sec, avg 27.889 ms, 35.857 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32H753ZI (-O2, Thumb2 ARM ASM, SP-ASM Cortex M small)

Enable CPU I-Cache and D-Cache by calling:

```c
SCB_EnableICache();
SCB_EnableDCache();
```

Build options for ARM ASM:

```c
#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_INLINE
#define WOLFSSL_ARMASM_NO_HW_CRYPTO
#define WOLFSSL_ARMASM_NO_NEON
#define WOLFSSL_ARM_ARCH 7
```

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.6
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                          6 MiB took 1.000 seconds,    6.079 MiB/s
AES-128-CBC-enc             17 MiB took 1.000 seconds,   17.261 MiB/s
AES-128-CBC-dec             17 MiB took 1.000 seconds,   16.748 MiB/s
AES-192-CBC-enc             15 MiB took 1.000 seconds,   14.575 MiB/s
AES-192-CBC-dec             14 MiB took 1.000 seconds,   14.209 MiB/s
AES-256-CBC-enc             13 MiB took 1.000 seconds,   12.622 MiB/s
AES-256-CBC-dec             12 MiB took 1.000 seconds,   12.378 MiB/s
AES-128-GCM-enc              8 MiB took 1.000 seconds,    8.374 MiB/s
AES-128-GCM-dec              8 MiB took 1.000 seconds,    8.374 MiB/s
AES-192-GCM-enc              8 MiB took 1.000 seconds,    7.690 MiB/s
AES-192-GCM-dec              8 MiB took 1.000 seconds,    7.690 MiB/s
AES-256-GCM-enc              7 MiB took 1.000 seconds,    7.129 MiB/s
AES-256-GCM-dec              7 MiB took 1.000 seconds,    7.104 MiB/s
AES-128-GCM-enc-no_AAD       8 MiB took 1.000 seconds,    8.472 MiB/s
AES-128-GCM-dec-no_AAD       8 MiB took 1.000 seconds,    8.472 MiB/s
AES-192-GCM-enc-no_AAD       8 MiB took 1.000 seconds,    7.764 MiB/s
AES-192-GCM-dec-no_AAD       8 MiB took 1.000 seconds,    7.715 MiB/s
AES-256-GCM-enc-no_AAD       7 MiB took 1.000 seconds,    7.153 MiB/s
AES-256-GCM-dec-no_AAD       7 MiB took 1.000 seconds,    7.153 MiB/s
GMAC Table 4-bit            17 MiB took 1.000 seconds,   16.617 MiB/s
CHACHA                      29 MiB took 1.000 seconds,   28.662 MiB/s
CHA-POLY                    19 MiB took 1.000 seconds,   18.848 MiB/s
POLY1305                    90 MiB took 1.000 seconds,   89.771 MiB/s
SHA-224                     18 MiB took 1.000 seconds,   18.042 MiB/s
SHA-256                     18 MiB took 1.000 seconds,   18.042 MiB/s
SHA-384                      8 MiB took 1.000 seconds,    7.544 MiB/s
SHA-512                      8 MiB took 1.000 seconds,    7.568 MiB/s
SHA-512/224                  8 MiB took 1.000 seconds,    7.544 MiB/s
SHA-512/256                  8 MiB took 1.000 seconds,    7.520 MiB/s
HMAC-SHA224                 18 MiB took 1.000 seconds,   17.896 MiB/s
HMAC-SHA256                 18 MiB took 1.000 seconds,   17.896 MiB/s
HMAC-SHA384                  7 MiB took 1.000 seconds,    7.373 MiB/s
HMAC-SHA512                  7 MiB took 1.000 seconds,    7.397 MiB/s
RSA     2048   public       508 ops took 1.000 sec, avg 1.969 ms, 508.000 ops/sec
RSA     2048  private        14 ops took 1.020 sec, avg 72.857 ms, 13.725 ops/sec
DH      2048  key gen        30 ops took 1.012 sec, avg 33.733 ms, 29.644 ops/sec
DH      2048    agree        30 ops took 1.012 sec, avg 33.733 ms, 29.644 ops/sec
ECC   [      SECP256R1]   256  key gen       982 ops took 1.000 sec, avg 1.018 ms, 982.000 ops/sec
ECDHE [      SECP256R1]   256    agree       456 ops took 1.000 sec, avg 2.193 ms, 456.000 ops/sec
ECDSA [      SECP256R1]   256     sign       520 ops took 1.000 sec, avg 1.923 ms, 520.000 ops/sec
ECDSA [      SECP256R1]   256   verify       288 ops took 1.004 sec, avg 3.486 ms, 286.853 ops/sec
CURVE  25519  key gen      1112 ops took 1.000 sec, avg 0.899 ms, 1112.000 ops/sec
CURVE  25519    agree      1144 ops took 1.000 sec, avg 0.874 ms, 1144.000 ops/sec
ED     25519  key gen      2358 ops took 1.000 sec, avg 0.424 ms, 2358.000 ops/sec
ED     25519     sign      1716 ops took 1.000 sec, avg 0.583 ms, 1716.000 ops/sec
ED     25519   verify       862 ops took 1.000 sec, avg 1.160 ms, 862.000 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


### STM32H753ZI (No HW Crypto, -Os, FastMath)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                  1 MB took 1.015 seconds,    1.010 MB/s
AES-128-CBC-enc      1 MB took 1.012 seconds,    1.399 MB/s
AES-128-CBC-dec      1 MB took 1.000 seconds,    1.318 MB/s
AES-192-CBC-enc      1 MB took 1.019 seconds,    1.198 MB/s
AES-192-CBC-dec      1 MB took 1.012 seconds,    1.134 MB/s
AES-256-CBC-enc      1 MB took 1.000 seconds,    1.050 MB/s
AES-256-CBC-dec      1 MB took 1.012 seconds,    0.989 MB/s
AES-128-GCM-enc     75 KB took 1.125 seconds,   66.667 KB/s
AES-128-GCM-dec     75 KB took 1.125 seconds,   66.667 KB/s
AES-192-GCM-enc     75 KB took 1.149 seconds,   65.274 KB/s
AES-192-GCM-dec     75 KB took 1.149 seconds,   65.274 KB/s
AES-256-GCM-enc     75 KB took 1.161 seconds,   64.599 KB/s
AES-256-GCM-dec     75 KB took 1.165 seconds,   64.378 KB/s
CHACHA               5 MB took 1.000 seconds,    4.858 MB/s
CHA-POLY             3 MB took 1.003 seconds,    3.140 MB/s
POLY1305            13 MB took 1.000 seconds,   12.671 MB/s
SHA-256              3 MB took 1.004 seconds,    2.845 MB/s
HMAC-SHA256          3 MB took 1.004 seconds,    2.821 MB/s
RSA     2048 public         38 ops took 1.012 sec, avg 26.632 ms, 37.549 ops/sec
RSA     2048 private         2 ops took 3.267 sec, avg 1633.500 ms, 0.612 ops/sec
DH      2048 key gen         4 ops took 1.184 sec, avg 296.000 ms, 3.378 ops/sec
DH      2048 agree           2 ops took 1.259 sec, avg 629.500 ms, 1.589 ops/sec
ECC      256 key gen         4 ops took 1.070 sec, avg 267.500 ms, 3.738 ops/sec
ECDHE    256 agree           4 ops took 1.070 sec, avg 267.500 ms, 3.738 ops/sec
ECDSA    256 sign            4 ops took 1.082 sec, avg 270.500 ms, 3.697 ops/sec
ECDSA    256 verify          6 ops took 1.016 sec, avg 169.333 ms, 5.906 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32WB55

Supports RNG, ECC P-256, AES-CBC and SHA-256 acceleration.
Note: SP math beats PKA HW. HW RNG on for all tests

Board: P-NUCLEO-WB55 (MB1355C-02)
CPU: Cortex-M4 at 64 MHz
IDE: STM32CubeIDE
RTOS: FreeRTOS

### STM32WB55 (STM AES-CBC/Hash Acceleration, -Os, SP-ASM Cortex-M)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                375 KB took 1.008 seconds,  372.024 KB/s
AES-128-CBC-enc      4 MB took 1.000 seconds,    3.882 MB/s
AES-128-CBC-dec      4 MB took 1.000 seconds,    3.955 MB/s
AES-256-CBC-enc      4 MB took 1.004 seconds,    3.550 MB/s
AES-256-CBC-dec      4 MB took 1.004 seconds,    3.599 MB/s
AES-128-GCM-enc     50 KB took 1.800 seconds,   27.778 KB/s
AES-128-GCM-dec     50 KB took 1.804 seconds,   27.716 KB/s
AES-256-GCM-enc     50 KB took 1.828 seconds,   27.352 KB/s
AES-256-GCM-dec     50 KB took 1.831 seconds,   27.307 KB/s
CHACHA               2 MB took 1.008 seconds,    1.574 MB/s
CHA-POLY             1 MB took 1.004 seconds,    1.046 MB/s
POLY1305             5 MB took 1.000 seconds,    4.663 MB/s
SHA-256           1000 KB took 1.015 seconds,  985.222 KB/s
HMAC-SHA256        975 KB took 1.000 seconds,  975.000 KB/s
RSA     2048 public         28 ops took 1.016 sec, avg 36.286 ms, 27.559 ops/sec
RSA     2048 private         2 ops took 2.522 sec, avg 1261.000 ms, 0.793 ops/sec
DH      2048 key gen         2 ops took 1.184 sec, avg 592.000 ms, 1.689 ops/sec
DH      2048 agree           2 ops took 1.181 sec, avg 590.500 ms, 1.693 ops/sec
ECC      256 key gen        37 ops took 1.008 sec, avg 27.243 ms, 36.706 ops/sec
ECDHE    256 agree          18 ops took 1.071 sec, avg 59.500 ms, 16.807 ops/sec
ECDSA    256 sign           14 ops took 1.130 sec, avg 80.714 ms, 12.389 ops/sec
ECDSA    256 verify          8 ops took 1.305 sec, avg 163.125 ms, 6.130 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32WB55 (STM PKA only, -Os, FastMath)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                375 KB took 1.008 seconds,  372.024 KB/s
AES-128-CBC-enc    600 KB took 1.020 seconds,  588.235 KB/s
AES-128-CBC-dec    575 KB took 1.007 seconds,  571.003 KB/s
AES-192-CBC-enc    525 KB took 1.043 seconds,  503.356 KB/s
AES-192-CBC-dec    500 KB took 1.028 seconds,  486.381 KB/s
AES-256-CBC-enc    450 KB took 1.027 seconds,  438.169 KB/s
AES-256-CBC-dec    425 KB took 1.000 seconds,  425.000 KB/s
AES-128-GCM-enc     50 KB took 1.819 seconds,   27.488 KB/s
AES-128-GCM-dec     50 KB took 1.820 seconds,   27.473 KB/s
AES-192-GCM-enc     50 KB took 1.855 seconds,   26.954 KB/s
AES-192-GCM-dec     50 KB took 1.851 seconds,   27.012 KB/s
AES-256-GCM-enc     50 KB took 1.874 seconds,   26.681 KB/s
AES-256-GCM-dec     50 KB took 1.875 seconds,   26.667 KB/s
CHACHA               2 MB took 1.004 seconds,    1.581 MB/s
CHA-POLY             1 MB took 1.000 seconds,    1.050 MB/s
POLY1305             5 MB took 1.000 seconds,    4.663 MB/s
SHA-256           1000 KB took 1.016 seconds,  984.252 KB/s
HMAC-SHA256       1000 KB took 1.024 seconds,  976.562 KB/s
RSA     2048 public         14 ops took 1.121 sec, avg 80.071 ms, 12.489 ops/sec
RSA     2048 private         2 ops took 9.428 sec, avg 4714.000 ms, 0.212 ops/sec
DH      2048 key gen         2 ops took 1.807 sec, avg 903.500 ms, 1.107 ops/sec
DH      2048 agree           2 ops took 3.643 sec, avg 1821.500 ms, 0.549 ops/sec
ECC      256 key gen         9 ops took 1.024 sec, avg 113.778 ms, 8.789 ops/sec
ECDHE    256 agree          10 ops took 1.129 sec, avg 112.900 ms, 8.857 ops/sec
ECDSA    256 sign           14 ops took 1.157 sec, avg 82.643 ms, 12.100 ops/sec
ECDSA    256 verify          8 ops took 1.282 sec, avg 160.250 ms, 6.240 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32WB55 (No HW Crypto, -Os, FastMath)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                375 KB took 1.004 seconds,  373.506 KB/s
AES-128-CBC-enc    600 KB took 1.024 seconds,  585.937 KB/s
AES-128-CBC-dec    575 KB took 1.008 seconds,  570.437 KB/s
AES-192-CBC-enc    525 KB took 1.047 seconds,  501.433 KB/s
AES-192-CBC-dec    500 KB took 1.028 seconds,  486.381 KB/s
AES-256-CBC-enc    450 KB took 1.028 seconds,  437.743 KB/s
AES-256-CBC-dec    450 KB took 1.055 seconds,  426.540 KB/s
AES-128-GCM-enc     50 KB took 1.816 seconds,   27.533 KB/s
AES-128-GCM-dec     50 KB took 1.820 seconds,   27.473 KB/s
AES-192-GCM-enc     50 KB took 1.851 seconds,   27.012 KB/s
AES-192-GCM-dec     50 KB took 1.851 seconds,   27.012 KB/s
AES-256-GCM-enc     50 KB took 1.875 seconds,   26.667 KB/s
AES-256-GCM-dec     50 KB took 1.874 seconds,   26.681 KB/s
CHACHA               2 MB took 1.004 seconds,    1.581 MB/s
CHA-POLY             1 MB took 1.012 seconds,    1.061 MB/s
POLY1305             5 MB took 1.004 seconds,    4.693 MB/s
SHA-256           1000 KB took 1.016 seconds,  984.252 KB/s
HMAC-SHA256       1000 KB took 1.023 seconds,  977.517 KB/s
RSA     2048 public         14 ops took 1.141 sec, avg 81.500 ms, 12.270 ops/sec
RSA     2048 private         2 ops took 9.498 sec, avg 4749.000 ms, 0.211 ops/sec
DH      2048 key gen         2 ops took 1.839 sec, avg 919.500 ms, 1.088 ops/sec
DH      2048 agree           2 ops took 3.674 sec, avg 1837.000 ms, 0.544 ops/sec
ECC      256 key gen         1 ops took 1.130 sec, avg 1130.000 ms, 0.885 ops/sec
ECDHE    256 agree           2 ops took 2.251 sec, avg 1125.500 ms, 0.888 ops/sec
ECDSA    256 sign            2 ops took 2.275 sec, avg 1137.500 ms, 0.879 ops/sec
ECDSA    256 verify          2 ops took 1.490 sec, avg 745.000 ms, 1.342 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32WL55

Supports RNG, ECC P-256 and AES-CBC acceleration.
Note: SP math beats PKA HW. HW RNG on for all tests

Board: NUCLEO-WL55JC1 (MB1389-HIGHBAND-E02)
CPU: Cortex-M4 at 64 MHz
IDE: STM32CubeIDE
RTOS: Bare-Metal

### STM32WL55 (STM AES-CBC Acceleration, -Os, SP-ASM Cortex-M WOLF_CONF_MATH=4)

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.4
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                        200 KiB took 1.012 seconds,  197.628 KiB/s
AES-128-CBC-enc              2 MiB took 1.000 seconds,    2.246 MiB/s
AES-128-CBC-dec              2 MiB took 1.004 seconds,    2.213 MiB/s
AES-256-CBC-enc              2 MiB took 1.008 seconds,    2.228 MiB/s
AES-256-CBC-dec              2 MiB took 1.000 seconds,    2.197 MiB/s
SHA-256                    600 KiB took 1.000 seconds,  600.000 KiB/s
HMAC-SHA256                600 KiB took 1.012 seconds,  592.885 KiB/s
ECC   [      SECP256R1]   256  key gen        56 ops took 1.023 sec, avg 18.268 ms, 54.741 ops/sec
ECDHE [      SECP256R1]   256    agree        26 ops took 1.024 sec, avg 39.385 ms, 25.391 ops/sec
ECDSA [      SECP256R1]   256     sign        30 ops took 1.019 sec, avg 33.967 ms, 29.441 ops/sec
ECDSA [      SECP256R1]   256   verify        18 ops took 1.098 sec, avg 61.000 ms, 16.393 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32WL55 (STM AES-CBC Acceleration and PKA ECC, -Os)

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.4
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                        200 KiB took 1.000 seconds,  200.000 KiB/s
AES-128-CBC-enc              2 MiB took 1.000 seconds,    2.295 MiB/s
AES-128-CBC-dec              2 MiB took 1.007 seconds,    2.279 MiB/s
AES-256-CBC-enc              2 MiB took 1.000 seconds,    2.295 MiB/s
AES-256-CBC-dec              2 MiB took 1.008 seconds,    2.252 MiB/s
SHA-256                    575 KiB took 1.043 seconds,  551.294 KiB/s
HMAC-SHA256                550 KiB took 1.000 seconds,  550.000 KiB/s
ECC   [      SECP256R1]   256  key gen         4 ops took 1.172 sec, avg 293.000 ms, 3.413 ops/sec
ECDHE [      SECP256R1]   256    agree         4 ops took 1.165 sec, avg 291.250 ms, 3.433 ops/sec
ECDSA [      SECP256R1]   256     sign        10 ops took 1.070 sec, avg 107.000 ms, 9.346 ops/sec
ECDSA [      SECP256R1]   256   verify         6 ops took 1.275 sec, avg 212.500 ms, 4.706 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32WL55 (No HW Crypto, -Os, SP Math All (WOLF_CONF_MATH=6))

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.4
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                        200 KiB took 1.015 seconds,  197.044 KiB/s
AES-128-CBC-enc            400 KiB took 1.004 seconds,  398.406 KiB/s
AES-128-CBC-dec            400 KiB took 1.000 seconds,  400.000 KiB/s
AES-192-CBC-enc            350 KiB took 1.031 seconds,  339.476 KiB/s
AES-192-CBC-dec            350 KiB took 1.028 seconds,  340.467 KiB/s
AES-256-CBC-enc            300 KiB took 1.007 seconds,  297.915 KiB/s
AES-256-CBC-dec            300 KiB took 1.004 seconds,  298.805 KiB/s
SHA-256                    550 KiB took 1.016 seconds,  541.339 KiB/s
HMAC-SHA256                550 KiB took 1.024 seconds,  537.109 KiB/s
ECC   [      SECP256R1]   256  key gen         4 ops took 1.180 sec, avg 295.000 ms, 3.390 ops/sec
ECDHE [      SECP256R1]   256    agree         4 ops took 1.181 sec, avg 295.250 ms, 3.387 ops/sec
ECDSA [      SECP256R1]   256     sign         4 ops took 1.306 sec, avg 326.500 ms, 3.063 ops/sec
ECDSA [      SECP256R1]   256   verify         2 ops took 1.188 sec, avg 594.000 ms, 1.684 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32F437

Supports RNG, AES-CBC/GCM and SHA-256 acceleration.
Note: HW RNG on for all tests

Board: STM32F437I-EVAL
CPU: Cortex-M4 at 160 MHz
IDE: STM32CubeIDE
RTOS: FreeRTOS

### STM32F437 (STM Crypto/Hash Acceleration, -Os, SP-ASM Cortex-M)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                500 KB took 1.000 seconds,  500.000 KB/s
AES-128-CBC-enc      9 MB took 1.000 seconds,    8.716 MB/s
AES-128-CBC-dec      9 MB took 1.004 seconds,    8.681 MB/s
AES-192-CBC-enc      9 MB took 1.000 seconds,    8.740 MB/s
AES-192-CBC-dec      9 MB took 1.000 seconds,    8.667 MB/s
AES-256-CBC-enc      9 MB took 1.000 seconds,    8.740 MB/s
AES-256-CBC-dec      9 MB took 1.004 seconds,    8.681 MB/s
AES-128-GCM-enc      8 MB took 1.000 seconds,    7.837 MB/s
AES-128-GCM-dec      8 MB took 1.000 seconds,    7.812 MB/s
AES-192-GCM-enc      8 MB took 1.000 seconds,    7.812 MB/s
AES-192-GCM-dec      8 MB took 1.000 seconds,    7.788 MB/s
AES-256-GCM-enc      8 MB took 1.000 seconds,    7.837 MB/s
AES-256-GCM-dec      8 MB took 1.000 seconds,    7.764 MB/s
CHACHA               4 MB took 1.000 seconds,    4.150 MB/s
CHA-POLY             3 MB took 1.004 seconds,    2.821 MB/s
POLY1305            13 MB took 1.000 seconds,   12.646 MB/s
SHA-256              7 MB took 1.000 seconds,    7.446 MB/s
HMAC-SHA256          7 MB took 1.000 seconds,    7.251 MB/s
RSA     2048 public         74 ops took 1.000 sec, avg 13.514 ms, 74.000 ops/sec
RSA     2048 private         4 ops took 1.933 sec, avg 483.250 ms, 2.069 ops/sec
DH      2048 key gen         5 ops took 1.075 sec, avg 215.000 ms, 4.651 ops/sec
DH      2048 agree           6 ops took 1.282 sec, avg 213.667 ms, 4.680 ops/sec
ECC      256 key gen       123 ops took 1.004 sec, avg 8.163 ms, 122.510 ops/sec
ECDHE    256 agree          58 ops took 1.019 sec, avg 17.569 ms, 56.919 ops/sec
ECDSA    256 sign           82 ops took 1.016 sec, avg 12.390 ms, 80.709 ops/sec
ECDSA    256 verify         38 ops took 1.015 sec, avg 26.711 ms, 37.438 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32F437 (No HW Crypto, -Os, FastMath)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                  1 MB took 1.024 seconds,    0.978 MB/s
AES-128-CBC-enc      1 MB took 1.012 seconds,    1.303 MB/s
AES-128-CBC-dec      1 MB took 1.004 seconds,    1.264 MB/s
AES-192-CBC-enc      1 MB took 1.012 seconds,    1.110 MB/s
AES-192-CBC-dec      1 MB took 1.016 seconds,    1.081 MB/s
AES-256-CBC-enc   1000 KB took 1.011 seconds,  989.120 KB/s
AES-256-CBC-dec    975 KB took 1.008 seconds,  967.262 KB/s
AES-128-GCM-enc     75 KB took 1.024 seconds,   73.242 KB/s
AES-128-GCM-dec     75 KB took 1.024 seconds,   73.242 KB/s
AES-192-GCM-enc     75 KB took 1.043 seconds,   71.908 KB/s
AES-192-GCM-dec     75 KB took 1.047 seconds,   71.633 KB/s
AES-256-GCM-enc     75 KB took 1.059 seconds,   70.822 KB/s
AES-256-GCM-dec     75 KB took 1.058 seconds,   70.888 KB/s
CHACHA               4 MB took 1.004 seconds,    4.158 MB/s
CHA-POLY             3 MB took 1.004 seconds,    2.821 MB/s
POLY1305            13 MB took 1.000 seconds,   12.598 MB/s
SHA-256              3 MB took 1.004 seconds,    2.602 MB/s
HMAC-SHA256          3 MB took 1.000 seconds,    2.588 MB/s
RSA     2048 public         34 ops took 1.039 sec, avg 30.559 ms, 32.724 ops/sec
RSA     2048 private         2 ops took 3.635 sec, avg 1817.500 ms, 0.550 ops/sec
DH      2048 key gen         3 ops took 1.039 sec, avg 346.333 ms, 2.887 ops/sec
DH      2048 agree           2 ops took 1.416 sec, avg 708.000 ms, 1.412 ops/sec
ECC      256 key gen         3 ops took 1.248 sec, avg 416.000 ms, 2.404 ops/sec
ECDHE    256 agree           4 ops took 1.662 sec, avg 415.500 ms, 2.407 ops/sec
ECDSA    256 sign            4 ops took 1.691 sec, avg 422.750 ms, 2.365 ops/sec
ECDSA    256 verify          4 ops took 1.091 sec, avg 272.750 ms, 3.666 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32L4A6Z

Supports RNG, AES-CBC/GCM and SHA-256 acceleration.
Note: HW RNG on for all tests

Board: NUCLEO-L4A6ZG
CPU: Cortex-M4 at 80 MHz
IDE: STM32CubeIDE
RTOS: FreeRTOS
Compiler: GCC with -Os

### STM32L4A6Z (STM Crypto/Hash Acceleration, SP-ASM Cortex-M Small and ARM ASM Thumb speedups)

Build options used:

```c
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define WOLFSSL_SP_384
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NO_MALLOC

#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_INLINE
#define WOLFSSL_ARMASM_NO_HW_CRYPTO
#define WOLFSSL_ARMASM_NO_NEON
#define WOLFSSL_ARM_ARCH 7
```

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.4
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                        225 KiB took 1.078 seconds,  208.720 KiB/s
AES-128-CBC-enc              4 MiB took 1.000 seconds,    4.150 MiB/s
AES-128-CBC-dec              3 MiB took 1.004 seconds,    3.234 MiB/s
AES-256-CBC-enc              3 MiB took 1.000 seconds,    3.247 MiB/s
AES-256-CBC-dec              3 MiB took 1.008 seconds,    2.543 MiB/s
AES-128-GCM-enc              4 MiB took 1.000 seconds,    3.687 MiB/s
AES-128-GCM-dec              4 MiB took 1.000 seconds,    3.638 MiB/s
AES-256-GCM-enc              3 MiB took 1.000 seconds,    2.930 MiB/s
AES-256-GCM-dec              3 MiB took 1.004 seconds,    2.894 MiB/s
AES-128-GCM-enc-no_AAD       4 MiB took 1.000 seconds,    3.687 MiB/s
AES-128-GCM-dec-no_AAD       4 MiB took 1.000 seconds,    3.662 MiB/s
AES-256-GCM-enc-no_AAD       3 MiB took 1.003 seconds,    2.945 MiB/s
AES-256-GCM-dec-no_AAD       3 MiB took 1.004 seconds,    2.918 MiB/s
GMAC Table 4-bit           952 KiB took 1.000 seconds,  952.000 KiB/s
CHACHA                       3 MiB took 1.004 seconds,    2.894 MiB/s
CHA-POLY                     2 MiB took 1.004 seconds,    1.775 MiB/s
POLY1305                     7 MiB took 1.000 seconds,    7.227 MiB/s
SHA-256                      7 MiB took 1.000 seconds,    7.104 MiB/s
SHA-512                    350 KiB took 1.036 seconds,  337.838 KiB/s
SHA-512/224                350 KiB took 1.035 seconds,  338.164 KiB/s
SHA-512/256                350 KiB took 1.035 seconds,  338.164 KiB/s
HMAC-SHA256                  7 MiB took 1.000 seconds,    6.763 MiB/s
HMAC-SHA512                350 KiB took 1.047 seconds,  334.288 KiB/s
RSA     2048   public        36 ops took 1.008 sec, avg 28.000 ms, 35.714 ops/sec
RSA     2048  private         2 ops took 2.016 sec, avg 1008.000 ms, 0.992 ops/sec
DH      2048  key gen         3 ops took 1.416 sec, avg 472.000 ms, 2.119 ops/sec
DH      2048    agree         4 ops took 1.890 sec, avg 472.500 ms, 2.116 ops/sec
ECC   [      SECP256R1]   256  key gen        32 ops took 1.000 sec, avg 31.250 ms, 32.000 ops/sec
ECDHE [      SECP256R1]   256    agree        16 ops took 1.101 sec, avg 68.812 ms, 14.532 ops/sec
ECDSA [      SECP256R1]   256     sign        24 ops took 1.020 sec, avg 42.500 ms, 23.529 ops/sec
ECDSA [      SECP256R1]   256   verify        12 ops took 1.133 sec, avg 94.417 ms, 10.591 ops/sec
ECC   [      SECP384R1]   384  key gen        10 ops took 1.232 sec, avg 123.200 ms, 8.117 ops/sec
ECDHE [      SECP384R1]   384    agree         4 ops took 1.063 sec, avg 265.750 ms, 3.763 ops/sec
ECDSA [      SECP384R1]   384     sign         8 ops took 1.223 sec, avg 152.875 ms, 6.541 ops/sec
ECDSA [      SECP384R1]   384   verify         4 ops took 1.388 sec, avg 347.000 ms, 2.882 ops/sec
CURVE  25519  key gen        32 ops took 1.023 sec, avg 31.969 ms, 31.281 ops/sec
CURVE  25519    agree        32 ops took 1.012 sec, avg 31.625 ms, 31.621 ops/sec
ED     25519  key gen        80 ops took 1.008 sec, avg 12.600 ms, 79.365 ops/sec
ED     25519     sign        64 ops took 1.027 sec, avg 16.047 ms, 62.317 ops/sec
ED     25519   verify        28 ops took 1.024 sec, avg 36.571 ms, 27.344 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32L4A6Z (No HW Crypto, SP Math All (sp_int.c) NO ASM)

```
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define WOLFSSL_NO_ASM
#define WOLFSSL_SP_NO_MALLOC
#define CURVED25519_SMALL
```

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.4
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                        325 KiB took 1.059 seconds,  306.893 KiB/s
AES-128-CBC-enc            425 KiB took 1.000 seconds,  425.000 KiB/s
AES-128-CBC-dec            450 KiB took 1.028 seconds,  437.743 KiB/s
AES-192-CBC-enc            375 KiB took 1.035 seconds,  362.319 KiB/s
AES-192-CBC-dec            375 KiB took 1.015 seconds,  369.458 KiB/s
AES-256-CBC-enc            325 KiB took 1.032 seconds,  314.922 KiB/s
AES-256-CBC-dec            325 KiB took 1.004 seconds,  323.705 KiB/s
AES-128-GCM-enc            325 KiB took 1.063 seconds,  305.738 KiB/s
AES-128-GCM-dec            325 KiB took 1.066 seconds,  304.878 KiB/s
AES-192-GCM-enc            275 KiB took 1.020 seconds,  269.608 KiB/s
AES-192-GCM-dec            275 KiB took 1.015 seconds,  270.936 KiB/s
AES-256-GCM-enc            250 KiB took 1.028 seconds,  243.191 KiB/s
AES-256-GCM-dec            250 KiB took 1.027 seconds,  243.427 KiB/s
AES-128-GCM-enc-no_AAD     325 KiB took 1.059 seconds,  306.893 KiB/s
AES-128-GCM-dec-no_AAD     325 KiB took 1.062 seconds,  306.026 KiB/s
AES-192-GCM-enc-no_AAD     275 KiB took 1.012 seconds,  271.739 KiB/s
AES-192-GCM-dec-no_AAD     275 KiB took 1.015 seconds,  270.936 KiB/s
AES-256-GCM-enc-no_AAD     250 KiB took 1.020 seconds,  245.098 KiB/s
AES-256-GCM-dec-no_AAD     250 KiB took 1.023 seconds,  244.379 KiB/s
GMAC Table 4-bit             1 MiB took 1.000 seconds,    1.064 MiB/s
CHACHA                       3 MiB took 1.000 seconds,    2.832 MiB/s
CHA-POLY                     2 MiB took 1.004 seconds,    1.751 MiB/s
POLY1305                     7 MiB took 1.000 seconds,    7.104 MiB/s
SHA-256                    850 KiB took 1.003 seconds,  847.458 KiB/s
SHA-512                    350 KiB took 1.036 seconds,  337.838 KiB/s
SHA-512/224                350 KiB took 1.035 seconds,  338.164 KiB/s
SHA-512/256                350 KiB took 1.035 seconds,  338.164 KiB/s
HMAC-SHA256                850 KiB took 1.012 seconds,  839.921 KiB/s
HMAC-SHA512                350 KiB took 1.051 seconds,  333.016 KiB/s
RSA     2048   public        24 ops took 1.067 sec, avg 44.458 ms, 22.493 ops/sec
RSA     2048  private         2 ops took 5.643 sec, avg 2821.500 ms, 0.354 ops/sec
DH      2048  key gen         2 ops took 1.078 sec, avg 539.000 ms, 1.855 ops/sec
DH      2048    agree         2 ops took 2.455 sec, avg 1227.500 ms, 0.815 ops/sec
ECC   [      SECP256R1]   256  key gen         4 ops took 1.808 sec, avg 452.000 ms, 2.212 ops/sec
ECDHE [      SECP256R1]   256    agree         4 ops took 1.807 sec, avg 451.750 ms, 2.214 ops/sec
ECDSA [      SECP256R1]   256     sign         4 ops took 1.828 sec, avg 457.000 ms, 2.188 ops/sec
ECDSA [      SECP256R1]   256   verify         4 ops took 1.224 sec, avg 306.000 ms, 3.268 ops/sec
CURVE  25519  key gen         2 ops took 1.392 sec, avg 696.000 ms, 1.437 ops/sec
CURVE  25519    agree         2 ops took 1.384 sec, avg 692.000 ms, 1.445 ops/sec
ED     25519  key gen         2 ops took 1.412 sec, avg 706.000 ms, 1.416 ops/sec
ED     25519     sign         2 ops took 1.435 sec, avg 717.500 ms, 1.394 ops/sec
ED     25519   verify         2 ops took 2.949 sec, avg 1474.500 ms, 0.678 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32L562E

Supports RNG, AES-CBC/GCM and SHA-256 acceleration.
Note: HW RNG on for all tests

Board: STM32L562E-DK
CPU: Cortex-M33 at 110 MHz
IDE: STM32CubeIDE
RTOS: FreeRTOS

### STM32L562E (STM AES-CBC/Hash Acceleration, -Os, SP-ASM Cortex-M)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                150 KB took 1.105 seconds,  135.747 KB/s
AES-128-CBC-enc      4 MB took 1.000 seconds,    4.468 MB/s
AES-128-CBC-dec      4 MB took 1.000 seconds,    4.297 MB/s
AES-256-CBC-enc      4 MB took 1.000 seconds,    3.857 MB/s
AES-256-CBC-dec      4 MB took 1.004 seconds,    3.745 MB/s
AES-128-GCM-enc      4 MB took 1.000 seconds,    3.662 MB/s
AES-128-GCM-dec      4 MB took 1.004 seconds,    3.648 MB/s
AES-256-GCM-enc      3 MB took 1.004 seconds,    3.258 MB/s
AES-256-GCM-dec      3 MB took 1.000 seconds,    3.247 MB/s
CHACHA               1 MB took 1.008 seconds,    1.138 MB/s
CHA-POLY           825 KB took 1.023 seconds,  806.452 KB/s
POLY1305             4 MB took 1.000 seconds,    3.711 MB/s
SHA-256              2 MB took 1.000 seconds,    1.855 MB/s
HMAC-SHA256          2 MB took 1.008 seconds,    1.817 MB/s
RSA     2048 public         20 ops took 1.106 sec, avg 55.300 ms, 18.083 ops/sec
RSA     2048 private         2 ops took 3.804 sec, avg 1902.000 ms, 0.526 ops/sec
DH      2048 key gen         2 ops took 1.772 sec, avg 886.000 ms, 1.129 ops/sec
DH      2048 agree           2 ops took 1.773 sec, avg 886.500 ms, 1.128 ops/sec
ECC      256 key gen        36 ops took 1.011 sec, avg 28.083 ms, 35.608 ops/sec
ECDHE    256 agree          18 ops took 1.086 sec, avg 60.333 ms, 16.575 ops/sec
ECDSA    256 sign           22 ops took 1.004 sec, avg 45.636 ms, 21.912 ops/sec
ECDSA    256 verify         12 ops took 1.133 sec, avg 94.417 ms, 10.591 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32L562E (STM PKA ECC/AES-CBC/Hash Acceleration, -Os, SP-ASM Cortex-M)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                150 KB took 1.105 seconds,  135.747 KB/s
AES-128-CBC-enc      4 MB took 1.000 seconds,    4.468 MB/s
AES-128-CBC-dec      4 MB took 1.000 seconds,    4.297 MB/s
AES-256-CBC-enc      4 MB took 1.000 seconds,    3.857 MB/s
AES-256-CBC-dec      4 MB took 1.004 seconds,    3.745 MB/s
AES-128-GCM-enc      4 MB took 1.000 seconds,    3.662 MB/s
AES-128-GCM-dec      4 MB took 1.004 seconds,    3.648 MB/s
AES-256-GCM-enc      3 MB took 1.004 seconds,    3.258 MB/s
AES-256-GCM-dec      3 MB took 1.000 seconds,    3.247 MB/s
CHACHA               1 MB took 1.008 seconds,    1.138 MB/s
CHA-POLY           825 KB took 1.023 seconds,  806.452 KB/s
POLY1305             4 MB took 1.000 seconds,    3.711 MB/s
SHA-256              2 MB took 1.000 seconds,    1.855 MB/s
HMAC-SHA256          2 MB took 1.008 seconds,    1.817 MB/s
RSA     2048 public         20 ops took 1.106 sec, avg 55.300 ms, 18.083 ops/sec
RSA     2048 private         2 ops took 3.804 sec, avg 1902.000 ms, 0.526 ops/sec
DH      2048 key gen         2 ops took 1.772 sec, avg 886.000 ms, 1.129 ops/sec
DH      2048 agree           2 ops took 1.773 sec, avg 886.500 ms, 1.128 ops/sec
ECC      256 key gen        11 ops took 1.067 sec, avg 97.000 ms, 10.309 ops/sec
ECDHE    256 agree          12 ops took 1.130 sec, avg 94.167 ms, 10.619 ops/sec
ECDSA    256 sign           22 ops took 1.071 sec, avg 48.682 ms, 20.542 ops/sec
ECDSA    256 verify         12 ops took 1.125 sec, avg 93.750 ms, 10.667 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32L562E (No HW Crypto, -Os, FastMath)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                 75 KB took 1.274 seconds,   58.870 KB/s
AES-128-CBC-enc    475 KB took 1.036 seconds,  458.494 KB/s
AES-128-CBC-dec    450 KB took 1.007 seconds,  446.872 KB/s
AES-192-CBC-enc    400 KB took 1.024 seconds,  390.625 KB/s
AES-192-CBC-dec    400 KB took 1.047 seconds,  382.044 KB/s
AES-256-CBC-enc    350 KB took 1.023 seconds,  342.131 KB/s
AES-256-CBC-dec    350 KB took 1.051 seconds,  333.016 KB/s
AES-128-GCM-enc     25 KB took 1.310 seconds,   19.084 KB/s
AES-128-GCM-dec     25 KB took 1.306 seconds,   19.142 KB/s
AES-192-GCM-enc     25 KB took 1.330 seconds,   18.797 KB/s
AES-192-GCM-dec     25 KB took 1.329 seconds,   18.811 KB/s
AES-256-GCM-enc     25 KB took 1.341 seconds,   18.643 KB/s
AES-256-GCM-dec     25 KB took 1.345 seconds,   18.587 KB/s
CHACHA               1 MB took 1.012 seconds,    1.230 MB/s
CHA-POLY           850 KB took 1.000 seconds,  850.000 KB/s
POLY1305             4 MB took 1.004 seconds,    3.672 MB/s
SHA-256            750 KB took 1.020 seconds,  735.294 KB/s
HMAC-SHA256        750 KB took 1.031 seconds,  727.449 KB/s
RSA     2048 public         10 ops took 1.086 sec, avg 108.600 ms, 9.208 ops/sec
RSA     2048 private         2 ops took 12.894 sec, avg 6447.000 ms, 0.155 ops/sec
DH      2048 key gen         1 ops took 1.200 sec, avg 1200.000 ms, 0.833 ops/sec
DH      2048 agree           2 ops took 4.867 sec, avg 2433.500 ms, 0.411 ops/sec
ECC      256 key gen         1 ops took 1.514 sec, avg 1514.000 ms, 0.661 ops/sec
ECDHE    256 agree           2 ops took 3.028 sec, avg 1514.000 ms, 0.661 ops/sec
ECDSA    256 sign            2 ops took 3.066 sec, avg 1533.000 ms, 0.652 ops/sec
ECDSA    256 verify          2 ops took 1.973 sec, avg 986.500 ms, 1.014 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32F777

Supports RNG, AES-CBC/GCM and SHA-256 acceleration.
Note: HW RNG on for all tests

Board: Custom STM32F777
CPU: Cortex-M7 at 216 MHz
IDE: STM32CubeIDE
RTOS: FreeRTOS

### STM32F777 (STM AES-CBC/Hash Acceleration, -Os, SP-ASM Cortex-M)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                525 KB took 1.012 seconds,  518.775 KB/s
AES-128-CBC-enc      8 MB took 1.000 seconds,    8.350 MB/s
AES-128-CBC-dec      8 MB took 1.000 seconds,    8.203 MB/s
AES-192-CBC-enc      8 MB took 1.000 seconds,    8.325 MB/s
AES-192-CBC-dec      8 MB took 1.000 seconds,    8.179 MB/s
AES-256-CBC-enc      8 MB took 1.000 seconds,    8.325 MB/s
AES-256-CBC-dec      8 MB took 1.000 seconds,    8.154 MB/s
AES-128-GCM-enc      6 MB took 1.000 seconds,    6.494 MB/s
AES-128-GCM-dec      6 MB took 1.000 seconds,    6.494 MB/s
AES-192-GCM-enc      6 MB took 1.000 seconds,    6.470 MB/s
AES-192-GCM-dec      6 MB took 1.000 seconds,    6.494 MB/s
AES-256-GCM-enc      6 MB took 1.000 seconds,    6.494 MB/s
AES-256-GCM-dec      6 MB took 1.000 seconds,    6.494 MB/s
CHACHA               4 MB took 1.004 seconds,    4.182 MB/s
CHA-POLY             3 MB took 1.004 seconds,    2.505 MB/s
POLY1305             9 MB took 1.000 seconds,    9.204 MB/s
SHA-256              3 MB took 1.000 seconds,    3.467 MB/s
HMAC-SHA256          3 MB took 1.004 seconds,    3.404 MB/s
RSA     2048 public         54 ops took 1.028 sec, avg 19.037 ms, 52.529 ops/sec
RSA     2048 private         2 ops took 1.262 sec, avg 631.000 ms, 1.585 ops/sec
DH      2048 key gen         4 ops took 1.220 sec, avg 305.000 ms, 3.279 ops/sec
DH      2048 agree           4 ops took 1.215 sec, avg 303.750 ms, 3.292 ops/sec
ECC      256 key gen       130 ops took 1.000 sec, avg 7.692 ms, 130.000 ops/sec
ECDHE    256 agree          60 ops took 1.003 sec, avg 16.717 ms, 59.821 ops/sec
ECDSA    256 sign           70 ops took 1.024 sec, avg 14.629 ms, 68.359 ops/sec
ECDSA    256 verify         36 ops took 1.015 sec, avg 28.194 ms, 35.468 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32F777 (No HW Crypto, -Os, FastMath)

```
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                700 KB took 1.016 seconds,  688.976 KB/s
AES-128-CBC-enc      1 MB took 1.019 seconds,    1.006 MB/s
AES-128-CBC-dec    950 KB took 1.000 seconds,  950.000 KB/s
AES-192-CBC-enc    900 KB took 1.016 seconds,  885.827 KB/s
AES-192-CBC-dec    825 KB took 1.011 seconds,  816.024 KB/s
AES-256-CBC-enc    800 KB took 1.028 seconds,  778.210 KB/s
AES-256-CBC-dec    725 KB took 1.008 seconds,  719.246 KB/s
AES-128-GCM-enc     50 KB took 1.223 seconds,   40.883 KB/s
AES-128-GCM-dec     50 KB took 1.220 seconds,   40.984 KB/s
AES-192-GCM-enc     50 KB took 1.251 seconds,   39.968 KB/s
AES-192-GCM-dec     50 KB took 1.247 seconds,   40.096 KB/s
AES-256-GCM-enc     50 KB took 1.267 seconds,   39.463 KB/s
AES-256-GCM-dec     50 KB took 1.263 seconds,   39.588 KB/s
CHACHA               4 MB took 1.000 seconds,    4.175 MB/s
CHA-POLY             2 MB took 1.000 seconds,    2.417 MB/s
POLY1305            10 MB took 1.000 seconds,   10.132 MB/s
SHA-256              2 MB took 1.000 seconds,    1.782 MB/s
HMAC-SHA256          2 MB took 1.004 seconds,    1.775 MB/s
RSA     2048 public         22 ops took 1.067 sec, avg 48.500 ms, 20.619 ops/sec
RSA     2048 private         2 ops took 5.549 sec, avg 2774.500 ms, 0.360 ops/sec
DH      2048 key gen         3 ops took 1.483 sec, avg 494.333 ms, 2.023 ops/sec
DH      2048 agree           2 ops took 1.866 sec, avg 933.000 ms, 1.072 ops/sec
ECC      256 key gen         1 ops took 1.090 sec, avg 1090.000 ms, 0.917 ops/sec
ECDHE    256 agree           2 ops took 2.180 sec, avg 1090.000 ms, 0.917 ops/sec
ECDSA    256 sign            2 ops took 2.208 sec, avg 1104.000 ms, 0.906 ops/sec
ECDSA    256 verify          2 ops took 1.463 sec, avg 731.500 ms, 1.367 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32U585

Supports RNG, AES CBC/GCM and SHA-1,SHA-2 acceleration.

Board: B-U585I-IOT02A
CPU: Cortex-M33 at 160 MHz
IDE: STM32CubeIDE
RTOS: FreeRTOS

### STM32U585 (STM Symmetric AES/SHA acceleration, STM PKA PKA w/Fast Math)

This test uses `WOLFSSL_SMALL_STACK_CACHE`, which slightly improves the DRBG RNG performance.

Only the ECC sign and verify are currently being accelerated by PKA.

```
------------------------------------------------------------------------------
 wolfSSL version 5.3.1
------------------------------------------------------------------------------
Running wolfCrypt Benchmarks...
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                575 KB took 1.039 seconds,  553.417 KB/s
AES-128-CBC-enc      6 MB took 1.000 seconds,    6.274 MB/s
AES-128-CBC-dec      6 MB took 1.000 seconds,    6.128 MB/s
AES-256-CBC-enc      6 MB took 1.000 seconds,    6.274 MB/s
AES-256-CBC-dec      6 MB took 1.000 seconds,    6.152 MB/s
AES-128-GCM-enc      6 MB took 1.000 seconds,    5.640 MB/s
AES-128-GCM-dec      6 MB took 1.000 seconds,    5.566 MB/s
AES-256-GCM-enc      6 MB took 1.000 seconds,    5.615 MB/s
AES-256-GCM-dec      6 MB took 1.000 seconds,    5.542 MB/s
GMAC Small          11 MB took 1.000 seconds,   11.499 MB/s
CHACHA               4 MB took 1.000 seconds,    3.882 MB/s
CHA-POLY             2 MB took 1.008 seconds,    2.470 MB/s
3DES               200 KB took 1.071 seconds,  186.741 KB/s
MD5                  6 MB took 1.000 seconds,    6.299 MB/s
POLY1305            10 MB took 1.000 seconds,   10.449 MB/s
SHA                  6 MB took 1.000 seconds,    6.299 MB/s
SHA-256              6 MB took 1.000 seconds,    6.250 MB/s
HMAC-MD5             6 MB took 1.000 seconds,    6.177 MB/s
HMAC-SHA             6 MB took 1.000 seconds,    6.177 MB/s
HMAC-SHA256          6 MB took 1.000 seconds,    6.104 MB/s
RSA     2048 public         28 ops took 1.031 sec, avg 36.821 ms, 27.158 ops/sec
RSA     2048 private         2 ops took 4.310 sec, avg 2155.000 ms, 0.464 ops/sec
DH      2048 key gen         3 ops took 1.197 sec, avg 399.000 ms, 2.506 ops/sec
DH      2048 agree           2 ops took 1.525 sec, avg 762.500 ms, 1.311 ops/sec
ECC   [      SECP256R1]   256 key gen        50 ops took 1.019 sec, avg 20.380 ms, 49.068 ops/sec
ECDHE [      SECP256R1]   256 agree          52 ops took 1.008 sec, avg 19.385 ms, 51.587 ops/sec
ECDSA [      SECP256R1]   256 sign           56 ops took 1.000 sec, avg 17.857 ms, 56.000 ops/sec
ECDSA [      SECP256R1]   256 verify         56 ops took 1.008 sec, avg 18.000 ms, 55.556 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


### STM32U585 (STM Symmetric AES/SHA acceleration, SP Math ASM Cortex M)

```
------------------------------------------------------------------------------
 wolfSSL version 5.3.1
------------------------------------------------------------------------------
Running wolfCrypt Benchmarks...
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                250 KB took 1.039 seconds,  240.616 KB/s
AES-128-CBC-enc      6 MB took 1.000 seconds,    6.152 MB/s
AES-128-CBC-dec      6 MB took 1.004 seconds,    6.031 MB/s
AES-256-CBC-enc      6 MB took 1.000 seconds,    6.152 MB/s
AES-256-CBC-dec      6 MB took 1.000 seconds,    6.055 MB/s
AES-128-GCM-enc      6 MB took 1.000 seconds,    5.542 MB/s
AES-128-GCM-dec      5 MB took 1.000 seconds,    5.493 MB/s
AES-256-GCM-enc      6 MB took 1.000 seconds,    5.518 MB/s
AES-256-GCM-dec      5 MB took 1.000 seconds,    5.469 MB/s
GMAC Small          11 MB took 1.000 seconds,   11.182 MB/s
CHACHA               3 MB took 1.004 seconds,    3.429 MB/s
CHA-POLY             2 MB took 1.000 seconds,    2.271 MB/s
3DES               175 KB took 1.000 seconds,  175.000 KB/s
MD5                  8 MB took 1.000 seconds,    8.008 MB/s
POLY1305            10 MB took 1.000 seconds,   10.181 MB/s
SHA                  8 MB took 1.000 seconds,    7.983 MB/s
SHA-256              8 MB took 1.000 seconds,    7.910 MB/s
HMAC-MD5             8 MB took 1.000 seconds,    7.812 MB/s
HMAC-SHA             8 MB took 1.000 seconds,    7.812 MB/s
HMAC-SHA256          8 MB took 1.000 seconds,    7.642 MB/s
RSA     2048 public         52 ops took 1.000 sec, avg 19.231 ms, 52.000 ops/sec
RSA     2048 private         2 ops took 1.381 sec, avg 690.500 ms, 1.448 ops/sec
DH      2048 key gen         4 ops took 1.263 sec, avg 315.750 ms, 3.167 ops/sec
DH      2048 agree           4 ops took 1.262 sec, avg 315.500 ms, 3.170 ops/sec
ECC   [      SECP256R1]   256 key gen       108 ops took 1.016 sec, avg 9.407 ms, 106.299 ops/sec
ECDHE [      SECP256R1]   256 agree          58 ops took 1.032 sec, avg 17.793 ms, 56.202 ops/sec
ECDSA [      SECP256R1]   256 sign           64 ops took 1.027 sec, avg 16.047 ms, 62.317 ops/sec
ECDSA [      SECP256R1]   256 verify         36 ops took 1.019 sec, avg 28.306 ms, 35.329 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

### STM32U585 (No STM HW Crypto, SP Math C32)

```
------------------------------------------------------------------------------
 wolfSSL version 5.3.1
------------------------------------------------------------------------------
Running wolfCrypt Benchmarks...
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                750 KB took 1.015 seconds,  738.916 KB/s
AES-128-CBC-enc    900 KB took 1.004 seconds,  896.414 KB/s
AES-128-CBC-dec    900 KB took 1.012 seconds,  889.328 KB/s
AES-192-CBC-enc    775 KB took 1.004 seconds,  771.912 KB/s
AES-192-CBC-dec    775 KB took 1.023 seconds,  757.576 KB/s
AES-256-CBC-enc    675 KB took 1.000 seconds,  675.000 KB/s
AES-256-CBC-dec    675 KB took 1.031 seconds,  654.704 KB/s
AES-128-GCM-enc     50 KB took 1.035 seconds,   48.309 KB/s
AES-128-GCM-dec     50 KB took 1.036 seconds,   48.263 KB/s
AES-192-GCM-enc     50 KB took 1.051 seconds,   47.574 KB/s
AES-192-GCM-dec     50 KB took 1.051 seconds,   47.574 KB/s
AES-256-GCM-enc     50 KB took 1.067 seconds,   46.860 KB/s
AES-256-GCM-dec     50 KB took 1.070 seconds,   46.729 KB/s
GMAC Small          52 KB took 1.004 seconds,   51.793 KB/s
CHACHA               4 MB took 1.000 seconds,    3.833 MB/s
CHA-POLY             2 MB took 1.004 seconds,    2.456 MB/s
3DES               200 KB took 1.074 seconds,  186.220 KB/s
MD5                  6 MB took 1.000 seconds,    6.274 MB/s
POLY1305            10 MB took 1.000 seconds,   10.400 MB/s
SHA                  5 MB took 1.000 seconds,    5.225 MB/s
SHA-256              2 MB took 1.004 seconds,    1.970 MB/s
HMAC-MD5             6 MB took 1.000 seconds,    6.201 MB/s
HMAC-SHA             5 MB took 1.000 seconds,    5.176 MB/s
HMAC-SHA256          2 MB took 1.000 seconds,    1.953 MB/s
RSA     2048 public         36 ops took 1.008 sec, avg 28.000 ms, 35.714 ops/sec
RSA     2048 private         2 ops took 3.216 sec, avg 1608.000 ms, 0.622 ops/sec
DH      2048 key gen         2 ops took 1.416 sec, avg 708.000 ms, 1.412 ops/sec
DH      2048 agree           2 ops took 1.419 sec, avg 709.500 ms, 1.409 ops/sec
ECC   [      SECP256R1]   256 key gen         8 ops took 1.169 sec, avg 146.125 ms, 6.843 ops/sec
ECDHE [      SECP256R1]   256 agree           8 ops took 1.165 sec, avg 145.625 ms, 6.867 ops/sec
ECDSA [      SECP256R1]   256 sign            8 ops took 1.314 sec, avg 164.250 ms, 6.088 ops/sec
ECDSA [      SECP256R1]   256 verify          4 ops took 1.196 sec, avg 299.000 ms, 3.344 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32H563ZI

Cortex-M33 at 150MHz

### STM32H563ZI (No STM HW Crypto, SP Math ASM Cortex M)

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.0
------------------------------------------------------------------------------
Running wolfCrypt Benchmarks...
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                          2 MB took 1.011 seconds,    1.950 MB/s
AES-128-CBC-enc              4 MB took 1.000 seconds,    3.686 MB/s
AES-128-CBC-dec              4 MB took 1.004 seconds,    3.723 MB/s
AES-192-CBC-enc              3 MB took 1.004 seconds,    3.187 MB/s
AES-192-CBC-dec              3 MB took 1.000 seconds,    3.046 MB/s
AES-256-CBC-enc              3 MB took 1.000 seconds,    2.816 MB/s
AES-256-CBC-dec              3 MB took 1.004 seconds,    2.728 MB/s
AES-128-GCM-enc              2 MB took 1.000 seconds,    2.048 MB/s
AES-128-GCM-dec              2 MB took 1.004 seconds,    2.091 MB/s
AES-192-GCM-enc              2 MB took 1.008 seconds,    1.879 MB/s
AES-192-GCM-dec              2 MB took 1.011 seconds,    1.874 MB/s
AES-256-GCM-enc              2 MB took 1.000 seconds,    1.741 MB/s
AES-256-GCM-dec              2 MB took 1.012 seconds,    1.745 MB/s
AES-128-GCM-enc-no_AAD       2 MB took 1.008 seconds,    2.057 MB/s
AES-128-GCM-dec-no_AAD       2 MB took 1.008 seconds,    2.108 MB/s
AES-192-GCM-enc-no_AAD       2 MB took 1.000 seconds,    1.894 MB/s
AES-192-GCM-dec-no_AAD       2 MB took 1.000 seconds,    1.894 MB/s
AES-256-GCM-enc-no_AAD       2 MB took 1.004 seconds,    1.759 MB/s
AES-256-GCM-dec-no_AAD       2 MB took 1.004 seconds,    1.759 MB/s
GMAC Table 4-bit             4 MB took 1.000 seconds,    4.400 MB/s
CHACHA                       8 MB took 1.000 seconds,    8.448 MB/s
CHA-POLY                     6 MB took 1.000 seconds,    5.683 MB/s
POLY1305                    26 MB took 1.000 seconds,   25.574 MB/s
SHA-256                      5 MB took 1.004 seconds,    4.972 MB/s
HMAC-SHA256                  5 MB took 1.000 seconds,    4.941 MB/s
RSA     2048   public       122 ops took 1.000 sec, avg 8.197 ms, 122.000 ops/sec
RSA     2048  private         4 ops took 1.231 sec, avg 307.750 ms, 3.249 ops/sec
DH      2048  key gen         7 ops took 1.000 sec, avg 142.857 ms, 7.000 ops/sec
DH      2048    agree         8 ops took 1.141 sec, avg 142.625 ms, 7.011 ops/sec
ECC   [      SECP256R1]   256  key gen       204 ops took 1.000 sec, avg 4.902 ms, 204.000 ops/sec
ECDHE [      SECP256R1]   256    agree        94 ops took 1.007 sec, avg 10.713 ms, 93.347 ops/sec
ECDSA [      SECP256R1]   256     sign       136 ops took 1.012 sec, avg 7.441 ms, 134.387 ops/sec
ECDSA [      SECP256R1]   256   verify        66 ops took 1.012 sec, avg 15.333 ms, 65.217 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```


## STM32G071RB

STM32G0 is a Cortex M0+ at up to 64MHz. The STM32G071RB has 128KB Flash and 36KB RAM.

### STM32G071RB Benchmarks (SP Math Small with ARM Thumb Assembly)

Build options used:
* `WOLFSSL_HAVE_SP_RSA`
* `WOLFSSL_SP_ARM_THUMB_ASM`
* `WOLFSSL_SP_SMALL`
* `WOLFSSL_SP_MATH`

```
------------------------------------------------------------------------------
 wolfSSL version 5.6.0
------------------------------------------------------------------------------
Running wolfCrypt Benchmarks...
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                        205 KB took 1.043 seconds,  196.357 KB/s
AES-128-CBC-enc            358 KB took 1.008 seconds,  355.556 KB/s
AES-128-CBC-dec            358 KB took 1.051 seconds,  341.009 KB/s
AES-192-CBC-enc            333 KB took 1.063 seconds,  313.076 KB/s
AES-192-CBC-dec            307 KB took 1.023 seconds,  300.293 KB/s
AES-256-CBC-enc            282 KB took 1.004 seconds,  280.478 KB/s
AES-256-CBC-dec            282 KB took 1.043 seconds,  269.990 KB/s
SHA-256                    486 KB took 1.020 seconds,  476.863 KB/s
HMAC-SHA256                486 KB took 1.028 seconds,  473.152 KB/s
RSA     2048   public        12 ops took 1.043 sec, avg 86.917 ms, 11.505 ops/sec
RSA     2048  private         2 ops took 6.482 sec, avg 3241.000 ms, 0.309 ops/sec
ECC   [      SECP256R1]   256  key gen        10 ops took 1.122 sec, avg 112.200 ms, 8.913 ops/sec
ECDHE [      SECP256R1]   256    agree         4 ops took 1.000 sec, avg 250.000 ms, 4.000 ops/sec
ECDSA [      SECP256R1]   256     sign         8 ops took 1.227 sec, avg 153.375 ms, 6.520 ops/sec
ECDSA [      SECP256R1]   256   verify         4 ops took 1.396 sec, avg 349.000 ms, 2.865 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

Without `WOLFSSL_SP_SMALL` (larger version):

```
RSA     2048   public        14 ops took 1.016 sec, avg 72.571 ms, 13.780 ops/sec
RSA     2048  private         2 ops took 5.447 sec, avg 2723.500 ms, 0.367 ops/sec
```

