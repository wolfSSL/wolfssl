# Intel QuickAssist Adapter Asynchronous Support

The wolfSSL / wolfCrypt libraries support hardware crypto acceleration using the Intel QuickAssist adapter. This software has been tested using the Intel DH8970 and DH8950 QuickAssist adapters.

## Overview

Support has been added for wolfCrypt for RSA public/private (CRT/non-CRT), AES CBC/GCM, ECDH/ECDSA, DH, DES3, SHA, SHA224, SHA256, SHA384, SHA512, MD5 and HMAC. RSA padding is done via software. The wolfCrypt tests and benchmarks have asynchronous support. The wolfCrypt benchmark tool support multi-threading. The wolfSSL SSL/TLS async support has been extended to include all PKI, Encryption/Decryption and hashing/HMAC. An async hardware simulator has been added to test the asynchronous support without hardware.

The Intel QuickAssist port files are located in `wolfcrypt/src/port/intel/quickassist.c` and `wolfssl/wolfcrypt/port/intel/quickassist.h`. The QuickAssist memory handling for NUMA and normal malloc is in `wolfcrypt/src/port/intel/quickassist_mem.c`.

The asynchronous crypto files are located at `wolfcrypt/src/async.c` and `wolfssl/wolfcrypt/async.h`. These files are not in the public repository. Please contact info@wolfssl.com if interested in our asynchronous support to request an evaluation.


## Building

1. Download Driver: The latest driver for QAT can be found here: https://www.intel.com/content/www/us/en/download/19734

2. Notes:

* If you have the older driver installed you may need to remove it or unload the module and reboot.
* If you are using the QAT hardware hashing, you may need to disable the params checking, which doesn't support a last partial with 0 length source input. Code runs and works, but parameter checking will fail.
Use `./configure --disable-param-check && sudo make install`
* If you want to use legacy algorithms like RSA 1024 bit then Use `./configure --enable-legacy-algorithms`
* Recommend not using `make -j` due to synchronization issues on dependencies.

3. Setup `QAT` and `wolfssl` next to each other in the same folder.

4. Build QAT Driver

Prerequisites Ubuntu:
`sudo apt-get install libudev-dev pciutils-dev g++ pkg-config libssl-dev`
OR
Prerequisites CentOS:
`sudo yum install pciutils libudev-devel kernel-devel-$(uname -r) gcc openssl-devel`

```sh
mkdir QAT
cd QAT
tar -zxof QAT.L.4.23.0-00001.tar.gz
./configure
sudo make install
...
There is 3 QAT acceleration device(s) in the system:
 qat_dev0 - type: c6xx,  inst_id: 0,  node_id: 1,  bsf: 0000:84:00.0,  #accel: 5 #engines: 10 state: up
 qat_dev1 - type: c6xx,  inst_id: 1,  node_id: 1,  bsf: 0000:85:00.0,  #accel: 5 #engines: 10 state: up
 qat_dev2 - type: c6xx,  inst_id: 2,  node_id: 1,  bsf: 0000:86:00.0,  #accel: 5 #engines: 10 state: up
```

```sh
$ lspci -d 8086: | grep QuickAssist
84:00.0 Co-processor: Intel Corporation C62x Chipset QuickAssist Technology (rev 04)
85:00.0 Co-processor: Intel Corporation C62x Chipset QuickAssist Technology (rev 04)
86:00.0 Co-processor: Intel Corporation C62x Chipset QuickAssist Technology (rev 04)
```

5. Build wolfSSL:

```sh
cd ../wolfssl
./configure --with-intelqa=../QAT --enable-asynccrypt
make
```


## Usage

Running wolfCrypt test and benchmark must be done with `sudo` to allow hardware access. By default the QuickAssist code uses the "SSL" process name via `QAT_PROCESS_NAME` in quickassist.h to match up to the hardware configuration.

Note: `sudo make check` will fail since default QAT configuration doesn't allow multiple concurrent processes to use hardware. You can run each of the make check scripts individually with sudo. The hardware configuration can be customized by editing the `QAT/build/dh895xcc_qa_dev0.conf` file to allow multiple processes.

Here are some build options for tuning your use:

1. `QAT_USE_POLLING_CHECK`: Enables polling check to ensure only one poll per crypto instance.
2. `WC_ASYNC_THREAD_BIND`: Enables binding of thread to crypto hardware instance.
3. `WOLFSSL_DEBUG_MEMORY_PRINT`: Enables verbose malloc/free printing. This option is used along with `WOLFSSL_DEBUG_MEMORY` and `WOLFSSL_TRACK_MEMORY`.
4. `WC_ASYNC_THRESH_NONE`: Disables the default thresholds for determining if software AES/DES3 is used. Otherwise you can define `WC_ASYNC_THRESH_AES_CBC`, `WC_ASYNC_THRESH_AES_GCM` and `WC_ASYNC_THRESH_DES3_CBC` with your own values. The defaults are AES CBC: 1024, AES GCM 128, DES3 1024. If the symmetric operation is over this size it will use QAT hardware. Otherwise software.
5. `WC_ASYNC_NO_CRYPT`: When defined with disable QAT use for AES/DES3.
6. `WC_ASYNC_NO_HASH`: When defined disables the QAT for hashing (MD5,SHA,SHA256,SHA512).
7. `WC_ASYNC_NO_RNG`: When defined disables the QAT DRBG (default for QAT v1.7)
8. `WC_NO_ASYNC_THREADING`: Disables the thread affinity code for optionally linking a thread to a specific QAT instance. To use this feature you must also define `WC_ASYNC_THREAD_BIND`.
9. `WC_ASYNC_BENCH_THREAD_COUNT`: Use specific number of threads for benchmarking.
10. `QAT_HASH_ENABLE_PARTIAL`: Enables partial hashing support, which allows sending blocks to hardware prior to final. Otherwise all hash updates are cached.

The QuickAssist v1.6 driver uses its own memory management system in `quickassist_mem.c`. This can be tuned using the following defines:

1. `USE_QAE_STATIC_MEM`: Uses a global pool for the list of allocations. This improves performance, but consumes extra up front memory. The pre-allocation size can be tuned using `QAE_USER_MEM_MAX_COUNT`.
2. `USE_QAE_THREAD_LS` : Uses thread-local-storage and removes the mutex. Can improve performance in multi-threaded environment, but does use extra memory.

For QuickAssist v1.7 or later the newer usdm memory driver is used directly.

### Recommended wolfSSL Build Options

```sh
$ ./configure --with-intelqa=../QAT --enable-asynccrypt \
    --enable-aesni --enable-intelasm \
    --enable-sp --enable-sp-asm \
    CFLAGS="-DWC_ASYNC_NO_HASH"
```

* `--with-intelqa=../QAT`: Enables the Intel QuickAssist mode.
* `--enable-asynccrypt`: Enables asynchronous cryptography mode.
* `--enable-aesni`: Enables the Intel AES-NI assembly speedups.
* `--enable-intelasm`: Enables the Intel ASM (AVX/AVX2) speedups.
* `--enable-sp`: Enable Single Precision math to speedup standard key sizes and curves.
* `--enable-sp-asm`: Enable Single Precision assembly speedups.
* `WC_ASYNC_NO_HASH`: Disable the QAT hashing and use Intel AVX accelerated software hashing. Overhead for using QAT hashing is not yet well tuned.


### wolfCrypt Test with QAT
```
sudo ./wolfcrypt/test/testwolfcrypt
IntelQA: Instances 2
...
RSA      test passed!
```

### wolfCrypt Benchmark with QAT 8970 (multi-threaded)

Multiple concurrent threads will be started based on the number of CPU's available. If you want to exclude the software benchmarks use `./configure CFLAGS="-DNO_SW_BENCH"`.

```
Intel QuickAssist DH8950 on Intel(R) Xeon(R) CPU E5-2678 v3 @ 2.50GHz:

Recommended wolfSSL build options when benchmarking.
$ ./configure --enable-sp --enable-sp-asm --enable-aesni --enable-intelasm --enable-intelrand --enable-keygen --enable-sha3 --enable-asynccrypt --with-intelqa=../QAT CFLAGS="-DWC_ASYNC_THRESH_NONE -DQAT_MAX_PENDING=40 -DWC_ASYNC_BENCH_THREAD_COUNT=2"
$ make

$ sudo ./wolfcrypt/benchmark/benchmark -rsa_sign -base10 -threads 2 -print
------------------------------------------------------------------------------
 wolfSSL version 4.5.0
------------------------------------------------------------------------------
IntelQA: Instances 18
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
CPUs: 2
RNG             SW    79 mB took 1.030 seconds,   76.388 mB/s Cycles per byte =  32.65
RNG             SW    79 mB took 1.042 seconds,   75.456 mB/s Cycles per byte =  33.05
AES-128-CBC-enc SW   729 mB took 1.006 seconds,  724.266 mB/s Cycles per byte =   3.44
AES-128-CBC-enc SW   729 mB took 1.007 seconds,  723.825 mB/s Cycles per byte =   3.45
AES-128-CBC-dec SW  5185 mB took 1.000 seconds, 5184.260 mB/s Cycles per byte =   0.48
AES-128-CBC-dec SW  5190 mB took 1.000 seconds, 5189.351 mB/s Cycles per byte =   0.48
AES-192-CBC-enc SW   608 mB took 1.003 seconds,  606.175 mB/s Cycles per byte =   4.11
AES-192-CBC-enc SW   608 mB took 1.004 seconds,  605.855 mB/s Cycles per byte =   4.12
AES-192-CBC-dec SW  4325 mB took 1.000 seconds, 4325.333 mB/s Cycles per byte =   0.58
AES-192-CBC-dec SW  4331 mB took 1.001 seconds, 4325.809 mB/s Cycles per byte =   0.58
AES-256-CBC-enc SW   524 mB took 1.005 seconds,  521.465 mB/s Cycles per byte =   4.78
AES-256-CBC-enc SW   524 mB took 1.006 seconds,  521.190 mB/s Cycles per byte =   4.79
AES-256-CBC-dec SW  3707 mB took 1.000 seconds, 3705.767 mB/s Cycles per byte =   0.67
AES-256-CBC-dec SW  3707 mB took 1.001 seconds, 3703.024 mB/s Cycles per byte =   0.67
AES-128-CBC-enc HW  2443 mB took 1.000 seconds, 2442.819 mB/s Cycles per byte =   1.02
AES-128-CBC-enc HW  2443 mB took 1.000 seconds, 2442.770 mB/s Cycles per byte =   1.02
AES-128-CBC-dec HW  2380 mB took 1.001 seconds, 2378.716 mB/s Cycles per byte =   1.05
AES-128-CBC-dec HW  2380 mB took 1.001 seconds, 2378.657 mB/s Cycles per byte =   1.05
AES-192-CBC-enc HW  2365 mB took 1.002 seconds, 2359.520 mB/s Cycles per byte =   1.06
AES-192-CBC-enc HW  2365 mB took 1.002 seconds, 2359.471 mB/s Cycles per byte =   1.06
AES-192-CBC-dec HW  2417 mB took 1.002 seconds, 2411.874 mB/s Cycles per byte =   1.03
AES-192-CBC-dec HW  2417 mB took 1.002 seconds, 2411.831 mB/s Cycles per byte =   1.03
AES-256-CBC-enc HW  2223 mB took 1.001 seconds, 2221.082 mB/s Cycles per byte =   1.12
AES-256-CBC-enc HW  2218 mB took 1.001 seconds, 2215.793 mB/s Cycles per byte =   1.13
AES-256-CBC-dec HW  2113 mB took 1.002 seconds, 2108.506 mB/s Cycles per byte =   1.18
AES-256-CBC-dec HW  2113 mB took 1.002 seconds, 2108.354 mB/s Cycles per byte =   1.18
AES-128-GCM-enc SW  1919 mB took 1.001 seconds, 1916.366 mB/s Cycles per byte =   1.30
AES-128-GCM-enc SW  2595 mB took 1.001 seconds, 2591.465 mB/s Cycles per byte =   0.96
AES-128-GCM-dec SW  2611 mB took 1.000 seconds, 2610.093 mB/s Cycles per byte =   0.96
AES-128-GCM-dec SW  2218 mB took 1.002 seconds, 2213.073 mB/s Cycles per byte =   1.13
AES-192-GCM-enc SW  2317 mB took 1.001 seconds, 2315.896 mB/s Cycles per byte =   1.08
AES-192-GCM-enc SW  2286 mB took 1.002 seconds, 2281.953 mB/s Cycles per byte =   1.09
AES-192-GCM-dec SW  2207 mB took 1.001 seconds, 2206.098 mB/s Cycles per byte =   1.13
AES-192-GCM-dec SW  1589 mB took 1.002 seconds, 1586.020 mB/s Cycles per byte =   1.57
AES-256-GCM-enc SW  2071 mB took 1.001 seconds, 2069.342 mB/s Cycles per byte =   1.21
AES-256-GCM-enc SW  2108 mB took 1.002 seconds, 2103.268 mB/s Cycles per byte =   1.19
AES-256-GCM-dec SW  2108 mB took 1.001 seconds, 2105.715 mB/s Cycles per byte =   1.18
AES-256-GCM-dec SW  2108 mB took 1.002 seconds, 2103.563 mB/s Cycles per byte =   1.19
AES-128-GCM-enc HW  2427 mB took 1.002 seconds, 2422.522 mB/s Cycles per byte =   1.03
AES-128-GCM-enc HW  2433 mB took 1.002 seconds, 2427.722 mB/s Cycles per byte =   1.03
AES-128-GCM-dec HW  1861 mB took 1.001 seconds, 1860.039 mB/s Cycles per byte =   1.34
AES-128-GCM-dec HW  1861 mB took 1.001 seconds, 1860.019 mB/s Cycles per byte =   1.34
AES-192-GCM-enc HW  2380 mB took 1.000 seconds, 2379.218 mB/s Cycles per byte =   1.05
AES-192-GCM-enc HW  2386 mB took 1.000 seconds, 2384.418 mB/s Cycles per byte =   1.05
AES-192-GCM-dec HW  1971 mB took 1.002 seconds, 1966.480 mB/s Cycles per byte =   1.27
AES-192-GCM-dec HW  1971 mB took 1.002 seconds, 1966.458 mB/s Cycles per byte =   1.27
AES-256-GCM-enc HW  2254 mB took 1.002 seconds, 2249.535 mB/s Cycles per byte =   1.11
AES-256-GCM-enc HW  2254 mB took 1.002 seconds, 2249.487 mB/s Cycles per byte =   1.11
AES-256-GCM-dec HW  1746 mB took 1.001 seconds, 1744.049 mB/s Cycles per byte =   1.43
AES-256-GCM-dec HW  1746 mB took 1.001 seconds, 1744.018 mB/s Cycles per byte =   1.43
CHACHA          SW  1478 mB took 1.000 seconds, 1478.220 mB/s Cycles per byte =   1.69
CHACHA          SW  1347 mB took 1.003 seconds, 1342.833 mB/s Cycles per byte =   1.86
CHA-POLY        SW   949 mB took 1.002 seconds,  946.915 mB/s Cycles per byte =   2.63
CHA-POLY        SW   949 mB took 1.005 seconds,  944.670 mB/s Cycles per byte =   2.64
MD5             SW   603 mB took 1.003 seconds,  601.383 mB/s Cycles per byte =   4.15
MD5             SW   613 mB took 1.005 seconds,  610.413 mB/s Cycles per byte =   4.09
MD5             HW   409 mB took 1.002 seconds,  408.088 mB/s Cycles per byte =   6.11
MD5             HW   409 mB took 1.003 seconds,  407.845 mB/s Cycles per byte =   6.12
POLY1305        SW  2621 mB took 1.000 seconds, 2620.709 mB/s Cycles per byte =   0.95
POLY1305        SW  2616 mB took 1.001 seconds, 2613.824 mB/s Cycles per byte =   0.95
SHA             SW   377 mB took 1.003 seconds,  376.342 mB/s Cycles per byte =   6.63
SHA             SW   383 mB took 1.011 seconds,  378.592 mB/s Cycles per byte =   6.59
SHA             HW   535 mB took 1.005 seconds,  531.941 mB/s Cycles per byte =   4.69
SHA             HW   535 mB took 1.006 seconds,  531.644 mB/s Cycles per byte =   4.69
SHA-224         SW   351 mB took 1.010 seconds,  347.715 mB/s Cycles per byte =   7.17
SHA-224         SW   351 mB took 1.014 seconds,  346.285 mB/s Cycles per byte =   7.20
SHA-224         HW   414 mB took 1.012 seconds,  409.434 mB/s Cycles per byte =   6.09
SHA-224         HW   419 mB took 1.012 seconds,  414.387 mB/s Cycles per byte =   6.02
SHA-256         SW   351 mB took 1.011 seconds,  347.292 mB/s Cycles per byte =   7.18
SHA-256         SW   315 mB took 1.013 seconds,  310.424 mB/s Cycles per byte =   8.03
SHA-256         HW   419 mB took 1.004 seconds,  417.688 mB/s Cycles per byte =   5.97
SHA-256         HW   419 mB took 1.005 seconds,  417.427 mB/s Cycles per byte =   5.98
SHA-384         SW   530 mB took 1.001 seconds,  529.040 mB/s Cycles per byte =   4.71
SHA-384         SW   530 mB took 1.003 seconds,  528.139 mB/s Cycles per byte =   4.72
SHA-384         HW   357 mB took 1.001 seconds,  356.156 mB/s Cycles per byte =   7.00
SHA-384         HW   367 mB took 1.010 seconds,  363.498 mB/s Cycles per byte =   6.86
SHA-512         SW   530 mB took 1.002 seconds,  528.589 mB/s Cycles per byte =   4.72
SHA-512         SW   446 mB took 1.009 seconds,  441.540 mB/s Cycles per byte =   5.65
SHA-512         HW   367 mB took 1.004 seconds,  365.434 mB/s Cycles per byte =   6.83
SHA-512         HW   367 mB took 1.005 seconds,  365.224 mB/s Cycles per byte =   6.83
SHA3-224        SW   236 mB took 1.014 seconds,  232.784 mB/s Cycles per byte =  10.71
SHA3-224        SW   236 mB took 1.018 seconds,  231.794 mB/s Cycles per byte =  10.76
SHA3-224        HW   220 mB took 1.006 seconds,  218.860 mB/s Cycles per byte =  11.40
SHA3-224        HW   236 mB took 1.015 seconds,  232.538 mB/s Cycles per byte =  10.73
SHA3-256        SW   163 mB took 1.000 seconds,  162.463 mB/s Cycles per byte =  15.35
SHA3-256        SW   225 mB took 1.023 seconds,  220.278 mB/s Cycles per byte =  11.32
SHA3-256        HW   692 mB took 1.004 seconds,  689.291 mB/s Cycles per byte =   3.62
SHA3-256        HW   692 mB took 1.007 seconds,  687.092 mB/s Cycles per byte =   3.63
SHA3-384        SW   173 mB took 1.022 seconds,  169.214 mB/s Cycles per byte =  14.74
SHA3-384        SW   173 mB took 1.024 seconds,  168.878 mB/s Cycles per byte =  14.77
SHA3-384        HW   173 mB took 1.023 seconds,  169.202 mB/s Cycles per byte =  14.74
SHA3-384        HW   173 mB took 1.024 seconds,  168.948 mB/s Cycles per byte =  14.76
SHA3-512        SW   121 mB took 1.026 seconds,  117.548 mB/s Cycles per byte =  21.22
SHA3-512        SW   121 mB took 1.027 seconds,  117.375 mB/s Cycles per byte =  21.25
SHA3-512        HW   121 mB took 1.026 seconds,  117.585 mB/s Cycles per byte =  21.21
SHA3-512        HW   121 mB took 1.028 seconds,  117.335 mB/s Cycles per byte =  21.26
HMAC-MD5        SW   608 mB took 1.000 seconds,  608.096 mB/s Cycles per byte =   4.10
HMAC-MD5        SW   613 mB took 1.004 seconds,  611.102 mB/s Cycles per byte =   4.08
HMAC-MD5        HW   414 mB took 1.001 seconds,  413.762 mB/s Cycles per byte =   6.03
HMAC-MD5        HW   414 mB took 1.004 seconds,  412.554 mB/s Cycles per byte =   6.05
HMAC-SHA        SW   383 mB took 1.011 seconds,  378.446 mB/s Cycles per byte =   6.59
HMAC-SHA        SW   383 mB took 1.013 seconds,  377.729 mB/s Cycles per byte =   6.60
HMAC-SHA        HW   535 mB took 1.008 seconds,  530.760 mB/s Cycles per byte =   4.70
HMAC-SHA        HW   514 mB took 1.009 seconds,  509.292 mB/s Cycles per byte =   4.90
HMAC-SHA224     SW   267 mB took 1.008 seconds,  265.316 mB/s Cycles per byte =   9.40
HMAC-SHA224     SW   351 mB took 1.012 seconds,  346.982 mB/s Cycles per byte =   7.19
HMAC-SHA224     HW   404 mB took 1.003 seconds,  402.579 mB/s Cycles per byte =   6.20
HMAC-SHA224     HW   393 mB took 1.011 seconds,  388.951 mB/s Cycles per byte =   6.41
HMAC-SHA256     SW   294 mB took 1.007 seconds,  291.426 mB/s Cycles per byte =   8.56
HMAC-SHA256     SW   351 mB took 1.012 seconds,  347.205 mB/s Cycles per byte =   7.18
HMAC-SHA256     HW   419 mB took 1.004 seconds,  417.677 mB/s Cycles per byte =   5.97
HMAC-SHA256     HW   419 mB took 1.009 seconds,  415.514 mB/s Cycles per byte =   6.00
HMAC-SHA384     SW   530 mB took 1.002 seconds,  528.479 mB/s Cycles per byte =   4.72
HMAC-SHA384     SW   530 mB took 1.007 seconds,  526.093 mB/s Cycles per byte =   4.74
HMAC-SHA384     HW   367 mB took 1.004 seconds,  365.498 mB/s Cycles per byte =   6.82
HMAC-SHA384     HW   367 mB took 1.006 seconds,  364.878 mB/s Cycles per byte =   6.84
HMAC-SHA512     SW   530 mB took 1.002 seconds,  528.616 mB/s Cycles per byte =   4.72
HMAC-SHA512     SW   530 mB took 1.006 seconds,  526.513 mB/s Cycles per byte =   4.74
HMAC-SHA512     HW   367 mB took 1.003 seconds,  365.816 mB/s Cycles per byte =   6.82
HMAC-SHA512     HW   367 mB took 1.007 seconds,  364.560 mB/s Cycles per byte =   6.84
RSA     1024 key gen   SW     40 ops took 1.191 sec, avg 29.780 ms, 33.580 ops/sec
RSA     1024 key gen   SW     40 ops took 1.428 sec, avg 35.694 ms, 28.016 ops/sec
RSA     2048 key gen   SW     40 ops took 4.154 sec, avg 103.853 ms, 9.629 ops/sec
RSA     2048 key gen   SW     40 ops took 5.687 sec, avg 142.172 ms, 7.034 ops/sec
RSA     1024 key gen   HW    120 ops took 1.064 sec, avg 8.866 ms, 112.790 ops/sec
RSA     1024 key gen   HW    120 ops took 1.072 sec, avg 8.932 ms, 111.953 ops/sec
RSA     2048 key gen   HW     40 ops took 1.389 sec, avg 34.717 ms, 28.804 ops/sec
RSA     2048 key gen   HW     40 ops took 1.437 sec, avg 35.935 ms, 27.828 ops/sec
RSA     2048 sign      SW   1000 ops took 1.046 sec, avg 1.046 ms, 956.197 ops/sec
RSA     2048 sign      SW   1000 ops took 1.052 sec, avg 1.052 ms, 950.320 ops/sec
RSA     2048 verify    SW  32300 ops took 1.001 sec, avg 0.031 ms, 32271.670 ops/sec
RSA     2048 verify    SW  32200 ops took 1.003 sec, avg 0.031 ms, 32117.110 ops/sec
RSA     2048 sign      HW  12300 ops took 1.001 sec, avg 0.081 ms, 12288.056 ops/sec
RSA     2048 sign      HW  19600 ops took 1.003 sec, avg 0.051 ms, 19537.967 ops/sec
RSA     2048 verify    HW 116000 ops took 1.000 sec, avg 0.009 ms, 115971.935 ops/sec
RSA     2048 verify    HW 118000 ops took 1.000 sec, avg 0.008 ms, 117962.707 ops/sec
DH      2048 key gen   SW   2080 ops took 1.000 sec, avg 0.481 ms, 2079.830 ops/sec
DH      2048 key gen   SW   2120 ops took 1.016 sec, avg 0.479 ms, 2086.548 ops/sec
DH      2048 agree     SW   2100 ops took 1.023 sec, avg 0.487 ms, 2053.478 ops/sec
DH      2048 agree     SW   2100 ops took 1.026 sec, avg 0.489 ms, 2046.644 ops/sec
DH      2048 key gen   HW  43720 ops took 1.000 sec, avg 0.023 ms, 43712.257 ops/sec
DH      2048 key gen   HW  43320 ops took 1.000 sec, avg 0.023 ms, 43299.560 ops/sec
DH      2048 agree     HW  32500 ops took 1.001 sec, avg 0.031 ms, 32471.874 ops/sec
DH      2048 agree     HW  39400 ops took 1.001 sec, avg 0.025 ms, 39351.757 ops/sec
ECC      256 key gen   SW  41320 ops took 1.001 sec, avg 0.024 ms, 41298.692 ops/sec
ECC      256 key gen   SW  41280 ops took 1.001 sec, avg 0.024 ms, 41258.674 ops/sec
ECC      256 key gen   HW  41320 ops took 1.000 sec, avg 0.024 ms, 41309.127 ops/sec
ECC      256 key gen   HW  41280 ops took 1.001 sec, avg 0.024 ms, 41244.118 ops/sec
ECDHE    256 agree     SW  13400 ops took 1.005 sec, avg 0.075 ms, 13328.731 ops/sec
ECDHE    256 agree     SW  13300 ops took 1.006 sec, avg 0.076 ms, 13221.465 ops/sec
ECDSA    256 sign      SW  29900 ops took 1.002 sec, avg 0.034 ms, 29841.744 ops/sec
ECDSA    256 sign      SW  30000 ops took 1.003 sec, avg 0.033 ms, 29910.091 ops/sec
ECDSA    256 verify    SW  10700 ops took 1.006 sec, avg 0.094 ms, 10641.471 ops/sec
ECDSA    256 verify    SW  10700 ops took 1.009 sec, avg 0.094 ms, 10604.105 ops/sec
ECDHE    256 agree     HW  26600 ops took 1.000 sec, avg 0.038 ms, 26594.522 ops/sec
ECDHE    256 agree     HW  19000 ops took 1.002 sec, avg 0.053 ms, 18964.479 ops/sec
ECDSA    256 sign      HW  22300 ops took 1.001 sec, avg 0.045 ms, 22286.137 ops/sec
ECDSA    256 sign      HW  22000 ops took 1.002 sec, avg 0.046 ms, 21963.146 ops/sec
ECDSA    256 verify    HW  12600 ops took 1.002 sec, avg 0.080 ms, 12569.531 ops/sec
ECDSA    256 verify    HW  12600 ops took 1.005 sec, avg 0.080 ms, 12542.829 ops/sec
Benchmark complete
RNG             SW  151.844 mB/s
AES-128-CBC-enc SW 1448.090 mB/s
AES-128-CBC-dec SW 10373.612 mB/s
AES-192-CBC-enc SW 1212.030 mB/s
AES-192-CBC-dec SW 8651.141 mB/s
AES-256-CBC-enc SW 1042.655 mB/s
AES-256-CBC-dec SW 7408.791 mB/s
AES-128-CBC-enc HW 4885.588 mB/s
AES-128-CBC-dec HW 4757.373 mB/s
AES-192-CBC-enc HW 4718.991 mB/s
AES-192-CBC-dec HW 4823.705 mB/s
AES-256-CBC-enc HW 4436.875 mB/s
AES-256-CBC-dec HW 4216.860 mB/s
AES-128-GCM-enc SW 4507.831 mB/s
AES-128-GCM-dec SW 4823.166 mB/s
AES-192-GCM-enc SW 4597.849 mB/s
AES-192-GCM-dec SW 3792.119 mB/s
AES-256-GCM-enc SW 4172.610 mB/s
AES-256-GCM-dec SW 4209.278 mB/s
AES-128-GCM-enc HW 4850.244 mB/s
AES-128-GCM-dec HW 3720.058 mB/s
AES-192-GCM-enc HW 4763.636 mB/s
AES-192-GCM-dec HW 3932.937 mB/s
AES-256-GCM-enc HW 4499.022 mB/s
AES-256-GCM-dec HW 3488.068 mB/s
CHACHA          SW 2821.053 mB/s
CHA-POLY        SW 1891.585 mB/s
MD5             SW 1211.796 mB/s
MD5             HW  815.933 mB/s
POLY1305        SW 5234.533 mB/s
SHA             SW  754.934 mB/s
SHA             HW 1063.586 mB/s
SHA-224         SW  694.001 mB/s
SHA-224         HW  823.821 mB/s
SHA-256         SW  657.716 mB/s
SHA-256         HW  835.115 mB/s
SHA-384         SW 1057.178 mB/s
SHA-384         HW  719.655 mB/s
SHA-512         SW  970.129 mB/s
SHA-512         HW  730.657 mB/s
SHA3-224        SW  464.579 mB/s
SHA3-224        HW  451.398 mB/s
SHA3-256        SW  382.741 mB/s
SHA3-256        HW 1376.382 mB/s
SHA3-384        SW  338.092 mB/s
SHA3-384        HW  338.150 mB/s
SHA3-512        SW  234.923 mB/s
SHA3-512        HW  234.921 mB/s
HMAC-MD5        SW 1219.198 mB/s
HMAC-MD5        HW  826.316 mB/s
HMAC-SHA        SW  756.175 mB/s
HMAC-SHA        HW 1040.052 mB/s
HMAC-SHA224     SW  612.297 mB/s
HMAC-SHA224     HW  791.530 mB/s
HMAC-SHA256     SW  638.631 mB/s
HMAC-SHA256     HW  833.191 mB/s
HMAC-SHA384     SW 1054.571 mB/s
HMAC-SHA384     HW  730.376 mB/s
HMAC-SHA512     SW 1055.130 mB/s
HMAC-SHA512     HW  730.377 mB/s
RSA   1024 key gen   SW 61.596 ops/sec
RSA   2048 key gen   SW 16.663 ops/sec
RSA   1024 key gen   HW 224.743 ops/sec
RSA   2048 key gen   HW 56.632 ops/sec
RSA   2048 sign      SW 1906.517 ops/sec
RSA   2048 verify    SW 64388.780 ops/sec
RSA   2048 sign      HW 31826.022 ops/sec
RSA   2048 verify    HW 233934.642 ops/sec
DH    2048 key gen   SW 4166.378 ops/sec
DH    2048 agree     SW 4100.122 ops/sec
DH    2048 key gen   HW 87011.816 ops/sec
DH    2048 agree     HW 71823.630 ops/sec
ECC    256 key gen   SW 82557.366 ops/sec
ECC    256 key gen   HW 82553.245 ops/sec
ECDHE  256 agree     SW 26550.196 ops/sec
ECDSA  256 sign      SW 59751.835 ops/sec
ECDSA  256 verify    SW 21245.576 ops/sec
ECDHE  256 agree     HW 45559.001 ops/sec
ECDSA  256 sign      HW 44249.283 ops/sec
ECDSA  256 verify    HW 25112.360 ops/sec
IntelQA: Stop
```

### wolfCrypt Benchmark with QAT (single-threaded)

To use the benchmark tool against hardware in single threaded mode build the library with `CFLAGS="-DWC_NO_ASYNC_THREADING"`.

```
sudo ./wolfcrypt/benchmark/benchmark -rsa_sign -dh -ecc
IntelQA: Instances 2
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
RSA     2048 public    HW 161000 ops took 1.000 sec, avg 0.006 ms, 160989.829 ops/sec
RSA     2048 private   HW  18600 ops took 1.002 sec, avg 0.054 ms, 18566.416 ops/sec
DH      2048 key gen   HW  48945 ops took 1.000 sec, avg 0.020 ms, 48931.782 ops/sec
DH      2048 agree     HW  43300 ops took 1.001 sec, avg 0.023 ms, 43248.876 ops/sec
ECDHE    256 agree     HW  26400 ops took 1.001 sec, avg 0.038 ms, 26382.639 ops/sec
ECDSA    256 sign      HW  23900 ops took 1.004 sec, avg 0.042 ms, 23810.849 ops/sec
ECDSA    256 verify    HW  13800 ops took 1.000 sec, avg 0.072 ms, 13799.878 ops/sec
IntelQA: Stop
```

### wolfSSL Asynchronous Test Mode

Enable asynccrypt alone to use async simulator.
`./configure --enable-asynccrypt`


## Debugging

To enable debug messages:
`./configure --enable-asynccrypt --with-intelqa=../QAT --enable-debug --disable-shared CFLAGS="-DQAT_DEBUG" && make`


## Support

For questions or issues email us at support@wolfssl.com.
