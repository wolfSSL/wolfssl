# Intel QuickAssist Adapter Asynchronous Support

The wolfSSL / wolfCrypt libraries support hardware crypto acceleration using the Intel QuickAssist adapter. This software has been tested using the Intel DH8970 and DH8950 QuickAssist adapters.

## Overview

Support has been added for wolfCrypt for RSA public/private (CRT/non-CRT), AES CBC/GCM, ECDH/ECDSA, DH, DES3, SHA, SHA224, SHA256, SHA384, SHA512, MD5 and HMAC. RSA padding is done via software. The wolfCrypt tests and benchmarks have asynchronous support. The wolfCrypt benchmark tool support multi-threading. The wolfSSL SSL/TLS async support has been extended to include all PKI, Encryption/Decryption and hashing/HMAC. An async hardware simulator has been added to test the asynchronous support without hardware.

The Intel QuickAssist port files are located in `wolfcrypt/src/port/intel/quickassist.c` and `wolfssl/wolfcrypt/port/intel/quickassist.h`. The QuickAssist memory handling for NUMA and normal malloc is in `wolfcrypt/src/port/intel/quickassist_mem.c`.

The asynchronous crypto files are located at `wolfcrypt/src/async.c` and `wolfssl/wolfcrypt/async.h`. These files are not in the public repository. Please contact facts@wolfssl.com if interested in our asynchronous support to request an evaluation.


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

Running wolfCrypt test and benchmark requires access to the QAT hardware. By default the QuickAssist code uses the "SSL" process name via `QAT_PROCESS_NAME` in quickassist.h to match up to the hardware configuration. The device configuration file is per device and named for the device type, for example `/etc/c6xx_dev0.conf` (older docs reference `dh895xcc_qa_dev0.conf`).

### Running without sudo

Recent QAT driver installs ship a udev rule (`/etc/udev/rules.d/00-qat.rules`) that assigns the `qat` group to `/dev/usdm_drv`, `/dev/qat_dev_processes`, `/dev/qat_adf_ctl` and `/dev/hugepages/qat`. To use the hardware as a normal user, add yourself to that group and start a fresh login shell:

```sh
sudo usermod -aG qat $USER
# log out/in (or 'newgrp qat'), then verify:
ls -l /dev/usdm_drv /dev/qat_dev_processes   # should be group 'qat', mode 0660
./wolfcrypt/test/testwolfcrypt               # no sudo; prints 'IntelQA: Instances N'
```

If `testwolfcrypt` prints `Could not start qae mem for user space (status -2)` and `Running without async`, the usdm memory driver is not accessible (group not applied yet, or the `usdm_drv` module is not loaded). Crypto then runs in software (the QAT NUMA allocator falls back to regular memory when the device is not up); bring the driver up to get hardware acceleration.

### make check

When configured `--with-intelqa`, the build (and so `make check`) is serialized automatically (`.NOTPARALLEL` in `Makefile.am`), because the QAT driver cannot serve the many concurrent user processes a `make -j` test run would launch. A single test still runs a server and a client, so raise `NumProcesses` in the `[SSL]` section of each `/etc/<device>_dev<N>.conf` (default `1`, e.g. to 3) and restart the driver, then run `make check` normally:

```sh
sudo systemctl restart qat   # clean usdm state
make check
```

Note: against a healthy QAT (boot-time hugepages reserved; see the diagnostics
section below) `testsuite/testsuite.test` passes with all instances up and no
`-173`. The remaining `resume.test` / `unit.test` flakiness is QAT
contiguous-memory exhaustion, not a code defect: each test launches a fresh
server+client, and once the usdm pool fragments those processes fail SAL init
(`Lac_MemPoolCreate ... contiguous chunk`) and fall back to software or time
out. Runtime `vm.nr_hugepages` cannot reliably reserve a large pool once memory
is fragmented, so boot-time hugepages are required for back-to-back QAT tests.

Two real code bugs were found and fixed in this change: the software-fallback
NUMA allocation bug (`-142`/`-140`, crypto failed instead of running in
software when the device could not be opened), and a TLS 1.3 hybrid PQC server
key-share async bug that produced `SSL_connect -173`. The latter only triggers
when the ECDH key generation completes synchronously and only the shared-secret
offloads/suspends ("B-first" ordering, which is what QAT does): the server then
dropped the ML-KEM ciphertext and sent only the 65-byte ECDH public key. To
reproduce deterministically without QAT hardware, build
`--enable-asynccrypt --enable-asynccrypt-sw` and make `wc_AsyncSwInit()` return
0 for `ASYNC_SW_ECC_MAKE` (keygen synchronous, shared-secret still suspends),
then run a hybrid-group (e.g. P256+ML-KEM-768) TLS 1.3 handshake; the default
simulator does A-then-B ordering and does not exercise this path.

### Diagnosing / probing QAT health

If wolfCrypt prints `Could not start sal for user space`, `SalCtrl_ServiceInit Failed to initialise all service instances`, or falls back to `Running without async`, the user-space SAL could not bring up the device. Useful probes:

```sh
sudo adf_ctl status                 # per-device kernel state (look for 'state: down')
sudo dmesg | grep -iE 'c6xx|qat|heartbeat|ras|reset|orphan'   # device events
lspci -s 09:00.0 -vv | grep -iE 'UESta|CESta'                 # PCIe Advanced Error Reporting (a '+' = real bus error)
cat /sys/module/usdm_drv/parameters/max_huge_pages            # usdm hugepage mode
grep HugePages_Total /proc/meminfo                            # actually-reserved hugepages
ls /sys/kernel/debug/qat_c6xx_<bdf>/                          # heartbeat, fw_counters, etc.
```

Common causes seen in practice:

- Hugepage mismatch: `usdm_drv` loaded with `max_huge_pages` > 0 but `HugePages_Total` is smaller (or 0) -- every QAT process then fails its SAL memory init. Either reserve enough hugepages at boot (GRUB `default_hugepagesz=2M hugepagesz=2M hugepages=N`) or reload `usdm_drv` with `max_huge_pages=0` (non-hugepage contiguous memory). Runtime `sysctl vm.nr_hugepages=N` is unreliable once memory is fragmented.
- Orphan rings: `dmesg` shows `Process <pid> ... exit with orphan rings`. A QAT process exited (often killed by a test timeout) without an orderly `wolfAsync_HardwareStop`/`icp_sal_userStop`, leaking instance rings. These accumulate (especially under `make -j` test runs) until the device's instance pool is exhausted and new processes can no longer init. Recover with a full driver-stack reload (`systemctl stop qat; rmmod usdm_drv qat_c62x intel_qat; modprobe qat_c62x; modprobe usdm_drv; systemctl start qat`) or a reboot. Always shut down QAT-using processes cleanly; avoid `make -j` (see make check above).
- PCIe Advanced Error Reporting errors (`UESta`/`CESta` flags set) or `dmesg` heartbeat/RAS/reset messages indicate a real firmware hang or bus error; with `AutoResetOnError = 0` (default in the device conf) the device stays down until a manual `adf_ctl reset`. Set `AutoResetOnError = 1` in `/etc/<device>_dev*.conf` for self-healing.

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
11. `QAT_NO_DEV_INTERLEAVE`: Disables interleaving crypto instances across devices. By default the instance list is reordered so consecutive threads land on different QAT devices, so thread counts below the total instance count still exercise every device instead of filling the first one.

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

### wolfCrypt Benchmark with QAT

Multiple concurrent threads are started based on the number of CPUs available. To exclude the software benchmarks use `./configure CFLAGS="-DNO_SW_BENCH"`.

To fully utilize a multi-device system, use at least as many benchmark threads as there are crypto instances (`-threads N`, where N >= the "IntelQA: Instances" count), since each thread is bound to one instance. Instances are spread across devices by default (`IntelQaInterleaveInstances`, disable with `QAT_NO_DEV_INTERLEAVE`), so even a thread count lower than the instance count exercises every device rather than filling the first one. For maximum throughput also raise the in-flight depth with `CFLAGS="-DQAT_MAX_PENDING=40 -DWC_ASYNC_THRESH_NONE"`. Example on a 3-device (18-instance) system: `-threads 18` or higher.

#### Latest measured performance (3x Intel C62x)

Host: Intel Core i9-14900K; 3x Intel C62x Chipset QuickAssist Technology (rev 04), 18 crypto instances; wolfSSL 5.9.1; `./configure --enable-asynccrypt --with-intelqa=../QAT`.

Public-key throughput aggregated across all 3 devices (`-threads 18`, hardware):

| algorithm | HW ops/sec |
|---|---|
| RSA-2048 private | 76,865 |
| RSA-2048 public  | 29,428 |
| ECDSA-256 sign   | 45,152 |
| ECDSA-256 verify | 72,200 |
| ECDHE-256 agree  | 100,514 |
| DH-2048 agree    | 141,390 |
| DH-2048 key gen  | 58,418  |

Bulk AES throughput, single instance (`-threads 1`, hardware). On this AES-NI host the software AES path is faster, so QAT AES is gated behind size thresholds (`WC_ASYNC_THRESH_*`) and `WC_ASYNC_NO_HASH` is recommended; the offload value here is the public-key work above.

| algorithm | enc MB/s | dec MB/s |
|---|---|---|
| AES-128-CBC | 552 | 619 |
| AES-256-CBC | 411 | 443 |
| AES-128-GCM | 256 | 126 |
| AES-256-GCM | 219 | 117 |

Note: higher-thread AES on this host hits usdm contiguous-memory exhaustion without boot-time hugepages (see the diagnostics section above); the public-key benchmarks use small buffers and scale cleanly to all 18 instances.

### wolfSSL Asynchronous Test Mode

Enable asynccrypt alone to use async simulator.
`./configure --enable-asynccrypt`


## Debugging

To enable debug messages:
`./configure --enable-asynccrypt --with-intelqa=../QAT --enable-debug --disable-shared CFLAGS="-DQAT_DEBUG" && make`


## Support

For questions or issues email us at support@wolfssl.com.
