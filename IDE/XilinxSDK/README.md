# Xilinx SDK wolfCrypt Project

To use this example project:
1. Start a new workspace
2. Create a new BSP called `standalone_bsp_0`.
3. Copy `.cproject` and `.project` into the wolfSSL root.
4. From the Xilinx SDK Import wolfBoot using "Import" -> "Existing Projects into Workspace".

## Platform

Tested on the Zynq UltraScale+ MPSoC (ZUC102).

This is a bare-metal example for wolfCrypt only with algorithm support for:
* RNG
* RSA
* ECC
* AES-GCM
* ChaCha20
* Poly1305
* SHA2
* SHA3
* PBKDF2

## Benchmark Results

```
------------------------------------------------------------------------------
 wolfSSL version 4.3.0
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min  sec each)
RNG                 72 MB took 1.000 seconds,   72.388 MB/s
AES-128-GCM-enc    370 MB took 1.000 seconds,  370.312 MB/s
AES-128-GCM-dec    187 MB took 1.000 seconds,  187.451 MB/s
AES-192-GCM-enc    341 MB took 1.000 seconds,  341.382 MB/s
AES-192-GCM-dec    180 MB took 1.000 seconds,  179.663 MB/s
AES-256-GCM-enc    316 MB took 1.000 seconds,  316.382 MB/s
AES-256-GCM-dec    172 MB took 1.000 seconds,  172.485 MB/s
CHACHA             256 MB took 1.000 seconds,  255.859 MB/s
CHA-POLY            98 MB took 1.000 seconds,   97.559 MB/s
POLY1305           517 MB took 1.000 seconds,  516.895 MB/s
SHA-256            535 MB took 1.000 seconds,  534.595 MB/s
SHA-384            123 MB took 1.000 seconds,  123.291 MB/s
SHA-512            124 MB took 1.000 seconds,  123.657 MB/s
SHA3-224            70 MB took 1.000 seconds,   70.337 MB/s
SHA3-256            67 MB took 1.000 seconds,   66.528 MB/s
SHA3-384            53 MB took 1.000 seconds,   52.710 MB/s
SHA3-512            38 MB took 1.000 seconds,   37.598 MB/s
HMAC-SHA256        520 MB took 1.000 seconds,  520.093 MB/s
HMAC-SHA384        121 MB took 1.000 seconds,  121.265 MB/s
HMAC-SHA512        121 MB took 1.000 seconds,  121.289 MB/s
PBKDF2              28 KB took 1.000 seconds,   28.375 KB/s
ECC      256 key gen      8518 ops took 1.000 sec, avg 0.117 ms, 8518.000 ops/sec
ECDHE    256 agree        1818 ops took 1.000 sec, avg 0.550 ms, 1818.000 ops/sec
ECDSA    256 sign         4448 ops took 1.000 sec, avg 0.225 ms, 4448.000 ops/sec
ECDSA    256 verify       1430 ops took 1.000 sec, avg 0.699 ms, 1430.000 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```
