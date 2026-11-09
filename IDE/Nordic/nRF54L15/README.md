# wolfCrypt CRACEN test on the nRF54L15 DK

Bare-metal GCC project that runs the CRACEN crypto callback port
(`wolfcrypt/src/port/nordic/`) on an nRF54L15 DK and checks every offloaded
algorithm against wolfCrypt's software implementation, then runs the full
`wolfcrypt_test()` suite through the device.

No Zephyr or nRF Connect SDK is needed. The build fetches two header
dependencies with sparse git checkouts: the Nordic MDK/HAL from nrfx
(device header, startup, system init, linker script, UARTE and GPIO HAL) and
the CMSIS core headers. Both are BSD-3-Clause / Apache-2.0.

## Prerequisites

- `arm-none-eabi-gcc` (any recent release)
- `git`
- `nrfutil` with the `device` command, for flashing
- a terminal program for the DK's first virtual COM port, 115200 8N1

## Build and run

```sh
cd IDE/Nordic/nRF54L15
make deps      # once; clones into deps/
make
make flash     # nrfutil device program ... + reset
```

Console output appears on the DK's VCOM0 (UARTE20, TX on P1.04, the same
port Zephyr uses for the console), for example:

```sh
picocom -b 115200 /dev/ttyACM0
```

## What it prints

```
wolfCrypt CRACEN test, nRF54L15
CRACEN engines 0x..., AES modes 0x..., AES ctr size 0x..., hash cfg 0x..., RNG cfg 0x...
  TRNG 65536 bytes in ... cycles: ... kB/s
  65536 bytes: ones .../1000, byte chi-square ... (255 dof), longest run ..., entropy ... mbit/byte, repeated blocks 0
  TRNG starts 1, error recoveries 0, alarms: repetition 0, proportion 0, AIS31 preliminary 0, AIS31 0, last status 0x..., bytes ...
RNG      TRNG sanity and Hash-DRBG: ok
SHA-256  known answer: ok
SHA-1    streaming vs software, 160 lengths: ok
SHA-224  streaming vs software, 160 lengths: ok
SHA-256  streaming vs software, 160 lengths: ok
SHA-384  streaming vs software, 160 lengths: ok
SHA-512  streaming vs software, 160 lengths: ok
SHA-256  copy, GetHash and reuse: ok
SHA-256  HMAC vs software, 45 cases: ok
SHA-384  HMAC vs software, 45 cases: ok
AES      ECB vs software, 18 cases: ok
AES      CBC chained vs software, 18 cases: ok
AES      CTR streaming vs software, 243 cases: ok
AES      GCM vs software, 300 cases: ok
AES      CMAC streaming vs software, 258 cases: ok
Timing at 128000000 Hz:
  SHA-256  4096 bytes hw: ... cycles
  ...

wolfcrypt_test() with devId 0x4352:
...
wolfcrypt_test() return code 0

ALL TESTS PASSED
```

A mismatch prints the failing case with both digests or tags. The first line
of hardware information is worth keeping with any bug report: it is the
engine presence and capability registers the port gates on.

## Layout

| File | Role |
|---|---|
| `Makefile` | Build, dependency fetch, flash |
| `linker.ld` | Memory map (RRAM at 0, 256 KB RAM); sections from the MDK's `nrf_common.ld` |
| `user_settings.h` | wolfCrypt configuration: SHA-1/2, HMAC, AES ECB/CBC/CTR/GCM/CCM, CMAC, Hash-DRBG; no public key |
| `src/main.c` | The tests |
| `src/board.c` | UARTE20 console, newlib `_write`/`_sbrk`, DWT cycle counter |

The application runs in the secure state straight from reset, which is what
CRACEN requires. Stack is 32 KB and heap 96 KB (`__STACK_SIZE`, `__HEAP_SIZE`
in the Makefile).

## TRNG checks

The RNG section reads 64 KB of conditioned TRNG output, prints the
throughput, and applies loose sanity bounds that a healthy source never trips:
ones fraction within 0.496..0.504, byte chi-square between 150 and 400
(255 degrees of freedom, expectation 255), no run of identical bits longer
than 48, at least 7.95 bits of byte entropy, no repeated 16-byte block. It then
reads odd sizes, powers the TRNG down and reads again (restart path), seeds
the Hash-DRBG through `wc_GenerateSeed()`, and prints the driver's counters.
Any error recovery (FSM error or start-up test failure) is reported as a
failure, since a sound board should see none.

For a proper statistical run on the host, build with a dump:

```sh
make TRNG_DUMP=1048576        # 1 MB of raw output, ~3 min at 115200 baud
make flash
picocom -b 115200 /dev/ttyACM0 --logfile trng.log      # wait for ---END TRNG---
sed -n '/---BEGIN TRNG---/,/---END TRNG---/p' trng.log | grep -v -- '---' | tr -d '\r' | xxd -r -p > trng.bin
ent trng.bin
dieharder -a -g 201 -f trng.bin   # or rngtest < trng.bin
```

## Variations

- `make CFLAGS_EXTRA=-DWOLFSSL_CRACEN_RNG_DIRECT` serves `wc_RNG_GenerateBlock()`
  straight from the TRNG instead of the Hash-DRBG.
- `make CFLAGS_EXTRA=-DWOLFSSL_CRACEN_TRNG_ON_DEMAND` powers the TRNG down
  after every read, trading start-up latency for idle power.
- Edit `user_settings.h` to drop algorithms; the port and the tests follow the
  same feature macros.
- `make NRFX_TAG=<tag>` pins a different nrfx release for the MDK.
