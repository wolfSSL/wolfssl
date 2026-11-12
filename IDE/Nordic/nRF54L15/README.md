# wolfCrypt CRACEN test on the nRF54L15 DK

Bare-metal GCC project that runs the CRACEN crypto callback port
(`wolfcrypt/src/port/nordic/`) on an nRF54L15 DK and checks every offloaded
algorithm against wolfCrypt's software implementation, then runs the full
`wolfcrypt_test()` suite through the device.

No Zephyr or nRF Connect SDK is needed. The build fetches two header
dependencies with sparse git checkouts: the Nordic MDK/HAL from nrfx
(device header, startup, system init, linker script, UARTE and GPIO HAL) and
the CMSIS core headers. Both are BSD-3-Clause / Apache-2.0. It also downloads
one file from the nRF Connect SDK: the public key engine microcode
(`microcode_binary.h`, LicenseRef-Nordic-5-Clause), pinned to a commit with
`SDK_NRF_REF` in the Makefile. That file stays in `deps/` and is compiled into
the test firmware only; review its license before redistributing a binary.
Without it the build still works and the public key algorithms run in
software.

## Prerequisites

- `arm-none-eabi-gcc` (any recent release)
- `git`
- `curl`, for the microcode header
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
PK microcode 1223 words: load 0, ready 1, PK cfg 0x01f72200
  TRNG 16384 bytes in ... cycles: ... kB/s
  16384 bytes: ones .../1000, byte chi-square ... (255 dof), longest run ..., entropy ... mbit/byte, repeated blocks 0
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
  P-192            keygen hw/sw ..., ECDH hw/sw ..., sign hw/sw ..., verify hw/sw ... cycles
ECC P-192            keygen, ECDH, ECDSA vs software: ok
ECC P-224            keygen, ECDH, ECDSA vs software: ok
ECC P-256            keygen, ECDH, ECDSA vs software: ok
ECC P-384            keygen, ECDH, ECDSA vs software: ok
ECC P-521            keygen, ECDH, ECDSA vs software: ok
ECC brainpoolP256r1  keygen, ECDH, ECDSA vs software: ok
RSA-2048  sign, verify, encrypt, decrypt vs software: ok
DH-2048   agree vs software: ok
X25519    keygen, shared secret vs software: ok
Ed25519   keygen, sign, verify (plain, ctx, ph) vs software: ok
Timing at 128000000 Hz:
  SHA-256  4096 bytes hw: ... cycles
  ...

wolfcrypt_test() with devId 0x4352:
...
wolfcrypt_test() return code 0
TAMPC status 0x00000000, tamper events 0, CRACEN tamper 0

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
| `user_settings.h` | wolfCrypt configuration: SHA-1/2, HMAC, AES ECB/CBC/CTR/GCM/CCM, CMAC, Hash-DRBG, ECC (P-192 to P-521, Brainpool), RSA, DH, X25519, Ed25519 |
| `src/main.c` | The tests |
| `src/board.c` | UARTE20 console, newlib `_write`/`_sbrk`, DWT cycle counter, TAMPC access |
| `deps/cracen_microcode.h` | Nordic's `ba414ep_ucode`, fetched by `make deps` |

The application runs in the secure state straight from reset, which is what
CRACEN requires. It is compiled as the secure image (`-mcmse`) so the MDK's
`SystemInit` applies the device trims and errata workarounds and opens the
debug access port, which TAMPC otherwise closes at every reset; the SAU is
left disabled (`NRF_SKIP_SAU_CONFIGURATION`) so the whole address map,
including the image at RRAM 0x0, stays secure. Stack is 32 KB and heap 176 KB (`__STACK_SIZE`, `__HEAP_SIZE`
in the Makefile); the heap has to hold the 128 KB buffer of the test suite's
long AES-CCM message case.

If `make flash` reports that the access port is protected, a previous image
left it closed: run `nrfutil device recover` once and flash again.

## TRNG checks

The RNG section reads 16 KB of conditioned TRNG output (about 8 s: the
TRNG delivers about 2 kB/s with Nordic's sampling divider), prints the
throughput, and applies loose sanity bounds that a healthy source never trips:
ones fraction within 0.494..0.506, byte chi-square between 150 and 400
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

## Public key checks

Each public key algorithm is exercised with one key object on the device
(`WOLFSSL_CRACEN_DEVID`) and one in software (`INVALID_DEVID`): keys generated
on the device are re-derived in software from the exported private value, the
two sides exchange public keys, agree on ECDH/DH/X25519 secrets that must
match, verify each other's ECDSA, RSA and Ed25519 signatures, and must reject
tampered signatures, digests and ciphertexts and points off the curve.
Deterministic outputs (PKCS#1 v1.5 and Ed25519 signatures) must be identical
on both sides. Cycle counts for the device and software paths are printed per
operation.

The PK engine and its sibling the IKG are monitored by the chip's tamper
controller. With the chip's defaults a "malicious use" event resets the device,
which on this test looks like the console output stopping and the banner
appearing again. To see the event instead of the reset, build with

```sh
make TAMPER_RESET=0
```

which clears `PROTECT.INTRESETEN` in TAMPC at start-up. In both builds the
last line before the verdict is the TAMPC status (`STATUS`, `EVENTS_TAMPER`,
`PROTECT.CRACENTAMP.STATUS`); any non-zero event counts as a failure.

## Variations

- `make CFLAGS_EXTRA=-DWOLFSSL_CRACEN_RNG_DIRECT` serves `wc_RNG_GenerateBlock()`
  straight from the TRNG instead of the Hash-DRBG.
- `make CFLAGS_EXTRA=-DWOLFSSL_CRACEN_TRNG_ON_DEMAND` powers the TRNG down
  after every read, trading start-up latency for idle power.
- Edit `user_settings.h` to drop algorithms; the port and the tests follow the
  same feature macros.
- `make NRFX_TAG=<tag>` pins a different nrfx release for the MDK;
  `make SDK_NRF_REF=<commit>` a different nRF Connect SDK revision for the
  microcode (delete `deps/cracen_microcode.h` first).
- `make CFLAGS_EXTRA=-DWOLFSSL_CRACEN_PK_NO_CM` runs the public key
  operations without the engine's side channel countermeasures.
