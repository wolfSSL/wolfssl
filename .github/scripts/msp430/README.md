# MSP430 simulator tests

These tests cross-compile wolfCrypt with TI's MSP430 GCC and execute the ELF
files with the bundled GNU simulator. Docker and Python 3 are the host
dependencies. The container uses Linux/amd64 and also runs through Docker on
Apple Silicon.

From the wolfSSL repository root:

```sh
# Original MSP430, MSP430X and P-256, with software multiplication.
sh .github/scripts/msp430/run-docker.sh

# Full P-256 suite with the simulator's F5-series hardware multiplier.
MSP430_HWMULT=f5series sh .github/scripts/msp430/run-docker.sh "$PWD" ecc
```

An explicit wolfSSL source directory can be the first argument, followed by
one or more profiles. The workflow in `.github/workflows/msp430-sim.yml` runs
the following matrix:

| Profile | ISA and memory model | Tests |
| --- | --- | --- |
| `small` | Original MSP430, small | Separate SHA-224/256, HMAC-SHA256, ChaCha, Poly1305, ChaCha20-Poly1305, AES-CBC/CTR/GCM executables |
| `large` | MSP430X, large | Combined symmetric wolfCrypt suite and an explicit SHA-256 check with code and data above 64 KiB |
| `ecc`, software multiply | MSP430X, large | Captured ECDSA regression, invalid digest/signature checks, and the full P-256 `ecc_test()` |
| `ecc`, F5 multiply | MSP430X, large | The same P-256 coverage with `MSP430_HWMULT=f5series` |

All profiles check the target ABI and a known 64-bit multiplication. A separate
program must return guest exit status 7. Crypto tests must return zero and print
their exact completion marker; faults, timeouts and early simulator stops fail
the run. Splitting the small-model subtests keeps each executable within its
64 KiB address space.

## Toolchain and output

The wrapper downloads TI package 9.3.1.2, containing GCC 9.3.1.11 and GNU
simulator 9.1, from TI's versioned `software-dl.ti.com` archive. It verifies TI's
published archive SHA-256 before building:

```text
b60851b61565e3ddd2193298a3fac5120c2402597174106cc5f8482b9e9986e6
```

The source and harness mounts are read-only during compilation and execution.
Generated files stay in ignored directories at the source root:

| Setting | Default, relative to the wolfSSL source directory |
| --- | --- |
| `MSP430_CACHE_DIR` | `.msp430-gcc-cache` |
| `MSP430_OUTPUT_DIR` | `.msp430-sim-build` |
| `MSP430_TEST_TIMEOUT` | `900` seconds per crypto executable |
| `MSP430_HWMULT` | `none`; also accepts `f5series` |

Each profile directory contains compiler logs, simulator logs, ELF files and
linker maps. `timings.txt` records simulator wall time, not hardware timing.

## TI GCC register workaround

With the pinned compiler, a large-model `-Os` build of
`sp_256_rshift1_9()` uses the R8/R9 register pair for its final 32-bit shift but
only saves R8 and R10. The modular-inverse caller keeps its bit counter in R9;
the shift silently overwrites that counter. A valid ECDSA signature can then
be rejected with `verify == 0` and no API error.

The large-model builds reserve R9 with `-ffixed-r9`. This prevents the bad
allocation without changing the cryptographic arithmetic. Apply the same
workaround when using this TI compiler for another large-model MSP430 GCC
project; IAR is not covered by this compiler setting.

`ecdsa_regression.c` retains the public key, digest and raw R||S signature from
the original failure, independently verified with OpenSSL. It checks acceptance
of that signature and rejection after changing either the digest or signature.
Keep this test when upgrading the compiler, and recheck before removing the
register workaround.

The ECC configuration explicitly selects `WOLFSSL_SP_ALLOW_16BIT_CPU` with
32-bit SP words. It uses deterministic test entropy and only P-256. This
fixture must not be used as an entropy source in firmware.

## Coverage limits

This is functional CPU, ABI and crypto coverage using GNU's generic simulator
memory map. It does not establish fit on a particular physical MCU, hardware
timing, board/peripheral behaviour, production entropy, TLS or IAR correctness.
`BENCH_EMBEDDED` omits oversized cases. The existing monolithic `test.c` emits
16-bit conversion warnings for some large line-number/error diagnostics;
implicit function declarations are treated as errors.

References:

- [TI MSP430 GCC downloads](https://www.ti.com/tool/MSP430-GCC-OPENSOURCE)
- [Pinned Linux toolchain archive](https://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/9_3_1_2/export/msp430-gcc-9.3.1.11_linux64.tar.bz2)
- [GCC MSP430 options](https://gcc.gnu.org/onlinedocs/gcc/MSP430-Options.html)
