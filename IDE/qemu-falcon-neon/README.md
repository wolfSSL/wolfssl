# qemu-falcon-neon

Minimal bare-metal AArch64 firmware that runs a full native Falcon
keygen -> sign -> verify round-trip (levels 1 and 5) under
`qemu-system-aarch64 -machine virt`, exercising the **NEON** (2-wide
`float64x2_t` + FMA) FFT on the signing / key-generation path
(`WOLFSSL_FALCON_FFT_NEON`, over the inline-double fpr backend).

A genuine signature must verify and a one-byte-tampered signature must be
rejected, for both levels. The result is reported over ARM semihosting:
`NEON_FFT_PASS` on success, `NEON_FFT_FAIL` otherwise, then qemu exits.

The startup (`start.S`) installs exception vectors, enables FP/Advanced SIMD
(`CPACR_EL1`), and brings up a flat identity MMU marking RAM as Normal
cacheable memory (required so the crypto code's unaligned accesses don't
fault).

Build (needs an AArch64 bare-metal toolchain, e.g. `aarch64-none-elf-gcc`):
```sh
make -C IDE/qemu-falcon-neon CC=aarch64-none-elf-gcc
```

Run:
```sh
qemu-system-aarch64 -machine virt -cpu cortex-a53 -nographic -semihosting \
    -kernel IDE/qemu-falcon-neon/app-falcon-neon.elf
```

Confirm the NEON vector FMA was compiled into the FFT:
```sh
make -C IDE/qemu-falcon-neon CC=aarch64-none-elf-gcc dis
grep -E 'fmla\s+v[0-9]+\.2d' IDE/qemu-falcon-neon/app-falcon-neon.dis
```

In a wolfSSL library build, the NEON FFT is enabled with
`--enable-falcon=neon` (AArch64; implies the `double` fpr backend).
