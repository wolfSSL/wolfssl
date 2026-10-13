# wolfSSL for Green Hills INTEGRITY on the TI AM64x (Cortex-A53)

This directory holds a Green Hills MULTI/gbuild project that builds wolfSSL
for INTEGRITY on the TI AM64x (AM6442) application cores, plus a test
application that runs the wolfCrypt test and benchmark. Hardware support is:

- **TRNG (always on):** the SA2UL true random number generator seeds
  wolfCrypt's RNG (`CUSTOM_RAND_GENERATE_SEED`).
- **SA2UL crypto offload (optional):** AES-ECB/CBC/GCM (128/192/256-bit
  keys) and SHA-224/256/384/512 on the SA2UL engine, through a wolfCrypt
  crypto callback device. Off unless `WOLFSSL_SA2UL_DRIVER` is defined.

The port sources live in `wolfcrypt/src/port/ti/integrity/` and
`wolfssl/wolfcrypt/port/ti/integrity/`.

## Prerequisites

- Green Hills MULTI with the Arm64 compiler (developed with compiler
  2025.1.4) and INTEGRITY 19.1.x (developed with 19.1.4).
- The INTEGRITY `platform-jacinto7` BSP, which supports the AM64x. The
  board's device tree is the BSP's AM64x EVM tree (`k3-am64-evm`).
- A boot chain that starts OP-TEE before INTEGRITY. OP-TEE initializes the
  TRNG and opens its firewall (see OP-TEE's `sa2ul_init()`); the TRNG driver
  depends on that. TI's firmware (TIFS) normally has the SA2UL engines
  enabled already.
- Tested on the TI AM64x EVM (AM6442).

## Layout

| Path | Contents |
|---|---|
| `default.gpj` | Top-level project: paths, the SA2UL switch, build configurations |
| `user_settings.h` | wolfSSL configuration, shared by the library and the app |
| `proj/myproject.gpj` | The INTEGRITY application (kernel, test app, library, loader) |
| `proj/myproject.int` | Integrate file: kernel and `wolfssl_test_app` AddressSpace |
| `proj/myproject_kernel.gpj`, `myproject_kernel.c` | Kernel, including the kernel-side TRNG and SA2UL drivers |
| `proj/libwolfssl.gpj` | wolfSSL library |
| `proj/wolfssl_test_app.gpj`, `wolfssl_test.c` | Test app: `wolfcrypt_test()` then `benchmark_test()` |
| `proj/system_loader.*` | Standard INTEGRITY system loader |
| `tgt/` | Linker directives, `default.bsp` and build configuration files |

## Configure

Edit the macros at the top of `default.gpj`:

- `__OS_DIR`: your INTEGRITY installation. It is hard-coded to
  `C:\ghs\int1914`; change it for your machine.
- `__WOLFSSL_DIR`: the wolfSSL source tree. It defaults to two directories
  above `default.gpj` (`%expand_path(..\..)`), so it only needs changing if
  this project is moved out of the wolfSSL tree.
- `__BSP_NAME` / `-bsp`: `platform-jacinto7`.

wolfSSL features are set in `user_settings.h`. The library and the app are
both built with `-DWOLFSSL_USER_SETTINGS` and the same `user_settings.h`;
keep it that way, as mismatched feature macros corrupt memory at run time.

## Build

Open `default.gpj` in MULTI and build, or from a command prompt:

```
gbuild -top default.gpj -cfg=Debug
```

Configurations: `Debug`, `Checked` and `Release` (`tgt/npw_*.gpc`). Only
`Debug` has been tested. Output goes to `dbg/` (`chk/`, `rel/`) next to
`default.gpj`; those directories are in wolfSSL's `.gitignore`. The bootable
monolith image is `dbg/bin/proj/myproject`.

Load and boot `myproject` the way you normally boot an INTEGRITY monolith on
the board (for example, from U-Boot or with a MULTI debug connection).

## Run

The kernel's initial task prints `Hello world!` when boot completes.
`wolfssl_test_app` is not started automatically (`DefaultStartIt` is false);
start it from the INTEGRITY serial debug console or from MULTI. It runs the
wolfCrypt test, then the benchmark, and prints `wolfcrypt_test PASSED` and
`benchmark_test PASSED`.

## SA2UL hardware offload

### Enabling it

It is controlled by `macro WOLFSSL_SA2UL_DRIVER=1` in `default.gpj`: leave
that line in to enable it, comment it out to disable it, then rebuild. That
one switch:

- builds the kernel-side drivers (`sa2ul_driver.c`, `sa2ul_devtree_driver.c`,
  `sa2ul_iodevice_server.c`) into the kernel,
- passes `-DWOLFSSL_SA2UL_DRIVER` to the kernel, the library and the app, and
  `user_settings.h` then enables the crypto callback
  (`WOLFSSL_TI_AM64X_A53_INTEGRITY`, `WOLF_CRYPTO_CB`, ...),
- sets the intex variable that adds the two shared pages to
  `proj/myproject.int` (see below).

Without it the build is pure software, with no crypto callbacks.

### How it works

The SA2UL is driven by a kernel-linked driver, which tasks use through an
IODevice named `Sa2ulDev`:

- **Device tree:** the driver binds to the `ti,am64-sa2ul` node
  (`crypto@40900000`) in the BSP's AM64x device tree, and uses its `dmas`
  entries (PKTDMA PSI-L threads `0xc001` tx, `0x4002`/`0x4003` rx). The TRNG
  driver binds to the child `inside-secure,safexcel-eip76` node. No device
  tree changes are needed for the AM64x EVM tree.
- **DMA:** the driver allocates its own DMA memory and sets up the SAUL
  PKTDMA channels through TI's firmware. The SAUL channels and flows must be
  assigned to the A53 host in TI's resource-management board configuration;
  TI's default configuration does this.
- **Shared pages:** each request and its data pass through two one-page
  MemoryRegions declared in `proj/myproject.int`: `sa2ul_ctrl_phys` and
  `sa2ul_data_phys` in the kernel, mapped into `wolfssl_test_app` as
  `sa2ul_ctrl_local` and `sa2ul_data_local`. The kernel's `main()`
  (`myproject_kernel.c`) attaches them to the IODevice at boot. Any other
  AddressSpace that uses the port needs the same two MemoryRegions (same
  names), because `sa2ul_port.c` includes the generated
  `myproject_integrate.h` to find them.
- **Fallback:** if the driver is unavailable or an operation fails, wolfCrypt
  falls back to software for that operation.

With the driver enabled, boot prints a `sa2ul:` line for each init step and
ends with `sa2ul: init done`.

### Performance and tuning

Each SA2UL operation is a round trip through the kernel and the DMA engine
(roughly 60 us measured), so the A53's own ARMv8 crypto instructions are
faster in raw throughput. Small requests therefore stay in software by
default:

| Macro | Default | Meaning |
|---|---|---|
| `WOLFSSL_SA2UL_ECB_MIN_SZ` | 32 | Smallest AES-ECB request sent to the SA2UL (16 sends every block) |
| `WOLFSSL_SA2UL_HASH_MIN_SZ` | 1024 | Smallest SHA-2 message sent to the SA2UL (1 sends every hash) |

Hashes are buffered for one SA2UL pass of up to 4 KB, one hash at a time;
longer messages, and hashes that are copied (e.g. the TLS 1.3 transcript),
continue in software.

Other build-time options:

| Macro | Meaning |
|---|---|
| `WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_AES` | Keep AES in software |
| `WOLFSSL_TI_AM64X_A53_INTEGRITY_NO_SHA` | Keep SHA-2 in software |
| `SA2UL_POLL_LIMIT`, `RNG_POLL_LIMIT` | Polling budgets for an SA2UL operation / TRNG result |
| `SA2UL_SCCTL2_PRIVID_VAL`, `_PRIV_VAL`, `_SECURE_VAL` | Security-context attributes (default `0xc3`/0/0, as in TI's SDK) |
| `SA2UL_NO_TRACE` | Drop the `sa2ul:` boot trace lines |
| `SA2UL_ENGINE_CONTROL` | Read/enable the CP_ACE engine registers at init (off: they may be firewalled from the A53) |

## Notes

- `user_settings.h` currently defines `WOLFSSL_ARMASM_NO_HW_CRYPTO`: the
  Green Hills assembler rejects the `.arch_extension crypto` directive used
  by wolfSSL's ARMv8 inline assembly. The crypto instructions themselves
  assemble without any directive. Remove the define once that is resolved.
- `WC_BENCH_CYCLES_FROM_CLOCK` makes the benchmark derive cycle counts from
  the system clock, because the two A53 cores' virtual timers differ.
