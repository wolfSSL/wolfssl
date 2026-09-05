# wolfCrypt test and benchmark on EFR32xG25

Runs the wolfCrypt algorithm self-test and benchmark on an EFR32xG25 with crypto routed to the Secure Element through the wolfSSL crypto callback port. Builds headlessly with `slc-cli` and GNU Arm - no Simplicity Studio GUI needed.

For the port itself, including which algorithms are offloaded and the Secure Vault key management API, see [/wolfcrypt/src/port/silabs/README.md](/wolfcrypt/src/port/silabs/README.md).

## Hardware

An xG25 radio board (BRD4270B, BRD4271A or BRD4272A) on a BRD4002A/BRD4001A mainboard. All three radio boards carry `EFR32FG25B222F1920IM56`: Series 2 Config 5, Secure Vault **High**, 1920 KB flash. Set `BOARD` if yours is not the default BRD4270B:

```sh
BOARD=brd4271a ./build.sh
```

The application prints the SE firmware version and the detected Secure Vault level at startup, so a captured log records which silicon produced the numbers under it.

## Toolchain

Install headlessly with Silicon Labs Tool (SLT). As of SLC-CLI v6 the CLI is no longer a direct download; SLT fetches it along with the SDK, GNU Arm and Commander from a recipe:

```sh
mkdir -p ~/silabs && cd ~/silabs
wget -O slt-cli.zip \
  "https://www.silabs.com/documents/public/software/slt-cli-1.2.1-linux-x64.zip"
unzip -o slt-cli.zip && chmod +x slt
cat > pkg.slt <<'RECIPE'
[dependency]
simplicity-sdk = "~"
slc-cli = "~"
gcc-arm-none-eabi = "~"
commander = "~"
RECIPE
./slt install
```

Check the current SLT version on the [command line development page](https://www.silabs.com/software-and-tools/simplicity-studio/configurator-command-line-development). `build.sh` and `flash.sh` read `~/.silabs/sdks.json` and `~/.silabs/tools.json` to locate everything, so no paths are hardcoded. Override `SDK`, `SLC`, `GCC_DIR` or `COMMANDER` in the environment if your install lives elsewhere.

Developed against Simplicity SDK 2026.6.1 (platform 6.0.0), slc-cli 6.0.23, Commander 1.24.3, GNU Arm 14.2.rel1.

## Build and flash

```sh
./build.sh          # slc generate + make, output in ./build
./flash.sh          # commander device info, flash, reset
```

Then read the VCOM output at 115200 8N1. On a bench running the `uart-monitor` daemon, tail its log rather than opening the port directly.

## What to expect

`wolfcrypt_test` must report a full PASS. Because `WOLFSSL_SILABS_CRYPTOCB` points `WC_USE_DEVID` at the SE device, every algorithm the port claims runs on the Secure Element, so a PASS is direct evidence the callback is correct against the known-answer vectors.

The benchmark then runs each algorithm twice, labelling rows `HW` and `SW`, which gives a hardware-versus-software comparison in one run.

## Measured results

Captured on an **EFR32FG25B222F1920IM56** (Secure Vault High, SE firmware 2.2.0) with this project, wolfSSL 5.9.2. `wolfcrypt_test` reports a **full PASS** in both builds below; the software/Secure Element pairs are the `HW` and `SW` rows the benchmark prints in one run.

Both builds define the `--enable-harden` options (`ECC_TIMING_RESISTANT`, `WC_RSA_BLINDING`), so these are hardened numbers. They cost nothing measurable here: this configuration routes P-256 through `WOLFSSL_SP_MATH_ALL`/`WOLFSSL_HAVE_SP_ECC`, which is already constant time, and every ECC and RSA row moved by less than 0.3% when the options were added.

The two software columns are two builds of this project. **Software (C)** is what you get out of the box. **Software (Thumb2 asm)** additionally enables the `WOLFSSL_ARMASM` block near the top of `user_settings.h` -- flip its `#if 0` to `#if 1` to reproduce it. Both builds already use `WOLFSSL_SP_ARM_CORTEX_M_ASM` for ECC, so the ECC rows do not move.

| Algorithm | Software (C) | Software (Thumb2 asm) | Secure Element | SE vs C | SE vs asm |
|---|---|---|---|---|---|
| RNG SHA-256 DRBG | 332 KiB/s | 408 KiB/s | **93 KiB/s** | **0.3x** | **0.2x** |
| AES-128-CBC-enc | 856 KiB/s | 986 KiB/s | **2.63 MiB/s** | **3.2x** | **2.7x** |
| AES-128-CBC-dec | 854 KiB/s | 985 KiB/s | **2.65 MiB/s** | **3.2x** | **2.8x** |
| AES-192-CBC-enc | 722 KiB/s | 826 KiB/s | **2.60 MiB/s** | **3.7x** | **3.2x** |
| AES-192-CBC-dec | 722 KiB/s | 820 KiB/s | **2.59 MiB/s** | **3.7x** | **3.2x** |
| AES-256-CBC-enc | 627 KiB/s | 710 KiB/s | **2.58 MiB/s** | **4.2x** | **3.7x** |
| AES-256-CBC-dec | 626 KiB/s | 712 KiB/s | **2.59 MiB/s** | **4.2x** | **3.7x** |
| AES-128-GCM-enc | 293 KiB/s | 629 KiB/s | **2.37 MiB/s** | **8.3x** | **3.9x** |
| AES-128-GCM-dec | 291 KiB/s | 626 KiB/s | **2.26 MiB/s** | **8.0x** | **3.7x** |
| AES-192-GCM-enc | 275 KiB/s | 558 KiB/s | **2.38 MiB/s** | **8.9x** | **4.4x** |
| AES-192-GCM-dec | 274 KiB/s | 556 KiB/s | **2.24 MiB/s** | **8.4x** | **4.1x** |
| AES-256-GCM-enc | 260 KiB/s | 502 KiB/s | **2.38 MiB/s** | **9.4x** | **4.8x** |
| AES-256-GCM-dec | 258 KiB/s | 501 KiB/s | **2.23 MiB/s** | **8.8x** | **4.6x** |
| AES-128-GCM-enc-no_AAD | 296 KiB/s | 632 KiB/s | **2.44 MiB/s** | **8.4x** | **3.9x** |
| AES-128-GCM-dec-no_AAD | 294 KiB/s | 630 KiB/s | **2.28 MiB/s** | **7.9x** | **3.7x** |
| AES-192-GCM-enc-no_AAD | 278 KiB/s | 560 KiB/s | **2.41 MiB/s** | **8.9x** | **4.4x** |
| AES-192-GCM-dec-no_AAD | 276 KiB/s | 559 KiB/s | **2.30 MiB/s** | **8.5x** | **4.2x** |
| AES-256-GCM-enc-no_AAD | 262 KiB/s | 505 KiB/s | **2.35 MiB/s** | **9.2x** | **4.8x** |
| AES-256-GCM-dec-no_AAD | 261 KiB/s | 503 KiB/s | **2.23 MiB/s** | **8.8x** | **4.5x** |
| AES-128-ECB-enc | 876 KiB/s | 992 KiB/s | **2.84 MiB/s** | **3.3x** | **2.9x** |
| AES-128-ECB-dec | 882 KiB/s | 988 KiB/s | **2.77 MiB/s** | **3.2x** | **2.9x** |
| AES-192-ECB-enc | 737 KiB/s | 824 KiB/s | **2.74 MiB/s** | **3.8x** | **3.4x** |
| AES-192-ECB-dec | 741 KiB/s | 833 KiB/s | **2.79 MiB/s** | **3.9x** | **3.4x** |
| AES-256-ECB-enc | 638 KiB/s | 711 KiB/s | **2.70 MiB/s** | **4.3x** | **3.9x** |
| AES-256-ECB-dec | 640 KiB/s | 710 KiB/s | **2.71 MiB/s** | **4.3x** | **3.9x** |
| AES-128-CTR | 852 KiB/s | 977 KiB/s | **2.63 MiB/s** | **3.2x** | n/a |
| AES-192-CTR | 720 KiB/s | 820 KiB/s | **2.62 MiB/s** | **3.7x** | n/a |
| AES-256-CTR | 625 KiB/s | 705 KiB/s | **2.63 MiB/s** | **4.3x** | n/a |
| AES-CCM-enc | 426 KiB/s | 460 KiB/s | **2.20 MiB/s** | **5.3x** | **4.9x** |
| AES-CCM-dec | 425 KiB/s | 459 KiB/s | **2.14 MiB/s** | **5.1x** | **4.8x** |
| AES-CCM-enc-no_AAD | 426 KiB/s | 460 KiB/s | **2.20 MiB/s** | **5.3x** | **4.9x** |
| AES-CCM-dec-no_AAD | 425 KiB/s | 459 KiB/s | **2.11 MiB/s** | **5.1x** | **4.7x** |
| SHA-1 | 3.91 MiB/s | 3.92 MiB/s | **3.63 MiB/s** | **0.9x** | **0.9x** |
| SHA-224 | 1.23 MiB/s | 1.99 MiB/s | **3.67 MiB/s** | **3.0x** | **1.8x** |
| SHA-256 | 1.23 MiB/s | 1.99 MiB/s | **3.67 MiB/s** | **3.0x** | **1.8x** |
| AES-128-CMAC | 793 KiB/s | 856 KiB/s | **2.45 MiB/s** | **3.2x** | **2.9x** |
| AES-256-CMAC | 593 KiB/s | 640 KiB/s | **2.40 MiB/s** | **4.1x** | **3.8x** |
| HMAC-SHA-1 | 3.87 MiB/s | 3.87 MiB/s | **3.01 MiB/s** | **0.8x** | **0.8x** |
| HMAC-SHA-224 | 1.22 MiB/s | 1.97 MiB/s | **3.04 MiB/s** | **2.5x** | **1.5x** |
| HMAC-SHA-256 | 1.22 MiB/s | 1.97 MiB/s | **3.04 MiB/s** | **2.5x** | **1.5x** |
| ECC 256 key gen | 125.4 ops/s | 125.3 ops/s | **180.6 ops/s** | **1.4x** | **1.4x** |
| ECDHE 256 agree | 65.4 ops/s | 65.4 ops/s | **179.8 ops/s** | **2.7x** | **2.7x** |
| ECDSA 256 sign | 67.8 ops/s | 67.8 ops/s | **173.4 ops/s** | **2.6x** | **2.6x** |
| ECDSA 256 verify | 41.9 ops/s | 41.9 ops/s | **163.8 ops/s** | **3.9x** | **3.9x** |

Where the Secure Element is **slower** the numbers are reported as measured. SHA-1 and HMAC-SHA-1 are cheap enough on this Cortex-M33 that the SE round trip costs more than it saves. The **RNG** row compares asking the SE for every byte against a SHA-256 DRBG seeded once from that same SE TRNG - seeding a DRBG is the normal way to use a hardware entropy source, so the `HW` row is raw TRNG throughput rather than the cost of getting random data. **AES-GCM** gains the most, up to **9.4x**.

**AES-CTR** reads `n/a` in the last column because the port deliberately declines CTR when `WOLFSSL_ARMASM` is defined -- the Thumb2 keystream remainder and the SE's do not line up -- so that build has no Secure Element CTR number.

**RSA** and **DH** are omitted because Series 2 has no RSA hardware, so both columns run in software. **SHA-384/512** likewise, and they are always left to software (see the port README). **ChaCha20-Poly1305** has no paired row because its one-shot API carries no `devId`; it is still offloaded.

To check the software fallback path, offload a subset by adding one or more engine macros to `user_settings.h` (for example only `WOLFSSL_SILABS_CRYPTOCB_HASH`) and re-run: everything else must still pass, in software.

## TLS 1.3 over the Secure Element

Flip the `WOLFSSL_XG25_TLS13` block at the top of `user_settings.h` to `#if 1`
and rebuild. The application then runs `tls13_test.c` between the wolfCrypt
test and the benchmark: a client and a server, both on the device, wired
together through two in-memory byte queues, with the Secure Element `devId` set
on both. It runs the handshake once per TLS 1.3 cipher suite and then pushes
application data through the record layer.

This covers ground the known answer vectors cannot. Handshake and record
buffers are cursors into a larger buffer, so the engines see arbitrary byte
offsets rather than aligned stack arrays, and one `Aes` object is reused across
many chained records, so any state the port fails to carry between calls shows
up as a decrypt failure instead of passing on a single shot. The two suites
differ in which hash drives the key schedule: `TLS13-AES128-GCM-SHA256` runs it
on the SE, while `TLS13-AES256-GCM-SHA384` runs it in software, so between them
they cover both the offloaded and the fallback hash path.

Measured result on the kit:

```
--- TLS 1.3 over the Secure Element ---
  [TLS13-AES128-GCM-SHA256]
  handshake OK: TLSv1.3 TLS_AES_128_GCM_SHA256
  record layer OK: 9 payloads, 1 to 255 bytes
  [TLS13-AES256-GCM-SHA384]
  handshake OK: TLSv1.3 TLS_AES_256_GCM_SHA384
  record layer OK: 9 payloads, 1 to 255 bytes
tls13_test returned 0 (PASS)
```

The kit has no battery-backed real time clock, so `app.c` supplies a
`_gettimeofday()` seeded from the build date, overriding newlib's weak stub.
Without it `time()` returns -1, every certificate reads as not yet valid and
the CA fails to load with `ASN_BEFORE_DATE_E` (-150). That clock is good enough
for a self-contained demo and nothing more: a device that cannot tell the time
cannot tell a valid certificate from an expired one, so a real design needs an
RTC, a time server, or a provisioned time that an attacker cannot move.

## Notes

* The SE firmware must be recent enough for the SE Manager commands used. xG25 is Series 2 Config 5, so it takes the `s2c5` firmware package - not the `s2c1` package referenced by older wolfSSL SiLabs documentation. Check with `commander device info` and upgrade with `commander flash` if needed.
* `user_settings.h` is shared by the library and the application, as wolfSSL requires. Changing feature macros in one and not the other corrupts struct layouts at runtime.
* RSA has no hardware support on Series 2 and stays in software; the benchmark rows for it are software timings.
