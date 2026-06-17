# RealTek AmebaPro2 (RTL8735B) HUK Port

Binds wolfCrypt keys to the RTL8735B silicon Hardware Unique Key (HUK) through
the AmebaPro2 HAL crypto engine, via the wolfCrypt crypto-callback (CryptoCb)
framework. A 256-bit "seed" is run through the HAL HKDF key-ladder against the
HUK to land a device-bound working key in a secure key-storage slot; AES
(GCM/ECB/CBC/CTR) then runs from that slot and the working key never enters
software. It is a pure crypto-callback device and adds no wolfSSL core API or
struct fields: AES reads its seed from the standard `aes->devKey`, and ECDSA
reads a `wc_Rtl8735b_EccKey` (the HUK-wrapped scalar + seed) the caller attaches
via the standard `ecc_key->devCtx`. This mirrors the device pattern the STM32
DHUK port (`wc_Stm32_DhukRegister`) also uses.

## Hardware

RTL8735B / AmebaPro2 security blocks used by this port (from the
`Ameba-AIoT/nuwa_hal_realtek` SDK, `rtl8735b` branch, headers under
`ameba/amebapro2/source/fwlib/rtl8735b/include/`):

- HUK in OTP: `SB_OTP_HIGH_VAL_HUK1` (0x21), `HUK2` (0x22), `HUK_RMA` (0x2F).
- HKDF key-ladder in secure RAM: `hal_hkdf_hmac_sha256_secure_init`,
  `hal_hkdf_extract_secure_all`, `hal_hkdf_expand_secure_all` -- derive the HUK
  into a secure key-storage slot without exposing the key to software.
- AES secure-key ops that reference the derived slot by number:
  `hal_crypto_aes_ecb_sk_init`, `hal_crypto_aes_gcm_sk_init` (key never leaves
  hardware).
- Secure-key HMAC-SHA256 (`hal_crypto_hmac_sha2_256_sk_init` /
  `hal_crypto_hmac_sha2_256_update` / `_sk_final`) MAC'ing over the HUK-derived
  slot, so the HMAC key also never enters software.
- HUK-bound ECDSA sign has two backends: software sign after an AES secure-key
  unwrap of the wrapped scalar (default), or the HW ECDSA engine (`hal_ecdsa.h`)
  with the private scalar either unwrapped (INPUT PRK) or OTP-resident via
  `hal_ecdsa_select_prk` (`ECDSA_OTP_PRK_1/2`, scalar never in software).
- Secure TRNG (`hal_trng_sec.h`, `hal_trng_sec_init` / `hal_trng_sec_get_rand`) exposed as the
  crypto-callback SEED source. The plain TRNG (`hal_trng.h`) is also available; the
  `ameba-zephyr-pro2-platform` repo provides a Zephyr entropy driver
  (`entropy_rtl8735b.c`, DT `realtek,amebapro2-trng`) that feeds wolfCrypt's
  `wc_GenerateSeed` via `sys_rand_get`.

## Enabling

```c
#define WOLFSSL_RTL8735B_HUK   /* enable the AmebaPro2 HUK device */
#define WOLF_CRYPTO_CB        /* required -- HUK routes through crypto callbacks */
```

Set these in `user_settings.h`. The application/board CMake must add
the AmebaPro2 HAL include directory (e.g.
`.../fwlib/rtl8735b/include/`) to the wolfSSL library include path so this port
can include `hal_crypto.h` and `hal_hkdf.h`.

Two build implications to be aware of when enabling the port:

- It requires AES-ECB (the CBC/CTR modes chain over single-block secure-key ECB
  operations), so `--enable-rtl8735b` adds `-DHAVE_AES_ECB` to the whole build;
  define `HAVE_AES_ECB` yourself when configuring via `user_settings.h`.
- For multi-threaded use the port relies on the wolfCrypt HW mutex to serialize
  the shared HW key slot and the derivation cache. Defining `WOLFSSL_RTL8735B_HUK`
  auto-enables `WOLFSSL_CRYPT_HW_MUTEX` (via `wc_port.h`), so this is handled for
  you; it does require the wolfCrypt mutex/threading primitives for your RTOS to
  be present.

Configurable (override in `user_settings.h` before including wolfSSL):

| Macro                          | Default | Meaning                              |
|--------------------------------|---------|--------------------------------------|
| `WC_HUK_DEVID`                 | 810     | CryptoCb device id (STM32 uses 807-809) |
| `WC_RTL8735B_HUK_SK_IDX`      | 0xC     | Key-storage slot holding the HUK (KEY_STG_HUK1) |
| `WC_RTL8735B_HKDF_PRK_IDX`    | 3       | Intermediate HKDF PRK slot           |
| `WC_RTL8735B_DERIVED_WB_IDX`  | 4       | Derived working-key slot (AES uses it) |
| `WC_RTL8735B_HKDF_CRYPTO_SEL` | 0       | `crypto_sel` for the secure HKDF init |
| `WC_RTL8735B_MAX_WRAPPED`     | 96      | Max wrapped-scalar blob the ECDSA sign path unwraps |

## API

```c
#include <wolfssl/wolfcrypt/port/realtek/rtl8735b.h>

/* One-time: register the AmebaPro2 HUK crypto-callback device. */
wc_Rtl8735b_HukRegister(WC_HUK_DEVID);

/* AES / GCM: enable via devId at init, then pass the 256-bit seed as the key.
 * The seed is HKDF input that diversifies the HUK -- it is NOT the AES key. */
Aes aes;
byte seed[32];     /* per-purpose derivation seed (need not be secret) */
wc_AesInit(&aes, NULL, WC_HUK_DEVID);
wc_AesGcmSetKey(&aes, seed, 32);
wc_AesGcmEncrypt(&aes, ct, pt, ptSz, iv, 12, tag, tagSz, aad, aadSz); /* full GCM */
wc_AesFree(&aes);

/* AES-ECB / AES-CBC follow the same pattern (wc_AesSetKey + wc_AesEcb*/
/* wc_AesCbc* with devId = WC_HUK_DEVID). */

wc_Rtl8735b_HukUnRegister(WC_HUK_DEVID);
```

The seed maps to a device-bound working key as:
HUK (slot `WC_RTL8735B_HUK_SK_IDX`) -> `hal_hkdf_extract_secure_all` -> PRK slot
-> `hal_hkdf_expand_secure_all` -> working key in `WC_RTL8735B_DERIVED_WB_IDX`
-> `hal_crypto_aes_gcm_sk_init` / `hal_crypto_aes_ecb_sk_init`. The derive and
the AES op run under one crypto-mutex hold; the working key never enters
software. Identical seed -> identical working key (deterministic, so GMAC
verifies and AES round-trips); a wrong seed yields a different key (GCM decrypt
returns `AES_GCM_AUTH_E`).

HUK-bound ECDSA sign (Stage 3, wrapped-scalar): point the key's crypto-callback
context at a `wc_Rtl8735b_EccKey` (the scalar AES-wrapped under a HUK-derived
key, plus its 32-byte seed) -- no dedicated wolfSSL import API:

```c
#include <wolfssl/wolfcrypt/port/realtek/rtl8735b.h>
wc_Rtl8735b_EccKey hk = { seed, 32, wrapped, wrappedLen, plainLen };
ecc_key key;
wc_ecc_init_ex(&key, NULL, WC_HUK_DEVID);
wc_ecc_set_curve(&key, plainLen, ECC_SECP256R1);
key.devCtx = &hk;                       /* borrowed; must outlive the key */
wc_ecc_sign_hash(hash, hashSz, sig, &sigSz, rng, &key);
```

At sign time the port derives the slot key from the seed, ECB-unwraps the scalar
into a short-lived buffer, signs, and scrubs it. The wrapped blob is device-bound
(it only unwraps on the silicon whose HUK produced the slot key). The scalar is
briefly in software during the sign; an OTP-resident model (`hal_ecdsa_select_prk`,
scalar never in software) and routing the sign itself through the HW ECDSA engine
(`hal_ecdsa`) are follow-ons.

### Additional HUK operations

HMAC-SHA256 under the HUK (the 32-byte key is the HKDF seed; the MAC runs over
the HUK-derived secure-key slot):

```c
Hmac hmac;
byte seed[32];
wc_HmacInit(&hmac, NULL, WC_HUK_DEVID);
wc_HmacSetKey(&hmac, WC_SHA256, seed, 32);
wc_HmacUpdate(&hmac, msg, msgSz);
wc_HmacFinal(&hmac, mac);   /* MAC produced one-shot at final under the HUK */
wc_HmacFree(&hmac);
```

HW-seeded RNG (entropy from the secure TRNG via the crypto-callback SEED source,
no `CUSTOM_RAND_GENERATE_SEED` wiring needed):

```c
WC_RNG rng;
wc_InitRng_ex(&rng, NULL, WC_HUK_DEVID);
wc_RNG_GenerateBlock(&rng, buf, sizeof(buf));
wc_FreeRng(&rng);
```

To route ECDSA sign through the HW engine instead of the software-after-unwrap
path, set `hk.useHwEngine = 1` (validated on the RTL8735B); to sign from an
OTP-resident key (scalar never in software) set `hk.otpPrkSel` to `1`/`2`
(`ECDSA_OTP_PRK_1/2`) and leave `seed`/`wrapped` unused (that OTP path is
implemented but unexercised -- it needs an OTP key provisioned).

## Notes / limitations

- The HAL GCM path assumes a 96-bit (12-byte) IV (standard J0). A non-12-byte
  IV returns a hard error (not a software fallback, which would key off the seed
  rather than the device-bound key).
- AES-CBC and AES-CTR chain in software over single-block
  `hal_crypto_aes_ecb_sk_*` calls because the HAL exposes no CBC/CTR secure-key
  variant; the key still stays in hardware. CTR maintains the wolfCrypt counter
  state (`aes->reg`/`tmp`/`left`) so partial blocks continue across calls.
- The HAL crypto engine DMAs its buffers on 32-byte (cache-line) boundaries and
  rejects an unaligned GCM iv/aad. The port stages key/iv/aad/tag on aligned
  temporaries and bounces unaligned in/out through aligned buffers, so callers
  need not align.
- Each operation derives the working key from the Aes' own `devKey` seed under
  the crypto mutex (no shared port global), so concurrent `Aes` objects are safe.
- Only a 32-byte seed is HUK-bound. A 16/24-byte AES key falls back to ordinary
  software AES (the bytes become the literal key, no device binding, no error),
  so AES-128/192 are not HUK-bound -- treat AES-256 as the HUK path.
- HUK HMAC-SHA256 is one-shot: it buffers the whole message on the heap and MACs
  at final (suits bounded/short MAC / KDF inputs). `WC_RTL8735B_HMAC_MAX_MSG`
  caps the buffered length (`BUFFER_E` past it); default 64 KB, set 0 for
  unbounded or raise it to MAC larger messages.
- The HMAC key buffer (the HUK seed passed to `wc_HmacSetKey`) is borrowed via
  `hmac->keyRaw` and re-read at `wc_HmacFinal`/`wc_HmacFree`, so it must stay
  valid and unmodified through all Update/Final/Free calls (same borrowed-buffer
  contract as the ECDSA `devCtx`).
- `--enable-rtl8735b` is a host compile + helper-KAT gate: it swaps the HAL
  headers for `rtl8735b_shim.h` (sentinel stubs, no real crypto) to build the
  crypto-callback dispatch and wiring without the vendor SDK.
  `.github/workflows/rtl8735b.yml` builds several algo/guard + `WOLFSSL_SMALL_STACK`
  combinations and runs `testwolfcrypt`, which calls `wc_Rtl8735b_HukSelfTest()`
  -- real KATs of the silicon-independent helpers (BE/LE word conversion, CTR
  counter increment, HMAC accumulator growth/overflow/cap, bounce alignment;
  these need no HAL crypto). What the shim CANNOT check -- AES/GCM/ECDSA crypto
  correctness on the silicon engine -- is validated on RTL8735B hardware (the
  wolfssl-examples HUK app + test/benchmark example), never asserted through the
  stubs.

## Status

Validated on RTL8735B silicon (both the RealTek FreeRTOS SDK app and a Zephyr
image): registration; AES-GCM (encrypt / deterministic tag / decrypt-verify /
round-trip / wrong-seed -> `AES_GCM_AUTH_E` / unaligned buffers / non-12-byte-IV
reject); AES-ECB; AES-CBC (incl. in-place, multi-call); AES-CTR; HMAC-SHA256;
HUK-bound ECDSA (P-256) sign; and HW ECDSA verify (good signature accepted,
tampered digest rejected) -- all pass.

Caveats worth knowing:

- ECDSA sign defaults to software-after-HUK-unwrap (`useHwEngine = 0`). The HW
  `hal_ecdsa` engine path is opt-in; its INPUT / HUK-wrapped-scalar mode is
  validated, but the OTP-resident mode (`otpPrkSel`) is implemented and
  compile-tested only -- it needs an OTP key provisioned (never burned in test).
- The HW engine also serves a general (non-HUK) sign/verify offload: an `ecc_key`
  with `devId = WC_HUK_DEVID` and no `devCtx` signs/verifies with its own
  key, so a stock `wolfcrypt_benchmark` drives the engine via
  `WC_USE_DEVID = WC_HUK_DEVID`.
- Host CI is build-only (shim, no real crypto); functional validation is on
  hardware (see the host-test note above).

## Benchmarks (software crypto baseline)

`wolfcrypt_test` (full self-test, all PASS) and `wolfcrypt_benchmark` were run on
the RTL8735B EVB to validate the core library and toolchain on this target. The
figures below are **pure software wolfCrypt** -- they are NOT the HUK device
(which routes AES through the silicon engine for HUK-derived keys); they serve as
a reference baseline and to size the benefit of hardware offload.

- Target: RTL8735B "KM4" Arm Cortex-M33 (ARMv8-M Mainline, TrustZone + DSP) at
  500 MHz (`CPU_CLK`); DDR at 533 MHz.
- Toolchain / build: RealTek ASDK 10.3.0 (GCC 10.3.0), SDK default `-Os`,
  FreeRTOS, `WOLFCRYPT_ONLY`, `SINGLE_THREADED`, big-integer math via the generic
  `WOLFSSL_SP_MATH_ALL` (portable C, no Cortex-M assembly), `BENCH_EMBEDDED`.
- Build options live with the example, not the wolfSSL tree: the
  `wolfssl-examples` repo `rtl8735b/test/{user_settings.h, wolfcrypt_test.cmake,
  main.c}`, copied into the AmebaPro2 FreeRTOS SDK as
  `component/example/wolfcrypt_test`. One `-DRTL_BENCH_MODE=N` switch selects the
  backend: 1 = pure C (this baseline), 2 = Thumb-2 / SP Cortex-M (the asm tables
  below), 3 = RealTek HW (the hardware-offload table below). The RNG is seeded
  from the SDK `rtw_get_random_bytes`; `current_time()` uses
  `hal_read_systime_us()`.

Symmetric / hash (higher is better):

| Algorithm           | Throughput |
|---------------------|------------|
| AES-128-CBC enc/dec | 9.55 / 9.67 MiB/s |
| AES-256-CBC enc/dec | 7.25 / 7.02 MiB/s |
| AES-128-GCM enc/dec | 5.35 / 5.33 MiB/s |
| AES-256-GCM enc/dec | 4.53 / 4.52 MiB/s |
| AES-128-CTR         | 9.75 MiB/s |
| AES-128-ECB enc/dec | 10.42 / 10.56 MiB/s |
| AES-CCM enc/dec     | 4.73 / 4.65 MiB/s |
| GMAC (4-bit table)  | 13.43 MiB/s |
| AES-128-CMAC        | 8.84 MiB/s |
| ChaCha20            | 24.79 MiB/s |
| ChaCha20-Poly1305   | 15.83 MiB/s |
| Poly1305            | 64.77 MiB/s |
| SHA-1               | 29.19 MiB/s |
| SHA-256             | 10.94 MiB/s |
| SHA-512             | 7.29 MiB/s |
| SHA3-256            | 6.61 MiB/s |
| HMAC-SHA256         | 10.85 MiB/s |

Public key (higher is better):

| Operation             | Rate |
|-----------------------|------|
| RSA-2048 public       | 214.7 ops/s |
| RSA-2048 private      | 6.14 ops/s |
| RSA-2048 key gen      | 0.40 ops/s |
| DH-2048 key gen/agree | 17.67 / 15.23 ops/s |
| ECDSA P-256 sign/verify | 40.03 / 29.81 ops/s |
| ECDHE P-256 agree     | 40.69 ops/s |
| Curve25519 key gen/agree | 414.8 / 419.4 ops/s |
| Ed25519 sign/verify   | 788.3 / 397.0 ops/s |

The tables above are the portable-C baseline. The assembly backends below raise
these substantially. Curve25519/Ed25519 already use the dedicated
`curve25519.c`/`ed25519.c` fast code.

## Optimizations (measured on RTL8735B @ 500 MHz, -Os)

Two wolfCrypt assembly backends apply to this Cortex-M33 and were validated on
hardware (both keep `wolfcrypt_test` all-PASS). Neither needs wolfSSL source
changes -- they are build-config selections plus adding the relevant asm files.

### 1. Public key -- `sp_cortexm.c` (Thumb-2/DSP single-precision)

Enable with `WOLFSSL_SP_ARM_CORTEX_M_ASM` + `WOLFSSL_HAVE_SP_RSA` +
`WOLFSSL_HAVE_SP_ECC` + `WOLFSSL_HAVE_SP_DH`, and add `wolfcrypt/src/sp_cortexm.c`
to the build (alongside the generic `sp_int.c` for sizes without an asm path).

| Operation              | Generic C | sp_cortexm | Speedup |
|------------------------|-----------|------------|---------|
| ECC P-256 key gen      | 40.7      | 541.2 ops/s | 13.3x |
| ECDSA P-256 sign       | 40.0      | 427.6 ops/s | 10.7x |
| ECDSA P-256 verify     | 29.8      | 292.7 ops/s | 9.8x  |
| ECDHE P-256 agree      | 40.7      | 318.1 ops/s | 7.8x  |
| RSA-2048 public        | 214.7     | 618.4 ops/s | 2.9x  |
| RSA-2048 private       | 6.14      | 19.0 ops/s  | 3.1x  |
| DH-2048 agree          | 15.2      | 38.3 ops/s  | 2.5x  |

### 2. Symmetric -- Thumb-2 asm (`port/arm/thumb2-*-asm.S`)

Enable with `WOLFSSL_ARMASM` + `WOLFSSL_ARMASM_THUMB2` +
`WOLFSSL_ARMASM_NO_HW_CRYPTO` + `WOLFSSL_ARMASM_NO_NEON` + `WOLFSSL_ARM_ARCH=7`,
and add `thumb2-aes-asm.S`, `thumb2-sha256-asm.S`, `thumb2-sha512-asm.S`,
`thumb2-sha3-asm.S`, `thumb2-chacha-asm.S`, `thumb2-poly1305-asm.S`.
`WOLFSSL_ARMASM` is a global switch, so provide the `.S` for every covered
module. (Curve25519/Ed25519 also have Thumb-2 asm but their `ge_operations.c`
integration assumes 64-bit and was left on the C path here.)

| Algorithm           | Generic C | Thumb-2 asm | Speedup |
|---------------------|-----------|-------------|---------|
| AES-128-CBC enc     | 9.55      | 20.85 MiB/s | 2.2x |
| AES-128-ECB enc     | 10.42     | 20.82 MiB/s | 2.0x |
| AES-128-CTR         | 9.75      | 20.47 MiB/s | 2.1x |
| AES-128-GCM enc     | 5.35      | 10.30 MiB/s | 1.9x |
| GMAC                | 13.43     | 20.81 MiB/s | 1.5x |
| AES-128-CMAC        | 8.84      | 14.67 MiB/s | 1.7x |
| ChaCha20            | 24.79     | 46.44 MiB/s | 1.9x |
| ChaCha20-Poly1305   | 15.83     | 25.38 MiB/s | 1.6x |
| SHA-256             | 10.94     | 17.83 MiB/s | 1.6x |
| SHA3-256            | 6.61      | 8.64 MiB/s  | 1.3x |
| HMAC-SHA256         | 10.85     | 17.66 MiB/s | 1.6x |

### 3. Hardware offload -- the HUK crypto-callback device (`hal_crypto` / `hal_ecdsa`)

Measured on the same `wolfcrypt_benchmark` with `WC_USE_DEVID = WC_HUK_DEVID`
(the test/benchmark example's mode 3, `RTL_BENCH_MODE=3`). The benchmark prints
a software and a hardware row per op; the software column here is the pure-C
`sp_int.c` baseline, the hardware column is this port driving the silicon engine.
The ECDSA rows exercise the port's general HW sign/verify offload (a benchmark
key with `devId = WC_HUK_DEVID` and no HUK context -- the engine signs with the
key's own scalar and verifies with its own public point).

| Operation              | Pure C    | HW (engine) | Speedup |
|------------------------|-----------|-------------|---------|
| AES-256-ECB enc/dec    | 7.73/7.76 | 48.87/48.69 MiB/s | 6.3x |
| AES-256-GCM enc/dec    | 4.52      | 38.44/38.18 MiB/s | 8.5x |
| AES-256-GCM no_AAD      | 4.55      | 41.73/41.34 MiB/s | 9.1x |
| HMAC-SHA256            | 10.63     | 42.03 MiB/s | 4.0x |
| ECDSA P-256 sign       | 39.81     | 272.05 ops/s | 6.8x |
| ECDSA P-256 verify     | 29.39     | 275.13 ops/s | 9.4x |

Caveats, all expected from the port's design:

- **AES-256-CBC / -CTR are slower on the engine** (2.28 MiB/s vs ~7.2 software):
  the port chains those in software over single-block secure-key ECB calls, so
  per-block HAL overhead dominates. AES-256-GCM and -ECB use the engine's native
  block path and are the real symmetric wins; for bulk CBC/CTR the software
  (especially Thumb-2) path is faster.
- **AES-128/192 fall back to software** -- the HUK-derived working key is 256-bit.
- **RSA, DH, ECDH, hashing and key generation fall back to software** (hardware
  row ~= software row) -- the device only advertises AES, HMAC-SHA256 and ECDSA
  P-256 sign/verify; everything else returns `CRYPTOCB_UNAVAILABLE` and the core
  runs it in software.
- The HW ECDSA **sign** (272 ops/s) is actually slower than the `sp_cortexm.c`
  software sign (427.6 ops/s above): the engine's value is binding to the HUK and
  offloading the CPU, not beating hand-tuned Thumb-2 P-256 latency. HW verify
  (275) is on par with the `sp_cortexm.c` verify (292.7).

So the recommended posture: take `sp_cortexm.c` for public-key math unconditionally
(no silicon dependency), use the engine for AES-256-GCM/ECB bulk throughput and
HUK-bound ECDSA, and keep the Thumb-2 symmetric asm as the portable fallback for
the cipher modes the engine does not accelerate well.

#### Full benchmark output (hardware mode)

Part: RealTek RTL8735B (AmebaPro2), "KM4" Arm Cortex-M33 @ 500 MHz (`CPU_CLK`),
DDR @ 533 MHz. Toolchain: RealTek ASDK 10.3.0 (GCC 10.3.0), SDK default `-Os`,
FreeRTOS, `WOLFCRYPT_ONLY`, `SINGLE_THREADED`, `BENCH_EMBEDDED`. Generic `sp_int.c`
big-integer math (the HW base is the pure-C backend, so the `SW` rows are the
pure-C baseline). The HUK device is registered and `WC_USE_DEVID = WC_HUK_DEVID`,
so `wolfcrypt_benchmark` prints a software (`SW`) and a hardware (`HW`) row per op;
ops the engine does not accelerate show `HW` ~= `SW` (software fallback).

Symmetric / hash throughput (MiB/s; enc / dec where both apply):

| Algorithm | SW | HW |
|-----------|----|----|
| RNG SHA-256 DRBG | 2.94 | - |
| AES-128-CBC | 9.54 / 9.64 | 9.42 / 9.53 |
| AES-192-CBC | 8.24 / 8.30 | 8.15 / 8.22 |
| AES-256-CBC | 7.24 / 7.01 | 2.28 / 2.23 |
| AES-128-GCM | 5.35 / 5.35 | 5.27 / 5.27 |
| AES-192-GCM | 4.90 / 4.90 | 4.84 / 4.84 |
| AES-256-GCM | 4.52 / 4.52 | 38.44 / 38.18 |
| AES-128-GCM no_AAD | 5.38 / 5.38 | 5.31 / 5.31 |
| AES-192-GCM no_AAD | 4.93 / 4.93 | 4.87 / 4.87 |
| AES-256-GCM no_AAD | 4.55 / 4.55 | 41.73 / 41.34 |
| GMAC (4-bit table) | 13.42 | - |
| AES-128-ECB | 10.41 / 10.56 | 10.27 / 10.42 |
| AES-192-ECB | 8.88 / 8.98 | 8.78 / 8.88 |
| AES-256-ECB | 7.73 / 7.76 | 48.87 / 48.69 |
| AES-128-CTR | 9.67 | 9.44 |
| AES-192-CTR | 8.34 | 8.16 |
| AES-256-CTR | 7.32 | 2.28 |
| AES-CCM | 4.73 / 4.65 | 4.71 / 4.62 |
| AES-CCM no_AAD | 4.74 / 4.65 | 4.71 / 4.62 |
| ChaCha20 | 24.79 | - |
| ChaCha20-Poly1305 | 15.82 | - |
| Poly1305 | 64.78 | - |
| SHA-1 | 29.13 | 28.07 |
| SHA-224 | 10.73 | 10.58 |
| SHA-256 | 10.73 | 10.58 |
| SHA-384 | 7.28 | 7.21 |
| SHA-512 | 7.28 | 7.21 |
| SHA-512/224 | 7.28 | 7.21 |
| SHA-512/256 | 7.28 | 7.21 |
| SHA3-224 | 7.00 | 6.94 |
| SHA3-256 | 6.61 | 6.55 |
| SHA3-384 | 5.10 | 5.07 |
| SHA3-512 | 3.57 | 3.55 |
| AES-128-CMAC | 8.85 | 8.75 |
| AES-256-CMAC | 6.56 | 6.50 |
| HMAC-SHA1 | 28.83 | 26.64 |
| HMAC-SHA224 | 10.63 | 10.33 |
| HMAC-SHA256 | 10.63 | 42.03 |
| HMAC-SHA384 | 7.16 | 7.02 |
| HMAC-SHA512 | 7.16 | 7.02 |

Public key (ops/s):

| Operation | SW | HW |
|-----------|----|----|
| RSA-2048 key gen | 0.130 | 0.150 |
| RSA-3072 key gen | 0.043 | 0.015 |
| RSA-2048 public | 213.4 | 213.4 |
| RSA-2048 private | 6.13 | 6.13 |
| DH-2048 key gen | 17.66 | 17.66 |
| DH-2048 agree | 15.28 | 15.34 |
| ECC P-256 key gen | 40.58 | 40.48 |
| ECDHE P-256 agree | 41.13 | 40.25 |
| ECDSA P-256 sign | 39.81 | 272.05 |
| ECDSA P-256 verify | 29.39 | 275.13 |
| RNG-256 SHA256 Init/Free | 2052.9 | - |

HW differs from SW only on the engine-accelerated rows: AES-256-GCM/ECB and
HMAC-SHA256 (big wins), ECDSA P-256 sign/verify (big wins), and AES-256-CBC/CTR
(slower -- software-chained over single-block ECB). Every other row is software
fallback (HW ~= SW).
