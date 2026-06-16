# ST Ports

Support for STM32 on-chip crypto hardware acceleration across the following families:

| Family flag           | Chips / typical NUCLEO board                                       |
|-----------------------|--------------------------------------------------------------------|
| `WOLFSSL_STM32F1`     | F1xx                                                                |
| `WOLFSSL_STM32F2`     | F2xx (RNG only on F207)                                             |
| `WOLFSSL_STM32F4`     | F4xx (CRYP / HASH / RNG)                                            |
| `WOLFSSL_STM32F7`     | F7xx (CRYP / HASH / RNG)                                            |
| `WOLFSSL_STM32G0`     | G0xx (TinyAES / RNG on crypto G0Bx/G0Cx; RNG-only on others)        |
| `WOLFSSL_STM32G4`     | G4xx (TinyAES / RNG / V1 PKA)                                       |
| `WOLFSSL_STM32H5`     | H5xx (HASH / RNG / SAES / V2 PKA / DHUK on H573)                    |
| `WOLFSSL_STM32H7`     | H7xx classic (CRYP / HASH / RNG); H7Ax/H7Bx + H72x are RNG-only     |
| `WOLFSSL_STM32H7S`    | H7Sx (SAES / HASH / RNG / V2 PKA)                                   |
| `WOLFSSL_STM32L4`     | L4xx (TinyAES variants / HASH / RNG / V1 PKA on L4-rev)             |
| `WOLFSSL_STM32L5`     | L5xx (HASH / RNG / V1 PKA; TinyAES + SAES on L562)                  |
| `WOLFSSL_STM32U0`     | U0xx (TinyAES / RNG only)                                           |
| `WOLFSSL_STM32U3`     | U3xx (TinyAES / HASH / RNG / SAES / V2 PKA / DHUK)                  |
| `WOLFSSL_STM32U5`     | U5xx (TinyAES / HASH / RNG / SAES / V2 PKA / DHUK)                  |
| `WOLFSSL_STM32WB`     | WB55 (TinyAES / RNG / V1 PKA)                                       |
| `WOLFSSL_STM32WBA`    | WBA52 (TinyAES / HASH / RNG / SAES / V2 PKA / DHUK)                 |
| `WOLFSSL_STM32WL`     | WL55 (TinyAES / RNG / V1 PKA)                                       |
| `WOLFSSL_STM32C0`     | C0xx (not yet supported in settings.h; SW only)                     |
| `WOLFSSL_STM32C5`     | C5xx (TinyAES / HASH / RNG / SAES / V2 PKA sign-only / DHUK / CCB)   |
| `WOLFSSL_STM32N6`     | N6xx (TinyAES / HASH / RNG / SAES / V2 PKA / DHUK; M55 core)        |
| `WOLFSSL_STM32MP13`   | MP13 (CRYP / HASH / RNG / PKA; Cortex-A7)                           |
| `WOLFSSL_STM32MP25`   | MP25 (not yet supported in settings.h; Cortex-A35 + M33)            |

The port supports three integration flavors:

- **CubeMX HAL** (`WOLFSSL_STM32_CUBEMX`) -- recommended for most projects. Pairs with ST's CubeMX-generated HAL drivers. This is the legacy default and what STM32 forum tutorials describe.
- **Standard Peripheral Library** (no `WOLFSSL_STM32_CUBEMX`) -- legacy StdPeriLib path, kept for older F1/F2/F4 projects that have not migrated.
- **BARE-metal** (`WOLFSSL_STM32_BARE`) -- direct-register access with zero HAL or StdPeriLib dependency. Designed for wolfBoot / no-OS / FreeRTOS / TrustZone-NS workloads where pulling in the HAL is undesirable. See [wolfssl-examples-stm32/STM32_Bare_Test](https://github.com/wolfSSL/wolfssl-examples-stm32) for a 27-board reference matrix.

Support for the STSAFE-A secure element family via I2C is documented separately below.

For details see our [wolfSSL ST](https://www.wolfssl.com/docs/stm32/) page.


## STM32 Symmetric Acceleration

The CRYP IP block (full-size, older families F2/F4/F7/H7-classic/MP13) and the TinyAES IP block (smaller, newer families L4/L5/G4/U0/U3/U5/WB/WBA/WL/H5/C5/N6) are both driven through the same wolfcrypt entry points in `wolfcrypt/src/port/st/stm32.c`. The HASH IP block has its own driver and is independent of the AES block.

### Enabling

Define the appropriate family flag from the table above, plus a build-flavor flag:

```
#define WOLFSSL_STM32U5            /* family */
#define WOLFSSL_STM32_CUBEMX       /* or WOLFSSL_STM32_BARE */
```

You can selectively disable parts of the HW acceleration:

```
#define NO_STM32_RNG
#define NO_STM32_CRYPTO
#define NO_STM32_HASH
#define NO_STM32_HMAC
```

If your chip simply does not have an IP block (e.g. H7Ax has no CRYP/HASH; F207 has no CRYP/HASH) the family arm sets the appropriate `NO_STM32_*` defines for you.

### SAES instance routing

Some newer families (H5/H7S/U3/U5/WBA/C5/N6, plus the L562 sub-variant) expose a Secure AES (SAES) instance in addition to (or instead of) a regular AES block. Define `WOLFSSL_STM32_USE_SAES` to route all wolfcrypt AES traffic through SAES via the `WC_STM32_AES_INST` indirection macro. This is required when the regular AES block is TrustZone-gated (H7S3) and is also a prerequisite for DHUK key-wrap on the families in the `WC_STM32_HAS_DHUK` gate (U3/U5/H5/WBA/C5).

### Coding

Include `<wolfssl/wolfcrypt/settings.h>` before any other wolfSSL headers. If building the sources directly we recommend defining `WOLFSSL_USER_SETTINGS` and adding your own `user_settings.h`. A reference is in `IDE/GCC-ARM/Header/user_settings.h`.

### Benchmarks

See our [benchmarks](https://www.wolfssl.com/docs/benchmarks/) page for canonical numbers. For per-silicon BARE-vs-CubeMX comparisons across the current 27-board NUCLEO matrix, see the bench tables in [wolfssl-examples-stm32/STM32_Bare_Test/README.md](https://github.com/wolfSSL/wolfssl-examples-stm32).


## STM32 PKA (Public Key Acceleration)

The STM32 PKA peripheral accelerates ECC scalar multiplication and ECDSA sign/verify. Two distinct IP revisions are in the wild:

- **V1 PKA** (WB55, WL55, L5, some L4 rev) -- single-curve-at-a-time, limited curve set, slower. Driven via the legacy `WOLFSSL_STM32_PKA` path.
- **V2 PKA** (U3, U5, WBA, H5, H7S, N6, L562, C5) -- larger RAM, more curves, more concurrent operations. Enabled by defining `WOLFSSL_STM32_PKA_V2` on top of `WOLFSSL_STM32_PKA`.

### Enabling

```
#define WOLFSSL_STM32_PKA
#define WOLFSSL_STM32_PKA_V2   /* additionally, for V2 silicon */
```

### Notes

- On V1 PKA chips the PKA peripheral runs a PKA-RAM clear on first clock-enable and silently rejects `CR.EN` writes during the clear. The wolfcrypt init mirrors HAL's behavior by spinning on `CR.EN` readback up to `WC_STM32_PKA_INIT_TIMEOUT` iterations. This was discovered during L5 bring-up but benefits every PKA chip.
- On V2 PKA the `coefB` parameter must be loaded explicitly (V1 hardware can derive it from the prime). The V2 ECC scalar-multiplication path in `HAL_PKA_ECCMul()` and the ECDSA sign/verify paths both populate it -- see `wolfcrypt/src/port/st/stm32.c`.
- BARE-metal V2 PKA ECDSA sign/verify is work-in-progress -- the single-curve P-256 path is functional but multi-curve sweeps in `wolfcrypt_test` hit a -248 result on some boards. Track this in the wolfssl-examples-stm32 STM32_Bare_Test/README.


## STM32 DHUK (Device Hardware Unique Key)

Newer STM32 silicon (U3/U5/WBA/H5/C5/N6; the `WC_STM32_HAS_DHUK` family gate) carries a chip-unique 256-bit key (DHUK) burned into the SAES key-derivation path. wolfSSL exposes it through the standard crypto-callback (`WOLF_CRYPTO_CB`) framework: register the STM32 DHUK device once, init a normal `Aes` / `ecc_key` with its `devId`, then perform NORMAL wolfCrypt operations (AES, AES-GCM/GMAC, ECDSA sign) transparently. There is no separate DHUK module -- the STM32 crypto callback lives in `wolfcrypt/src/port/st/stm32.c`.

A DHUK-protected key is driven by a per-key 256-bit seed. The SAES derives the device-bound working key from (seed, DHUK) inside the hardware; for symmetric operations the derived key never appears in software. For ECDSA the derived key decrypts a wrapped private scalar into a short-lived buffer only.

### Enabling

```
#define WOLFSSL_DHUK         /* enable DHUK */
#define WOLF_CRYPTO_CB       /* required -- DHUK routes through crypto callbacks */
```

`WC_STM32_HAS_DHUK` is auto-defined for the SAES+DHUK families when `WOLFSSL_DHUK` is set; other families compile out the DHUK code. `WOLFSSL_STM32_BARE` selects the bare-metal SAES backend.

### API

```c
/* one-time: register the STM32 DHUK crypto-callback device */
wc_Stm32_DhukRegister(WC_DHUK_DEVID);

/* AES / GMAC: enable via devId at init, then pass the 256-bit seed as the key */
Aes aes;
wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
wc_AesGcmSetKey(&aes, seed, 32);
wc_AesGcmEncrypt(&aes, NULL, NULL, 0, iv, ivSz, tag, tagSz, aad, aadSz); /* GMAC */
wc_AesFree(&aes);

wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
```

ECDSA mirrors this: init the key with `wc_ecc_init_ex(&key, NULL, WC_DHUK_DEVID)`, import the wrapped private scalar plus its derivation seed with `wc_ecc_import_wrapped_private(&key, seed, seedSz, wrapped, wrappedLen, plainLen)`, then call the normal `wc_ecc_sign_hash()`; verification uses the in-clear public key unchanged. The seed reaches the device as the AES key bytes (`aes->devKey`, set by the normal `wc_AesSetKey` / `wc_AesGcmSetKey`) or, for ECC, on the `ecc_key`; the STM32 callback reads it and derives the working key inside SAES.

### Provisioning helper

`wc_Stm32_Aes_Wrap()` performs a chip-bound DHUK wrap (KEYSEL=HW, deterministic output) and is retained for provisioning wrapped key material. `WOLFSSL_DHUK_DEVID` (808) / `WOLFSSL_SAES_DEVID` (807) select its wrap-key source.

### Current state

- Validated on STM32U385 (TZEN=0): transparent GMAC, AES-ECB, and ECDSA sign all run through the crypto-callback path; the derived key is deterministic, AES round-trips, and ECDSA verifies with the public counterpart.
- The SAES key-derivation/unwrap passes complete via `SR.BUSY` clearing plus `SR.KEYVALID`, NOT via `CCF` (which is only raised for data-output passes). Waiting on `CCF` for the key path was the original `WC_TIMEOUT_E`; the BUSY/KEYVALID completion is the fix.
- STM32U585 under TZEN=1 secure state: the derive currently stalls (`SR.BUSY` does not clear) -- a secure-context concern (SAES RNG / GTZC) that is open work. DHUK does not otherwise require secure state.

### Optional exact-key import (off by default)

`wc_Stm32_Aes_DhukOp[_ex]()` unwraps a previously DHUK-wrapped key into SAES KEYR and runs AES ECB/CBC with it (importing an externally-chosen key, vs deriving one from a seed). It is compiled only with `WOLFSSL_STM32_DHUK_UNWRAP`, is called explicitly (not auto-routed), and is not re-validated on current hardware.


## STM32 CCB (Coupling and Chaining Bridge)

STM32U3 and STM32C5 silicon (e.g. U385 / C5A3; RM0487 ch 31 and RM0522, the `WC_STM32_HAS_CCB` gate) carry the CCB peripheral, which chains the PKA, SAES and RNG over a private local interconnect. This lets a DHUK-protected ECDSA private scalar be unwrapped by the SAES and consumed by the PKA entirely in hardware -- the scalar never crosses the system bus or enters software, not even into a short-lived buffer (unlike the generic DHUK ECDSA path above, which decrypts the scalar into a stack buffer). CCB builds on DHUK: the private key is held as a chip-bound AES-GCM blob (`iv` / `tag` / wrapped scalar) created under the silicon DHUK.

CCB is supported on both build paths: the bare-metal direct-register OPSTEP driver (`WOLFSSL_STM32_BARE`) and the CubeMX/HAL path (`WOLFSSL_STM32_CUBEMX`, via ST's `HAL_CCB_*` driver). It currently covers ECDSA over P-256.

### Enabling

```
#define WOLFSSL_DHUK         /* CCB is a DHUK feature */
#define WOLF_CRYPTO_CB       /* required -- transparent sign routes through crypto callbacks */
#define WOLFSSL_STM32_CCB    /* opt in to the CCB-protected ECDSA path */
```

`WOLFSSL_STM32_CCB` requires CCB silicon (`WOLFSSL_STM32U3` or `WOLFSSL_STM32C5`) and either `WOLFSSL_STM32_BARE` or `WOLFSSL_STM32_CUBEMX` (a `#error` fires otherwise).

### API

The whole flow uses the **standard ECC API** -- there is no CCB-specific public API. Binding the key to `WC_DHUK_DEVID` routes keygen and sign through the STM32 crypto callback, which provisions and uses the CCB-protected key transparently (a drop-in for TLS and other consumers). The same flow works on both build paths.

```c
ecc_key key;

/* one-time: register the STM32 DHUK/CCB crypto-callback device */
wc_Stm32_DhukRegister(WC_DHUK_DEVID);

wc_ecc_init_ex(&key, NULL, WC_DHUK_DEVID);

/* provision a fresh device-bound key with the STANDARD keygen -- the crypto
 * callback intercepts it: the CCB generates the scalar, wraps it into a blob
 * and derives the public key, all in hardware. No CCB-specific API. */
wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);

/* transparent sign -- the scalar is unwrapped SAES->PKA in HW and signed */
wc_ecc_sign_hash(hash, hashLen, sig, &sigLen, &rng, &key);

/* verify with the in-clear public key, unchanged */
wc_ecc_verify_hash(sig, sigLen, hash, hashLen, &verified, &key);

wc_ecc_free(&key);
wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
```

To reuse a key across resets, persist the blob from a provisioned key and reload it later with `wc_ecc_import_wrapped_private_ex(&key, curve_id, wrapped, wrappedLen, iv, tag, pub, pubLen)` (the public key in uncompressed `qx||qy` form), then sign as above. Both paths set `key->dhuk_is_ccb` and the device `devId`, so dispatch to the CCB happens automatically inside the crypto callback.

### Current state

- Validated on STM32U385 (NUCLEO-U385RG-Q, TZEN=0), P-256, on both the bare-metal and CubeMX/HAL build paths: `wc_ecc_make_key` -> `wc_ecc_sign_hash` -> `wc_ecc_verify_hash` round-trips, with the private scalar never present in software.
- `Stm32Ccb_Init()` pulse-resets the PKA / SAES / RNG before each operation, so the first CCB op is robust even when prior standalone crypto (RNG seeding, ECC keygen) left an engine in a state that would otherwise stall the CCB's chained SAES GCM step. The family-specific reset register name is abstracted (`WC_STM32_CCB_RSTR`).
- CCB requires the U3 at its full clock; the reference clock-tree bring-up (96 MHz) is in the bare example's `boards/u3/hw_init.c`.


## STM32 BARE-metal port

`WOLFSSL_STM32_BARE` selects a direct-register integration with zero HAL or StdPeriLib dependency. Use this for:

- wolfBoot / no-OS firmware where the HAL footprint is unwelcome.
- TrustZone non-secure applications where the HAL link surface is too broad.
- FreeRTOS or RTX projects that prefer to provide their own clock-tree and UART init.

The caller is responsible for:

1. Clock-tree bring-up (HSI/HSE, PLL, voltage scaling, flash latency).
2. UART / VCP bring-up for stdout.
3. Peripheral clock-enable for the IP blocks you use (RNG, CRYP/SAES, HASH, PKA).

In return wolfcrypt drives the IP-block registers directly. Family-specific arms in `wolfssl/wolfcrypt/port/st/stm32.h` handle the per-chip register-name differences (e.g. `RCC->AHB2ENR` vs `RCC->AHB2ENR1`, `D2CCIP2R` vs `CDCCIP2R`).

### Enabling

```
#define WOLFSSL_STM32_BARE
#define WOLFSSL_STM32U5             /* or any other family flag */
#define STM32_RNG                   /* HW IP enables */
#define STM32_CRYPTO
#define STM32_HASH
```

### Per-family HW IP coverage (BARE-metal validation matrix)

The following table summarizes which IP blocks the BARE path drives on each family currently in the validation matrix. `-` means the silicon does not carry the IP; the corresponding wolfcrypt algorithm falls back to software.

| Family   | Chip example     | AES        | HASH | RNG  | PKA | SAES | DHUK |
|----------|------------------|------------|------|------|-----|------|------|
| F2       | STM32F207ZG      | -          | -    | HW   | -   | -    | -    |
| F3       | STM32F303ZE      | -          | -    | -    | -   | -    | -    |
| F4       | STM32F437/F439ZI | CRYP       | HW   | HW   | -   | -    | -    |
| F7       | STM32F767ZI      | CRYP       | HW   | HW   | -   | -    | -    |
| G0       | STM32G071RB      | -          | -    | -    | -   | -    | -    |
| G4       | STM32G491RE      | -          | -    | HW   | -   | -    | -    |
| H5 (no SAES) | STM32H563ZI  | -          | HW   | HW   | -   | -    | -    |
| H5 (full)| STM32H573ZI      | TinyAES    | HW   | HW   | V2  | HW   | HW   |
| H7       | STM32H753ZI      | CRYP       | HW   | HW   | -   | -    | -    |
| H7 RNG   | STM32H723/H7A3   | -          | -    | HW   | -   | -    | -    |
| H7S      | STM32H7S3L8      | SAES       | HW   | HW   | V2  | HW   | -    |
| L4       | STM32L4A6ZG      | TinyAES    | HW   | HW   | -   | -    | -    |
| L5 (552) | STM32L552ZE-Q    | -          | HW   | HW   | V1  | -    | -    |
| L5 (562) | STM32L562E-DK    | TinyAES    | HW   | HW   | V1  | HW   | -    |
| N6       | STM32N657X0-Q    | TinyAES    | HW   | HW   | V2  | HW   | HW   |
| U0       | STM32U083RC      | TinyAES    | -    | HW   | -   | -    | -    |
| U3       | STM32U385RG-Q    | TinyAES    | HW   | HW   | V2  | HW   | HW   |
| U5       | STM32U5xx        | TinyAES    | HW   | HW   | V2  | HW   | HW   |
| WB       | STM32WB55RG      | TinyAES    | -    | HW   | V1  | -    | -    |
| WBA      | STM32WBA52CG     | TinyAES    | HW   | HW   | V2  | HW   | HW   |
| WL       | STM32WL55JC      | TinyAES    | -    | HW   | V1  | -    | -    |
| C0       | STM32C031C6      | -          | -    | -    | -   | -    | -    |
| C5       | STM32C5A3ZG      | TinyAES    | HW   | HW   | V2  | HW   | HW   |

### Reference example

See [wolfssl-examples-stm32/STM32_Bare_Test/](https://github.com/wolfSSL/wolfssl-examples-stm32) for a Makefile-based harness covering all of the above families. It exposes three CONFIG flavors (`bare` = HW path, `asm` = WOLFSSL_ARMASM, `c` = software-C baseline) and two TARGETs (`test` = wolfcrypt KAT, `bench` = wolfcrypt benchmark). Per-silicon build-size and benchmark tables live in the example's README.

### TrustZone-aware silicon recovery

Some chips ship with `TZEN=1` from the factory (H5, L5, U5). To run a non-secure-only BARE binary on these you must first disable TrustZone via the option bytes:

```
STM32_Programmer_CLI -c port=swd sn=<probe_sn> mode=UR -ob TZEN=0
```

If a flashed binary commits a bad supply config (e.g. H7Ax `PWR_CR3` first-write-wins lock) and the SWD AP becomes unreachable, recovery is via BOOT0=VDD to reach the ROM bootloader, then mass-erase from there.

## STSAFE-A ECC Acceleration

Using the wolfSSL PK callbacks or Crypto callbacks with the ST-Safe reference API's we support ECC operations for TLS client/server:
 - **ECDSA Sign/Verify**: P-256 and P-384 (NIST and Brainpool curves)
 - **ECDH Key Agreement**: For TLS key exchange
 - **ECC Key Generation**: Ephemeral keys for TLS

At the wolfCrypt level we also support ECC native API's for `wc_ecc_*` using the ST-Safe via Crypto Callbacks.

### Supported Hardware

| Model | Macro | SDK |
|-------|-------|-----|
| STSAFE-A100/A110 | `WOLFSSL_STSAFEA100` | ST STSAFE-A1xx Middleware (proprietary) |
| STSAFE-A120 | `WOLFSSL_STSAFEA120` | [STSELib](https://github.com/STMicroelectronics/STSELib) (BSD-3, open source) |

### Building

For STSAFE-A100/A110 (legacy):

```
./configure --enable-pkcallbacks CFLAGS="-DWOLFSSL_STSAFEA100"
```

or in `user_settings.h`:

```c
#define HAVE_PK_CALLBACKS
#define WOLFSSL_STSAFEA100
```

For STSAFE-A120 with STSELib:

```
./configure --enable-pkcallbacks CFLAGS="-DWOLFSSL_STSAFEA120"
```

or in `user_settings.h`:

```c
#define HAVE_PK_CALLBACKS
#define WOLFSSL_STSAFEA120
```

To use Crypto Callbacks (recommended for wolfCrypt-level ECC operations):

```c
#define WOLF_CRYPTO_CB
#define WOLFSSL_STSAFEA120  /* or WOLFSSL_STSAFEA100 */
```

### Coding

#### Using PK Callbacks (TLS)

Setup the PK callbacks for TLS using:

```c
/* Setup PK Callbacks for STSAFE */
WOLFSSL_CTX* ctx;
SSL_STSAFE_SetupPkCallbacks(ctx);

/* Or manually: */
wolfSSL_CTX_SetEccKeyGenCb(ctx, SSL_STSAFE_CreateKeyCb);
wolfSSL_CTX_SetEccSignCb(ctx, SSL_STSAFE_SignCertificateCb);
wolfSSL_CTX_SetEccVerifyCb(ctx, SSL_STSAFE_VerifyPeerCertCb);
wolfSSL_CTX_SetEccSharedSecretCb(ctx, SSL_STSAFE_SharedSecretCb);
wolfSSL_CTX_SetDevId(ctx, 0); /* enables wolfCrypt `wc_ecc_*` ST-Safe use */
```

The reference STSAFE PK callback functions are located in the `wolfcrypt/src/port/st/stsafe.c` file.

Adding a custom context to the callbacks:

```c
/* Setup PK Callbacks context */
WOLFSSL* ssl;
void* myOwnCtx;
SSL_STSAFE_SetupPkCallbackCtx(ssl, myOwnCtx);
```

#### Using Crypto Callbacks (wolfCrypt)

For direct wolfCrypt ECC operations using the hardware:

```c
#include <wolfssl/wolfcrypt/port/st/stsafe.h>

/* Register the crypto callback */
wolfSTSAFE_CryptoCb_Ctx stsafeCtx;
stsafeCtx.devId = WOLF_STSAFE_DEVID;
wc_CryptoCb_RegisterDevice(WOLF_STSAFE_DEVID, wolfSSL_STSAFE_CryptoDevCb, &stsafeCtx);

/* For ECDSA signing operations (uses persistent slot 1) */
ecc_key key;
wc_ecc_init_ex(&key, NULL, WOLF_STSAFE_DEVID);
wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
/* Sign operations will use STSAFE hardware */

/* For ECDH operations (uses ephemeral slot 0xFF) */
ecc_key ecdh_key;
wc_ecc_init_ex(&ecdh_key, NULL, WOLF_STSAFE_DEVID);
ecdh_key.devCtx = (void*)(uintptr_t)STSAFE_KEY_SLOT_EPHEMERAL;  /* Configure for ECDH */
wc_ecc_make_key_ex(&rng, 32, &ecdh_key, ECC_SECP256R1);
/* ECDH shared secret computation will use STSAFE hardware */
```

**Note for STSAFE-A120**: ECDH operations require keys generated in the ephemeral slot (0xFF) which has key establishment enabled by default. Set `key.devCtx = (void*)(uintptr_t)STSAFE_KEY_SLOT_EPHEMERAL;` to configure keys for ECDH before generation. Persistent slots (0-4) require explicit configuration via `put_attribute` command to enable key establishment.

### Implementation Details

The STSAFE support is self-contained in `wolfcrypt/src/port/st/stsafe.c` with SDK-specific implementations selected at compile time:

| Macro | SDK | Description |
|-------|-----|-------------|
| `WOLFSSL_STSAFEA100` | STSAFE-A1xx Middleware | ST's proprietary SDK for A100/A110 |
| `WOLFSSL_STSAFEA120` | [STSELib](https://github.com/STMicroelectronics/STSELib) | ST's open-source SDK for A120 (BSD-3) |

#### External Interface (Backwards Compatibility)

For customers with existing custom implementations, define `WOLFSSL_STSAFE_INTERFACE_EXTERNAL` to use an external `stsafe_interface.h` file instead of the built-in implementation:

```c
#define WOLFSSL_STSAFEA100  /* or WOLFSSL_STSAFEA120 */
#define WOLFSSL_STSAFE_INTERFACE_EXTERNAL
```

When `WOLFSSL_STSAFE_INTERFACE_EXTERNAL` is defined, the customer must provide a `stsafe_interface.h` header that defines:

| Item | Type | Description |
|------|------|-------------|
| `stsafe_curve_id_t` | typedef | Curve identifier type |
| `stsafe_slot_t` | typedef | Key slot identifier type |
| `STSAFE_ECC_CURVE_P256` | macro | P-256 curve ID value |
| `STSAFE_ECC_CURVE_P384` | macro | P-384 curve ID value |
| `STSAFE_KEY_SLOT_0/1/EPHEMERAL` | macros | Key slot values |
| `STSAFE_A_OK` | macro | Success return code |
| `STSAFE_MAX_KEY_LEN` | macro | Max key size in bytes (48) |
| `STSAFE_MAX_PUBKEY_RAW_LEN` | macro | Max public key size (96) |
| `STSAFE_MAX_SIG_LEN` | macro | Max signature size (96) |

And provide implementations for these internal interface functions:
- `int stsafe_interface_init(void)`
- `int stsafe_create_key(stsafe_slot_t*, stsafe_curve_id_t, uint8_t*)`
- `int stsafe_sign(stsafe_slot_t, stsafe_curve_id_t, uint8_t*, uint8_t*)`
- `int stsafe_verify(stsafe_curve_id_t, uint8_t*, uint8_t*, uint8_t*, uint8_t*, int32_t*)`
- `int stsafe_shared_secret(stsafe_slot_t, stsafe_curve_id_t, uint8_t*, uint8_t*, uint8_t*, int32_t*)`
- `int stsafe_read_certificate(uint8_t**, uint32_t*)`
- `int stsafe_get_random(uint8_t*, uint32_t)` (if `USE_STSAFE_RNG_SEED` defined)

When **NOT** defined (default behavior): All code is self-contained in `stsafe.c` using the appropriate SDK automatically.

The implementation provides these internal operations:

| Operation | Description |
|-----------|-------------|
| `stsafe_interface_init()` | Initialize the STSAFE device (called by `wolfCrypt_Init()`) |
| `stsafe_sign()` | ECDSA signature generation (P-256/P-384) |
| `stsafe_verify()` | ECDSA signature verification (P-256/P-384) |
| `stsafe_create_key()` | Generate ECC key pair on device |
| `stsafe_shared_secret()` | ECDH shared secret computation |
| `stsafe_read_certificate()` | Read device certificate from secure storage |

### STSELib Setup (A120)

For STSAFE-A120, you need to include the STSELib library:

1. Clone STSELib as a submodule or add to your project:
   ```bash
   git submodule add https://github.com/STMicroelectronics/STSELib.git lib/stselib
   ```

2. Add STSELib headers to your include path

3. Implement the platform abstraction files required by STSELib:
   - `stse_conf.h` - Configuration (target device, features)
   - `stse_platform_generic.h` - Platform callbacks (I2C, timing)

4. See STSELib documentation for platform-specific integration details

### Raspberry Pi with STSAFE-A120

For testing on a Raspberry Pi with an STSAFE-A120 connected via I2C:

1. **Enable I2C** on the Raspberry Pi:
   ```bash
   sudo raspi-config
   # Navigate to: Interface Options -> I2C -> Enable
   ```

2. **Verify the STSAFE device is detected** (default I2C address is 0x20):
   ```bash
   sudo i2cdetect -y 1
   ```

3. **Build wolfSSL with STSAFE-A120 support**:
   ```bash
   ./configure --enable-pkcallbacks --enable-cryptocb \
       CFLAGS="-DWOLFSSL_STSAFEA120 -I/path/to/STSELib"
   make
   sudo make install
   ```

4. **Platform abstraction**: Implement the STSELib I2C callbacks using the Linux I2C driver (`/dev/i2c-1`).

### Benchmarks and Memory Use

Software only implementation (STM32L4 120Mhz, Cortex-M4, Fast Math):

```
ECDHE    256 key gen       SW    4 ops took 1.278 sec, avg 319.500 ms,  3.130 ops/sec
ECDHE    256 agree         SW    4 ops took 1.306 sec, avg 326.500 ms,  3.063 ops/sec
ECDSA    256 sign          SW    4 ops took 1.298 sec, avg 324.500 ms,  3.082 ops/sec
ECDSA    256 verify        SW    2 ops took 1.283 sec, avg 641.500 ms,  1.559 ops/sec
```

Memory Use:

```
Peak Stack: 18456
Peak Heap: 2640
Total: 21096
```


STSAFE-A100 acceleration:

```
ECDHE    256 key gen       HW    8 ops took 1.008 sec, avg 126.000 ms,  7.937 ops/sec
ECDHE    256 agree         HW    6 ops took 1.051 sec, avg 175.167 ms,  5.709 ops/sec
ECDSA    256 sign          HW   14 ops took 1.161 sec, avg  82.929 ms, 12.059 ops/sec
ECDSA    256 verify        HW    8 ops took 1.184 sec, avg 148.000 ms,  6.757 ops/sec
```

Memory Use:

```
Peak Stack: 9592
Peak Heap: 170
Total: 9762
```


## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
