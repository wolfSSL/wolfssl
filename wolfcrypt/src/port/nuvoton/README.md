# Nuvoton (nuvoton) Port

Hardware crypto for the Nuvoton NuMicro **M2354** series (Arm Cortex-M23,
Armv8-M baseline, TrustZone). Written against the
[M2354BSP](https://github.com/OpenNuvoton/M2354BSP) StdDriver and developed on
the [NuMaker-M2354](https://www.nuvoton.com/board/numaker-m2354/)
(M2354KJFAE, 1 MB flash, 256 KB SRAM, 96 MHz).

The part carries three separate blocks, and this port drives all three:

| Block | What it does |
|---|---|
| CRPT | AES, SHA, ECC and RSA accelerator, plus a PRNG |
| TRNG | Entropy source, separate IP, seeds the CRPT PRNG |
| Key Store | Key slots in SRAM, Flash and OTP, used by handle |

The port is a **crypto callback device**: software stays compiled in, and
anything the hardware cannot do is declined and runs in software rather than
failing. Nothing in the wolfSSL core grows a struct member for it - a Key Store
handle rides in the standard `devCtx` of the `Aes` or `ecc_key` it belongs to.

## Enabling

Define `WOLFSSL_NUVOTON_M2354` in `user_settings.h` and add
`wolfcrypt/src/port/nuvoton/*.c` to your project. With nothing else named,
every engine is offloaded. Name one or more of these instead and only those
are:

```c
#define WOLFSSL_NUVOTON_M2354
/* optional, otherwise all of them */
#define WOLFSSL_NUVOTON_TRNG
#define WOLFSSL_NUVOTON_HASH
#define WOLFSSL_NUVOTON_CIPHER
#define WOLFSSL_NUVOTON_ECC
#define WOLFSSL_NUVOTON_RSA
#define WOLFSSL_NUVOTON_KS
```

`wolfssl/wolfcrypt/port/nuvoton/nuvoton_settings.h` carries the full list,
including `WOLFSSL_NUVOTON_DEVID`, `WOLFSSL_NUVOTON_DMA_BUF_SZ` and
`WOLFSSL_NUVOTON_HW_TIMEOUT`.

Bring the device up once, then route work to it by device id:

```c
wolfCrypt_Init();
wc_NuvotonCryptoCb_RegisterDevice(WOLFSSL_NUVOTON_DEVID);

wc_AesInit(&aes, NULL, WOLFSSL_NUVOTON_DEVID);
wc_ecc_init_ex(&key, NULL, WOLFSSL_NUVOTON_DEVID);
/* or for a whole TLS context: */
wolfSSL_CTX_SetDevId(ctx, WOLFSSL_NUVOTON_DEVID);
```

### The CRPT interrupt is required

The BSP's ECC and RSA drivers block on a flag that only the CRPT interrupt
sets (`ECC_DriverISR` in `Library/StdDriver/src/crypto.c`). Route it:

```c
void CRPT_IRQHandler(void)
{
    ECC_DriverISR(CRPT);
}
...
NVIC_EnableIRQ(CRPT_IRQn);
```

The port arms `ECCIEN`/`ECCEIEN` during init, so the application supplies only
the handler and the NVIC line. The NVIC line alone is not enough - nothing in
the BSP driver sets `CRPT->INTEN`. Without the handler every public key call
spins to its timeout and returns `WC_HW_E`, deliberately an error rather than a
silent slow fallback that would hide the wiring mistake.

:warning: **Timeouts with the handler installed mean a misaligned vector
table.** The M2354 implements 132 exceptions, so `VTOR` must be **1024**-byte
aligned, not the 128 or 256 a smaller part needs. Nothing fails at startup and
only the first exception goes astray - usually the CRPT one. An image linked at
`0x00000000` is aligned by construction, so this only bites behind a header, as
a bootloader payload is. The example's `build.sh` rejects a misaligned image.

## What is offloaded

| Engine | Operations | Notes |
|---|---|---|
| TRNG | `wc_GenerateSeed`, `WC_ALGO_TYPE_RNG` | Also wired into the `wc_GenerateSeed` chain in `wolfcrypt/src/random.c`, so a `WC_RNG` built with `INVALID_DEVID` still gets entropy |
| SHA | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | Streaming, see below |
| AES | ECB, CBC, CTR | 128, 192 and 256 bit, whole blocks |
| AES-GCM | Encrypt, decrypt and GMAC | Any size: one round up to `WOLFSSL_NUVOTON_GCM_BUF_SZ`, DMA cascade above it |
| AES-CCM | Encrypt and decrypt | Nonce 7 to 13 bytes, up to `WOLFSSL_NUVOTON_GCM_BUF_SZ` of packed packet |
| ECC | ECDSA sign and verify, ECDH, key generation | P-192, P-224, P-256, P-384, P-521, Brainpool P-256/384/512 |
| RSA | Public and private modular exponentiation | 1024, 2048, 3072 and 4096 bit |
| Key Store | AES keys by handle | `wolfssl/wolfcrypt/port/nuvoton/nuvoton_key.h` |

There is one CRPT channel and the staging buffers are static, so every engine
call is serialised with `wolfSSL_CryptHwMutex*`. Those compile to nothing
unless `WOLFSSL_CRYPT_HW_MUTEX` is set, so the port turns it on for any build
that is not `SINGLE_THREADED`. `WOLFSSL_NUVOTON_NO_HW_MUTEX` opts out, which is
only safe if nothing else can enter the port concurrently.

Declined, and therefore run in software:

| Case | Why |
|---|---|
| AES-CCM past `WOLFSSL_NUVOTON_GCM_BUF_SZ` | GCM has a DMA cascade for this, CCM does not |
| AES-CTR not starting on a block boundary | The engine cannot resume part way into a key stream block (`aes->left`) |
| SHA-512/224 and SHA-512/256 | Different initial values; the engine does full SHA-512 only |
| The empty message | The SHA result register is only written by a DMA round, and a zero length round does not start one |
| Curves the engine lacks, other RSA sizes | Not implemented in hardware |
| ECC keys held in the Key Store | Vendor bug, see below |

:warning: `ECC_GenerateSignature_KS()` reports success and returns a well formed
signature that does not verify: `r` comes back as the base point x coordinate -
the answer for `k = 1` - for every slot layout tried, so the engine is not
taking `k` from the slot. The register form is correct on the same vector, so
this is not wolfSSL-side marshalling. Pending an answer from Nuvoton,
`wc_NuvotonKs_SetEccKey()` is not offered. AES keys from the store work.

## Key Store

A key written to the store gets a slot, and from then on the application uses
the handle. The key material never enters wolfCrypt memory again:

```c
wc_NuvotonKsKey ksKey;
Aes aes;

wc_NuvotonKs_Write(&ksKey, WC_NUVOTON_KS_MEM_SRAM, WC_NUVOTON_KS_OWNER_AES,
                   256, keyBytes, sizeof(keyBytes), 0 /* not readable */);

wc_AesInit(&aes, NULL, WOLFSSL_NUVOTON_DEVID);
wc_NuvotonKs_SetAesKey(&aes, &ksKey);
wc_AesSetIV(&aes, iv);
wc_AesCbcEncrypt(&aes, out, in, sizeof(in));
```

The handle has to outlive the object that points at it.

:warning: **OTP slots cannot be rewritten,** and `KS_EraseKey()` in the BSP
writes `KS_SRAM` into the metadata itself, so only a volatile slot can be
cleared. Flash and OTP keys are retired with `wc_NuvotonKs_Revoke()`. Both are
permanent.

## TrustZone

`CRPT`, `TRNG` and the Key Store are secure-only peripherals in the default SCU
partition, and `M2354.h` has no `KS_NS` alias at all. So where wolfCrypt runs
decides how it reaches them, and the port is built for either:

| Macro | wolfCrypt runs | How it reaches the hardware |
|---|---|---|
| `WOLFSSL_NUVOTON_SECURE` (default) | Secure world, which is also where a non-TrustZone application runs | `nuvoton_hw.c` calls the BSP drivers directly |
| `WOLFSSL_NUVOTON_NSC` | Non-secure world | `cmse_nonsecure_entry` veneers in a secure partition |

Everything the port does to the hardware goes through `wc_nuvoton_hw_*` in
`nuvoton_hw.h`, and no other file in the port includes a BSP header, so that is
the only seam between the two and the rest of the port is byte-identical either
way. The secure half lives in wolfssl-examples at
`embedded/nuvoton_m2354/secure/nuvoton_nsc.c`: one veneer per call, copying the
request into secure memory and validating every pointer with
`cmse_check_address_range()` first.

Two build notes:

- `NSC_Init()` programs **SAU region 3** from the `__start_NSC`/`__end_NSC`
  linker symbols, so a partition header must not also enable a static SAU
  region over those addresses. Overlapping SAU regions are UNPREDICTABLE in
  Armv8-M and every secure gateway call then faults.
- `system_M2354.c` must be compiled with `-mcmse`, or its SAU and SCU setup
  compiles to nothing and the part runs with the SAU disabled.

## Hashing

The SHA engine keeps its working state in `HMAC_FDBCK` (1728 bits, readable
*and writable*), and `HMAC_FBADDR` swaps that state to an SRAM buffer by DMA.
Every context gets its own buffer, so nothing of a message stays in the engine
between calls and hashes interleave freely - a TLS transcript hash against the
record MAC, or a `wc_Sha256Copy` fork, are safe by construction. A context
costs a fixed **~350 bytes** regardless of message length.

:warning: Nuvoton's own mbedTLS layer does not use the feedback registers, so
reading only that layer suggests the engine cannot save state at all. It can;
the mechanism is in the TRM and in `crpt_reg.h`.

## DMA addressing

CRPT DMA reads and writes only word-aligned SRAM addresses in the `0x2xxxxxxx`
region, as the BSP's own `aes_alt.c` states. **Both aliases count:** secure code
sees SRAM at `0x2xxxxxxx`, non-secure code sees the same memory at `0x3xxxxxxx`,
and the alias a transfer is given decides the security attribute of the access.
Buffers arriving through the veneers are non-secure, carry `0x3xxxxxxx`, and are
passed through unchanged.

:warning: Opposite polarity from the NXP TrustZone parts, where `0x3xxxxxxx` is
the secure alias.

AES bounces anything that does not qualify through a buffer sized by
`WOLFSSL_NUVOTON_DMA_BUF_SZ` (six blocks by default). SHA declines to software
instead, since staging a whole message would need a cascade and so exclusive use
of the engine across calls. In practice a message from `XMALLOC` always
qualifies.

## Multi-threading

The CRPT has one usable channel and the port serializes every operation on
`wolfSSL_CryptHwMutexLock()`. A build with `SINGLE_THREADED` gets that for
free.

## Example project

A runnable `wolfcrypt_test` and benchmark for the NuMaker-M2354 lives in
wolfssl-examples under `embedded/nuvoton_m2354`, with the non-secure callable
veneers, a `user_settings.h` to start from, and the CRPT interrupt handler.

## Status

Validated on a NuMaker-M2354 (M2354KJFAE at 96 MHz, UART0 on PA6/PA7).
`wolfcrypt_test` runs to completion with **no failures**, covering every
offloaded engine. Two things the suite does not reach were covered on the
board separately: the Key Store round trip in the example, and a sweep of
AES-GCM and AES-CCM against software across payload, nonce and tag lengths,
since the suite's GCM vectors use a single payload length and so miss the
boundary between the one-shot and cascade forms.

A two-image TrustZone build (NSCBA at `0x00080000`) has also been run on the
board, and every algorithm passes from the non-secure side - including **ECC**,
which depends on the CRPT interrupt being taken in the secure world, and the
Key Store round trip.

Host `--enable-all --enable-cryptocb` `make check` is unchanged by this port,
`check-headers` and `check-source-text` are clean, and both cross-compile legs
build under `-Wall -Wextra -Werror`.

A run on the non-secure path that stops printing after the RSA test is the
same `WOLFSSL_KEY_GEN` effect described under Status, not a TrustZone problem:
the next thing the suite does is a software 2048-bit DH parameter search. Each
of those tests passes when called directly across the boundary (`rsa 0`,
`dh 0`, `pwdbased 0`, `ecc 0`).

## Benchmarks

NuMaker-M2354 at 96 MHz. **Both columns come from the same build**, with
`WOLFSSL_HAVE_SP_ECC`, `WOLFSSL_HAVE_SP_RSA` and the Thumb-1 SP assembly
enabled, so the software column is wolfSSL configured properly for this core
rather than falling back to portable C. Measuring against an unoptimised
software baseline roughly triples the apparent speedup.

| Algorithm | Software | Hardware |
|---|---|---|
| SHA-1 | 1.850 MiB/s | 8.521 MiB/s |
| SHA-224 | 768.8 KiB/s | 8.740 MiB/s |
| SHA-256 | 771.1 KiB/s | 8.707 MiB/s |
| SHA-384 | 270.7 KiB/s | 13.843 MiB/s |
| SHA-512 | 270.9 KiB/s | 13.951 MiB/s |
| SHA-512/224 | 270.9 KiB/s | 270.4 KiB/s (declined) |
| SHA-512/256 | 270.7 KiB/s | 270.1 KiB/s (declined) |
| HMAC-SHA-1 | 1.824 MiB/s | 8.041 MiB/s |
| HMAC-SHA-256 | 762.0 KiB/s | 8.211 MiB/s |
| HMAC-SHA-512 | 266.5 KiB/s | 12.671 MiB/s |
| AES-128-CBC enc | 411.4 KiB/s | 8.732 MiB/s |
| AES-128-CBC dec | 392.9 KiB/s | 8.838 MiB/s |
| AES-256-CBC enc | 293.5 KiB/s | 7.837 MiB/s |
| AES-256-CBC dec | 287.4 KiB/s | 7.919 MiB/s |
| AES-128-CTR | 435.6 KiB/s | 8.561 MiB/s |
| AES-256-CTR | 306.6 KiB/s | 7.707 MiB/s |
| AES-128-ECB enc | 451.0 KiB/s | 11.494 MiB/s |
| AES-256-ECB enc | 316.2 KiB/s | 9.990 MiB/s |
| AES-128-GCM enc | 285.4 KiB/s | 721.4 KiB/s |
| RNG (Hash-DRBG) | - | 705.9 KiB/s |

The SHA-512/224 and SHA-512/256 rows matching software is the port correctly
declining those two. The RNG row is wolfCrypt's Hash-DRBG seeded from the TRNG,
the default; see `WOLFSSL_NUVOTON_RNG_OFFLOAD`. Public key timings are omitted
because the benchmark generates an RSA-3072 key first, which takes over seven
minutes on this part.

# wolfBoot

wolfBoot has an M2354 target that builds on this port, including the TrustZone
arrangement: https://github.com/wolfSSL/wolfBoot/pull/884

# Support

For questions please email support@wolfssl.com
