# Silicon Labs (silabs) Port

Support for the Silicon Labs hardware acceleration

Tested on ERF32 Gecko Series 2 device config 1 (Secure Element)

* https://docs.silabs.com/mcu/latest/efr32mg21/group-SE
* https://docs.silabs.com/gecko-platform/latest/service/api/group-sl-se-manager

There are two independent ports over the same SE Manager code:

| Port | Macro | Shape |
|---|---|---|
| Direct | `WOLFSSL_SILABS_SE_ACCEL` | Replaces the software implementation of each supported algorithm at compile time. All or nothing per algorithm; no `devId`, no runtime fallback. |
| Crypto callback | `WOLFSSL_SILABS_CRYPTOCB` | Routes operations through the wolfCrypt crypto callback framework by `devId`. Software stays compiled in, so anything the SE cannot do falls back instead of failing. |

They are mutually exclusive; defining both is a compile error. Both share the
`silabs_aes.c` / `silabs_ecc.c` / `silabs_hash.c` / `silabs_random.c` helpers,
and both pull the SE context members into `Aes`, `ecc_key` and `wc_Sha*` via the
internal `WOLFSSL_SILABS_SE_TYPES` umbrella.

## Building the direct port

To enable support define the following:

```
#define WOLFSSL_SILABS_SE_ACCEL
```

## Building the crypto callback port

```
#define WOLFSSL_SILABS_CRYPTOCB
```

That is all that is required: it turns on `WOLF_CRYPTO_CB`, registers the device
from `wolfCrypt_Init()` at `WOLFSSL_SILABS_DEVID` (default `0x5345`), and points
`WC_USE_DEVID` at it so the unmodified `wolfcrypt_test` and `benchmark` exercise
the hardware. Defining `WC_USE_DEVID` yourself overrides that.

By default every supported engine is offloaded. To offload a subset, define one
or more of these instead, in which case only those are used:

```
WOLFSSL_SILABS_CRYPTOCB_TRNG
WOLFSSL_SILABS_CRYPTOCB_HASH
WOLFSSL_SILABS_CRYPTOCB_CIPHER
WOLFSSL_SILABS_CRYPTOCB_CMAC
WOLFSSL_SILABS_CRYPTOCB_ECC
WOLFSSL_SILABS_CRYPTOCB_KDF
```

### What is offloaded

| Engine | Operations | Notes |
|---|---|---|
| TRNG | seed, and whole blocks with `WOLFSSL_SILABS_TRNG` | |
| Hash | SHA-1, SHA-224, SHA-256; SHA-384 and SHA-512 on Secure Vault High | SHA-512/224 and SHA-512/256 stay in software |
| Cipher | AES ECB/CBC/CTR/GCM/CCM | GCM tags shorter than 16 bytes fall back to software |
| Cipher | ChaCha20-Poly1305 | Secure Vault High only |
| CMAC | AES-CMAC, streaming and one-shot | |
| ECC | ECDSA sign/verify, ECDH, key generation | P-256 always; P-192 and, on Vault High, P-384 and P-521 |
| KDF | HKDF, PBKDF2 | Secure Vault High only |

There is **no RSA engine**: the Series 2 High Security Engine has no RSA
hardware, so RSA always runs in software.

There is **no HMAC engine**, and none is needed. wolfCrypt's HMAC gives its
inner and outer hash contexts the `Hmac`'s own `devId`, so every hash block of
an HMAC already runs on the SE through the hash engine. The SE's own HMAC
streaming state has no room to buffer a partial block, so a dedicated engine
would have to re-block the message for no gain.

AES-CTR is offloaded only for whole-block requests made on a block boundary.
The SE tracks the keystream with an mbedTLS-style offset while wolfCrypt tracks
unused bytes in `aes->tmp`; rather than translate between the two mid-keystream,
partial-block requests fall back to software, which keeps both representations
consistent because the SE updates the counter in `aes->reg` the same way.

When `WOLFSSL_ARMASM` is defined, AES-CTR is left entirely in software. The
Thumb2 assembly implementation keeps the keystream remainder on a different
contract than the C one, so a stream split between it and the SE does not line
up. Every other engine is unaffected by `WOLFSSL_ARMASM`.

Note that ChaCha20-Poly1305 dispatch is *keyless*: the wolfCrypt one-shot API
carries no key object and therefore no `devId`, so it is offered to whichever
device occupies callback slot 0. Registering this port means its ChaCha20-Poly1305
is offloaded regardless of any per-object `devId`.

### TLS 1.3

The port is exercised under a real TLS 1.3 handshake, not only the wolfCrypt
known answer vectors. `IDE/SimplicityStudio/xg25` builds an on-device test
(`WOLFSSL_XG25_TLS13`) that runs a client and a server against each other over
an in-memory transport with the SE `devId` set on both, once per TLS 1.3 cipher
suite, followed by application data through the record layer. Both suites pass
on an EFR32FG25.

That path matters because it drives the engines differently from the vector
tests: buffers arrive at arbitrary offsets rather than as aligned stack arrays,
and a single `Aes` object is reused across many chained records, so state that
is not carried correctly between calls fails rather than passing by luck.

Note that the SE is the only entropy source on the part. `wc_GenerateSeed()` is
wired to the SE TRNG for both ports, so a software DRBG can still be seeded when
an operation falls back; without that an `WC_RNG` built with `INVALID_DEVID` has
no seed at all and fails with `RNG_FAILURE_E`.

### Secure Vault key management

On a Secure Vault High part the SE can hold keys the application never sees. A
*wrapped* key is encrypted to a device-unique key: the SE uses it, the
application only ever handles the wrapped blob. A *built-in* key lives in an SE
slot and is named rather than supplied. Either kind binds to an ordinary `Aes`
or `ecc_key`, after which the normal wolfCrypt calls run on the SE against it:

```c
byte   wrapped[64];
word32 wrappedSz = (word32)sizeof(wrapped);
Aes    aes;

wc_SilabsSe_AesGenerateWrappedKey(256, wrapped, &wrappedSz);
wc_AesInit(&aes, NULL, WOLFSSL_SILABS_DEVID);
wc_SilabsSe_AesUseWrappedKey(&aes, wrapped, wrappedSz, 256);
/* wc_AesGcmEncrypt() and friends now run on the SE with that key */
```

The ECC equivalents are `wc_SilabsSe_EccGetWrappedKeySize()`,
`wc_SilabsSe_EccGenerateWrappedKey()` (which can also export the public point
as X||Y) and `wc_SilabsSe_EccUseWrappedKey()`. Built-in slots bind with
`wc_SilabsSe_AesUseBuiltInKey()` and `wc_SilabsSe_EccUseBuiltInKey()`, taking a
slot such as `SL_SE_KEY_SLOT_APPLICATION_ATTESTATION_KEY` or
`SL_SE_KEY_SLOT_APPLICATION_AES_128_KEY`.

Two things to keep in mind:

* The key descriptor **references** the caller's wrapped buffer rather than
  copying it, so that buffer must outlive the `Aes` / `ecc_key` bound to it.
* Wrapped keys need Secure Vault High. The built-in slots do not. On a Vault
  Mid part the wrapped-key functions compile out; define
  `WOLFSSL_SILABS_NO_VAULT_KEYS` to drop their prototypes too.

Generating a key into an `ecc_key` that is already bound to device-resident
material returns `BAD_FUNC_ARG` rather than silently discarding the binding;
use `wc_SilabsSe_EccGenerateWrappedKey()` for that.

### Host compile test

`./configure --enable-silabs-cryptocb` builds the port on a host with no
Simplicity SDK installed, by swapping the SE Manager headers for
`wolfcrypt/src/port/silabs/silabs_shim.h` (`WOLFSSL_SILABS_HOST_TEST`). Every
stub returns `SL_STATUS_NOT_SUPPORTED`, which the port maps to
`CRYPTOCB_UNAVAILABLE`, so `make check` passes entirely in software while
exercising each engine's decline-and-fall-back path. It is a build gate;
correctness is established on EFR32 silicon.

The shim models a Secure Vault High Series 2 Config 5 part. Defining
`WOLFSSL_SILABS_HOST_TEST_VAULT_MID` models a Vault Mid part instead, which
compile-tests that every Vault-only path (SHA-384/512, P-384/P-521,
ChaCha20-Poly1305, the SE KDFs and wrapped keys) drops out cleanly.

## Simplicity Studio Example

For the Silicon Labs Simplicity Studio example see [/IDE/SimplicityStudio/README.md](/IDE/SimplicityStudio/README.md).

## Caveats

:warning: **Be sure to update the SE firmware** Testing and results were done using SE firmware `1.2.6`

Update was performed under Simplicity Studio directory:
    `./developer/adapter_packs/commander/commander  flash ./offline/efr32/firmware/series2config1/se_firmware_package/s2c1_se_fw_upgrade_app_1v2p6.hex`

 * AES GCM tags length >= 16 bytes
 * By default random generator is seeded by the TRNG, but not used to
   generate all random data. `WOLFSSL_SILABS_TRNG` can be set to
   generate all random data with hardware TRNG. On early SE firmware
   versions requesting too much data or too quickly may result in
   system reset and setting `SESYSREQ`.

### Multi-threading

The SE manager supports multi-threading for FreeRTOS and Micrium
([ref](https://docs.silabs.com/gecko-platform/latest/service/api/group-sl-se-manager#autotoc-md152)).
If a different OS is used with multi-threading, additional mutex protection may be necessary.

## Benchmarks

See our [benchmarks](https://www.wolfssl.com/docs/benchmarks/) on the wolfSSL website.

### Crypto callback port, EFR32xG25

Measured with `IDE/SimplicityStudio/xg25` on an **EFR32FG25B222F1920IM56** (Secure Vault High, SE firmware 2.2.0), wolfSSL 5.9.2. Because `WOLFSSL_SILABS_CRYPTOCB` sets `WC_USE_DEVID`, the stock benchmark runs every algorithm twice and labels the rows `HW` and `SW`, so each software/Secure Element pair comes from a single run on one part.

Both builds define the `--enable-harden` options (`ECC_TIMING_RESISTANT`, `WC_RSA_BLINDING`), so these are hardened numbers. They cost nothing measurable in this configuration, which routes P-256 through the already constant-time `WOLFSSL_SP_MATH_ALL`/`WOLFSSL_HAVE_SP_ECC` path: every ECC and RSA row moved by less than 0.3% when the options were added.

The two software columns are two builds of that same project. **Software (C)** is the default: portable C for the symmetric and hash algorithms. **Software (Thumb2 asm)** additionally defines `WOLFSSL_ARMASM` (see the commented block in the example's `user_settings.h`), which brings in wolfSSL's Cortex-M Thumb2 assembly. Both builds already use `WOLFSSL_SP_ARM_CORTEX_M_ASM` for ECC and RSA, which is why the ECC rows are identical -- there is no plain-C ECC baseline here to beat.

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

Rows where the Secure Element is **slower** are reported as measured. SHA-1 and HMAC-SHA-1 are cheap enough on a 78 MHz Cortex-M33 that the SE mailbox round trip costs more than it saves at this message size. The **RNG** row is the widest gap and the least surprising: the `HW` column asks the SE for every byte, while the `SW` column is a SHA-256 DRBG seeded once from the same SE TRNG. Seeding a DRBG is the normal way to use a hardware entropy source, and it is what wolfSSL does by default -- the `HW` row measures raw TRNG throughput, not the speed of getting random data. Everything else gains, most of all **AES-GCM** at up to **9.4x**.

**AES-CTR** shows `n/a` against the assembly build because the port declines CTR when `WOLFSSL_ARMASM` is defined (see above), so that build has no Secure Element CTR number to compare.

**ChaCha20-Poly1305** has no paired row: its one-shot API carries no `devId`, so the benchmark runs it once. It is offloaded nonetheless -- the assembly build leaves `CHA-POLY-enc` unchanged (2453 vs 2459 KiB/s) while speeding the software-only incremental variants up by 17%.

**RSA** and **DH** are omitted: Series 2 has no RSA hardware, so they measure identically in both columns. **SHA-384/512** likewise: the SE supports them on Secure Vault High, but the SE context does not survive the context copy that `wc_ShaXXXGetHash()` performs, so they are left to software until that is implemented. Measurement showed no throughput gain over software for either.

### Direct port, EFR32MG21

```
RNG                  2 MB took 1.004 seconds,    1.897 MB/s
AES-128-CBC-enc      5 MB took 1.001 seconds,    4.902 MB/s
AES-128-CBC-dec      5 MB took 1.004 seconds,    4.912 MB/s
AES-192-CBC-enc      5 MB took 1.002 seconds,    4.800 MB/s
AES-192-CBC-dec      5 MB took 1.000 seconds,    4.810 MB/s
AES-256-CBC-enc      5 MB took 1.001 seconds,    4.707 MB/s
AES-256-CBC-dec      5 MB took 1.005 seconds,    4.713 MB/s
AES-128-GCM-enc      4 MB took 1.000 seconds,    4.468 MB/s
AES-128-GCM-dec      4 MB took 1.005 seconds,    4.324 MB/s
AES-192-GCM-enc      4 MB took 1.003 seconds,    4.381 MB/s
AES-192-GCM-dec      4 MB took 1.001 seconds,    4.244 MB/s
AES-256-GCM-enc      4 MB took 1.005 seconds,    4.300 MB/s
AES-256-GCM-dec      4 MB took 1.002 seconds,    4.166 MB/s
AES-CCM-Enc          4 MB took 1.005 seconds,    4.203 MB/s
AES-CCM-Dec          4 MB took 1.005 seconds,    4.057 MB/s
SHA                  7 MB took 1.000 seconds,    7.202 MB/s
SHA-224              7 MB took 1.001 seconds,    7.341 MB/s
SHA-256              7 MB took 1.000 seconds,    7.349 MB/s
HMAC-SHA             6 MB took 1.001 seconds,    6.390 MB/s
HMAC-SHA224          6 MB took 1.003 seconds,    6.475 MB/s
HMAC-SHA256          6 MB took 1.000 seconds,    6.470 MB/s
ECC      256 key gen       169 ops took 1.003 sec, avg 5.935 ms, 168.495 ops/sec
ECDHE    256 agree         184 ops took 1.003 sec, avg 5.451 ms, 183.450 ops/sec
ECDSA    256 sign          158 ops took 1.010 sec, avg 6.392 ms, 156.436 ops/sec
ECDSA    256 verify        148 ops took 1.001 sec, avg 6.764 ms, 147.852 ops/sec
```


# Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
