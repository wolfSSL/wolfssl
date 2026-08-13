# TI C2000 C28x (CHAR_BIT == 16) support

wolfCrypt builds and runs on the TI C2000 C28x DSP family, a word-addressed
architecture where `CHAR_BIT == 16` (a C `char`/`unsigned char` is 16 bits and
is the smallest addressable unit). Support is gated behind `WOLFSSL_WIDE_BYTE`,
which `wolfssl/wolfcrypt/types.h` auto-enables when `CHAR_BIT != 8` or a known
16-bit-char TI toolchain macro is seen (`__TMS320C28XX__`, `__TMS320C2000__`,
etc.). On normal 8-bit-byte targets none of this code changes behavior.

## Validated on hardware (LAUNCHXL-F28P55X, TMS320F28P550SJ, cl2000)

- SHA-1; SHA-224/256, SHA-384/512, SHA-512/224, SHA-512/256
- SHA3-224/256/384/512, SHAKE128/256 (split-64 Keccak permutation auto-enabled
  for `WOLFSSL_WIDE_BYTE`, ~53% faster than the generic C path)
- ML-DSA-44/65/87 (Dilithium) verify and full keygen/sign/verify;
  ML-KEM-512/768/1024 (FIPS 203)
- AES-128/192/256 CBC/CTR/CFB/OFB/GCM/XTS; AES-CMAC, AES-CCM, AES-GMAC,
  AES-SIV, AES-EAX
- HMAC + HKDF; ChaCha20-Poly1305; Poly1305
- X25519 + Ed25519; X448 + Ed448 (CURVE448_SMALL/ED448_SMALL byte backend)
- ECDSA + ECDH (SECP256R1, SP math)
- RSA-2048 PKCS#1 v1.5 sign and verify; DH FFDHE-2048 (SP math)

The on-target acceptance gate is the per-algorithm KAT set the reference example
prints over JTAG (e.g. `ML-DSA-87 verify KAT: PASS`, `X448 a*Bpub: PASS`); the
split-64 Keccak path is additionally validated on a host build with
`-DWC_SHA3_SPLIT64` forced, and the compile-only CI below guards every
`WOLFSSL_WIDE_BYTE` source against build breakage.

## What `WOLFSSL_WIDE_BYTE` fixes

The `CHAR_BIT != 8` work falls into a few recurring classes, each a no-op on
8-bit targets:

- Byte/word aliasing. Serializing a `word32`/`word64` via a `byte*` cast moves
  cells, not octets. Replaced with shift-based octet I/O. Shared helpers live in
  `wolfcrypt/src/misc.c`: `WordsFromBytesBE32`/`BytesFromWordsBE32`,
  `BytesFromWordsLE32`, the 64-bit variants, and octet-correct
  `readUnalignedWord32`/`readUnalignedWord64`. `sp_int.c sp_read_unsigned_bin`
  uses the endian-/`CHAR_BIT`-agnostic shift loop for its leftover bytes.
- `(byte)x` not truncating to an octet (it keeps 16 bits). Masked with
  `WC_OCTET(x)` = `(byte)((x) & 0xFF)` (types.h). Used across the ML-KEM/ML-DSA
  encoders, the SP `*_to_bin` serializers, AES `GETBYTE`, base64, and DRBG.
- Integer-promotion bugs. `1U << n` is 16-bit on C28x (use `1UL`); a bit width
  written `sizeof(t) * 8` is wrong when `CHAR_BIT != 8` (use `CHAR_BIT *
  sizeof(t)`); a `byte` operand promotes to a 16-bit `int`.
- `sizeof` counting cells, not octets. e.g. `CHACHA_CHUNK_BYTES` is `16 * 4`,
  not `16 * sizeof(word32)` (= 32 on C28x, which halves the ChaCha block).

The SP backend file `wolfcrypt/src/sp_c32.c` is generated; the `& 0xFF` octet
masks added to its `sp_*_to_bin_*` serializers are also applied in the SP
generator templates so a regeneration preserves them (tracked separately).

## cl2000 compiler workarounds

TI `cl2000` (C28x) miscompiles a couple of ML-DSA 32-bit reductions on this
16-bit target; both are worked around in `dilithium.h`, defaulted on under
`WC_16BIT_CPU` (correct on every target, no-ops off `WC_16BIT_CPU`):

- `MLDSA_MUL_QINV_WIDE64` -- `mldsa_mont_red()`'s q^-1 step uses a 32x64->64
  widening multiply instead of 32x32->32.
- `MLDSA_MUL_Q_SLOW` -- `mldsa_red()`/`mldsa_mont_red()`'s `* q` step uses shifts
  (`q = 2^23 - 2^13 + 1`) instead of a multiply. At `-O2` cl2000 mis-generates
  `mldsa_red()`'s multiply-based Barrett reduction: the reduced value stays
  correct (the verify KAT passes) but the emitted code adds a stray store that
  corrupts memory a later allocation trips on; the shift form avoids it (a
  widening multiply does not). Isolated by pinning single functions to `-O1`
  with `#pragma FUNCTION_OPTIONS`.

With both, ML-DSA builds at full `-O2` on the C28x with no per-file overrides.

## Hardware AES (AESA)

The F28P55x/F28P65x carry an "AESA" accelerator (a TI EIP-120t instance) at
`0x00042000` supporting ECB/CBC/CTR/CFB/GCM/CCM with 128/192/256-bit keys.
wolfCrypt drives it through the **crypto-callback** framework rather than by
replacing `wolfcrypt/src/aes.c`:

- `wolfcrypt/src/port/ti/ti-c2000-aes.c` + `wolfssl/wolfcrypt/port/ti/ti-c2000.h`,
  gated on `WOLFSSL_C2000_AES` (which also needs `WOLF_CRYPTO_CB`).
- `wc_C2000_Init(devId)` enables/resets the block and registers the callback.
  It must be called **after `wolfCrypt_Init()`** -- that is what marks the
  device table slots `INVALID_DEVID`, and registration claims one of those.
- A context opts in with `wc_AesInit(&aes, NULL, WOLFSSL_C2000_DEVID)`; one
  initialised with `INVALID_DEVID` stays pure software. Software AES remains
  compiled in, so a single image can run identical vectors through both paths
  and compare -- which is how this port is validated.
- Anything the hardware cannot do returns `CRYPTOCB_UNAVAILABLE` and falls
  through to software: non-block-multiple CBC (ciphertext stealing), key
  lengths other than 16/24/32, and every mode outside ECB/CBC/CTR.

Phase 1 covers ECB, CBC and CTR. GCM/CCM/CMAC remain software for now.

### Measured throughput (LAUNCHXL-F28P55X at 150 MHz)

`benchmark` with `WC_USE_DEVID` pointing at the AESA device, so it emits paired
`SW`/`HW` rows:

| Operation | Software | AESA | Speedup |
|---|---|---|---|
| AES-128-ECB encrypt | 471 KiB/s | 2.37 MiB/s | 5.2x |
| AES-256-ECB encrypt | 377 KiB/s | 2.32 MiB/s | 6.3x |
| AES-128-CBC encrypt | 405 KiB/s | 2.36 MiB/s | 6.0x |
| AES-128-CBC decrypt | 388 KiB/s | 2.34 MiB/s | 6.2x |
| AES-256-CBC encrypt | 333 KiB/s | 2.31 MiB/s | 7.1x |
| AES-256-CBC decrypt | 322 KiB/s | 2.29 MiB/s | 7.3x |
| AES-128-CTR | 408 KiB/s | 1.45 MiB/s | 3.6x |
| AES-256-CTR | 335 KiB/s | 1.44 MiB/s | 4.4x |

Hardware throughput is essentially key-length independent, as expected for a
pipelined block engine -- so the speedup grows with key size, where software
pays for more rounds. CTR lands lower than ECB/CBC because the port does the
counter increment and the keystream XOR in software (see above); it is still
the mode that gains least in relative terms but it is unambiguously worth
offloading. AES-GCM moves only from ~32 to ~34 KiB/s: only its internal ECB
calls reach the accelerator, and the `GCM_SMALL` byte-wise GHASH dominates.
Doing GCM properly means using the block's own GCM mode, which is phase 2.

### Build overrides

All `#ifndef`-guarded in `wolfssl/wolfcrypt/port/ti/ti-c2000.h`:

| Macro | Default | Purpose |
|---|---|---|
| `WOLFSSL_C2000_DEVID` | `0x2000` | devId passed to `wc_AesInit()` and `wc_CryptoCb_RegisterDevice()` |
| `WOLFSSL_C2000_AES_BASE` | `0x00042000` | AESA register base (`AESA_BASE`) |
| `WOLFSSL_C2000_AES_SS_BASE` | `0x00042C00` | AESA wrapper base (`AESA_SS_BASE`) |
| `WOLFSSL_C2000_AES_NO_LOCK` | off | Assert an external lock instead of requiring `SINGLE_THREADED` |

The two base addresses are defaulted in the port rather than taken from a
device header, so the same source builds against any C2000 part that places
the block elsewhere.

### Two things the 16-bit byte forces

**Octet packing.** C2000Ware's AES API is `uint32_t*`-based. On the C28x a
`byte` buffer holds one octet per 16-bit cell and `sizeof(word32)` is 2, so the
`(uint32_t*)in` cast the TivaWare port (`ti-aes.c`) uses is wrong here. Every
transfer is staged through a local `uint32_t` block using the packing driverlib
actually expects, confirmed against its own vectors
(`driverlib/f28p55x/examples/aes/aes_ex1_ecb_encrypt.c` writes the FIPS-197 key
`2b7e1516...` as `{0x16157e2b, ...}`):

```
word[i] = b[4i] | (b[4i+1] << 8) | (b[4i+2] << 16) | (b[4i+3] << 24)
```

little-endian octets within each word, words in natural order. The
word-index reversal inside `AES_writeDataBlocking()` is internal to driverlib
and must not be compensated for. The port packs and unpacks locally
(`c2000_WordsFromOctets()` / `c2000_OctetsFromWords()`), staging through
`uint32_t` rather than wolfSSL's `word32`: `word32` is only 32-bit under
`WC_16BIT_CPU`, while driverlib writes `uint32_t` either way, so a `word32`
staging array would be half the size the hardware fills.

**The hardware CTR counter does not match wolfCrypt's.** Measured on a
LAUNCHXL-F28P55X: with `AES_OPMODE_CTR` + `AES_CTR_WIDTH_128BIT` the first
block matches NIST SP800-38A F.5.1, but later blocks diverge from software as
soon as an increment carries across an octet boundary (the F.5 counter starts
at `...fe ff`, so block 2 already does). The block's 128-bit counter increment
therefore disagrees with `IncrementAesCounter()`, which carries through all 16
octets. The port instead runs the accelerator in **ECB** mode and keeps the
counter in software: identical hardware block-operation count, correct by
construction.

Both traps are silent -- the first block is right either way, which is exactly
why the KAT harness checks multi-block, split-call and in-place cases.

### Chaining state

`aes->reg` is updated in software (last ciphertext block on encrypt, a copy of
the last input block saved *before* processing on decrypt, so in-place calls
work). `AES_readInitializationVector()` is deliberately not used: the
`IV_IN_OUT` registers only hold the saved context when `CTRL.SAVE_CONTEXT` is
set, which `AES_configureModule()` does not set, and driverlib's reader does
not poll `CTRL.SVCTXTRDY` the way `AES_readTag()` does.

### Threading

The AESA block is a single shared resource and the port reloads key, IV and
mode on every operation, so it is re-entrant across `Aes` contexts but **not**
across preemption or an ISR. `ti-c2000.h` therefore `#error`s unless
`SINGLE_THREADED` is defined, or `WOLFSSL_C2000_AES_NO_LOCK` asserts that an
external lock provides the guarantee.

## Enabling on your build

Define a user-settings header (see `IDE/C2000/user_settings.h` for a
minimal CHAR_BIT!=8 config) and build with `WOLFSSL_USER_SETTINGS`. For the SP
math backend on a 16-bit-int target also set `WOLFSSL_SP_MATH`,
`SP_WORD_SIZE 32`, and `WOLFSSL_SP_ALLOW_16BIT_CPU`.

## Reference example

A complete bare-metal example with KATs, benchmark, linker scripts, and per-
algorithm build toggles is in wolfSSL Examples:
`embedded/ti-c2000-f28p55x/` (see its `README.md` for the `make` options:
`ECC`, `MLKEM`, `AES`, `AESEXTRA`, `X25519`, `HKDF`, `CHACHA`, `RSA`, `SIGN`,
`BENCH`).

Representative throughput on the F28P55X at 150 MHz: SHA-256 ~284 KiB/s; SHA3-256
~264 KiB/s; SHAKE128 ~319 KiB/s; RNG Hash-DRBG ~122 KiB/s. ML-DSA-87 verify
~225 ms/op in ~10.7 KB RAM (zero heap, with `WOLFSSL_MLDSA_VERIFY_SMALLEST_MEM`
+ `WOLFSSL_MLDSA_ASSIGN_KEY`).

## Continuous integration

`IDE/C2000/compile.sh` runs `cl2000 --compile_only` over the
`CHAR_BIT != 8` wolfCrypt subset to guard these paths without hardware;
`.github/workflows/ti-c2000-compile.yml` runs it in CI. TI gates the C2000
code generation tools behind a login, so the workflow fetches the installer
from the `TI_C2000_CGT_URL` repo/org variable (mirror it to a wolfSSL release
asset or internal server; optionally pin `TI_C2000_CGT_SHA256`). When that
variable is unset the job is skipped with a notice rather than failing.
