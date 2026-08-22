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
| AES-128-ECB encrypt | 471 KiB/s | 2.39 MiB/s | 5.2x |
| AES-256-ECB encrypt | 377 KiB/s | 2.34 MiB/s | 6.3x |
| AES-128-CBC encrypt | 405 KiB/s | 2.37 MiB/s | 6.0x |
| AES-128-CBC decrypt | 388 KiB/s | 2.36 MiB/s | 6.2x |
| AES-256-CBC encrypt | 333 KiB/s | 2.32 MiB/s | 7.1x |
| AES-256-CBC decrypt | 322 KiB/s | 2.31 MiB/s | 7.3x |
| AES-128-CTR | 408 KiB/s | 1.45 MiB/s | 3.6x |
| AES-256-CTR | 335 KiB/s | 1.45 MiB/s | 4.4x |

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

## Entropy (no TRNG on this part)

The F28P55x has **no hardware TRNG** -- there is no RNG peripheral anywhere in
C2000Ware for this device, and the one "TRNG" string in `hw_asysctl.h`
(`ASYSCTL_PMMCONFIGDFT_VREFTRNG1P225`) is a voltage-reference *trim range*
field. What the part does have is three independent oscillators -- INTOSC1 and
INTOSC2 (on-chip ~10 MHz RC) and the external crystal that SYSCLK/PLLRAWCLK
derive from -- and two Dual-Clock Comparators that can count one against
another.

`wolfcrypt/src/port/ti/ti-c2000-entropy.c` (gate `WOLFSSL_C2000_ENTROPY`)
turns that into an entropy source: a DCC counts PLLRAWCLK edges inside a
window of INTOSC cycles, and the **LSB of that count** is one noise bit,
carrying the relative phase drift of two physically distinct oscillators. Raw
noise is oversampled far past its measured min-entropy, health-tested per
SP800-90B 4.4, conditioned with SHA-256, and handed to the SP800-90A
Hash-DRBG.

The work is split in two. The port file owns only the hardware -- DCC setup,
one measurement, and the noise bit. Everything above that is the generic
`wc_NoiseSrc_*` layer described below, which is not C2000-specific.

### Measured on hardware

Captured with the reference example's `ENTROPY_PROBE=1` build (262144 raw bits
per source, LSB extraction) and analyzed on a host with the example's
`tools/entropy_analyze.py`, so these numbers are reproducible rather than
asserted:

| Source | Hmin/bit | bias | max \|acf\| lag 1..64 | chi-square p |
|---|---|---|---|---|
| INTOSC1 window / PLL counted (DCC1) | **0.932** | -0.0000 | 0.005 | 0.623 |
| INTOSC2 window / PLL counted (DCC0) | 0.843 | -0.0027 | 0.005 | 0.000 |
| ADC LSB, floating input | 0.834 | -0.0086 | 0.073 | 0.000 |

Min-entropy is the SP800-90B 6.3.1 most-common-value estimate at the 99% upper
confidence bound, taken over the 8-bit octet alphabet and divided by 8. The
octet alphabet is used rather than the bit alphabet because it also catches
structure across adjacent bits: on a stream with strong lag-1 correlation but
no marginal bias, a per-bit estimate reports 0.99 and sees nothing while the
octet estimate collapses. **This is an MCV estimate plus bias and correlation
screening, not a full SP800-90B non-IID assessment** (`ea_non_iid` was not
run); MCV assumes IID, so it is an upper bound, and the low measured
correlation on the credited source is what makes it a reasonable one.

Read 0.932 against the estimator's ceiling, not against 1.0: at this sample
count a synthetic uniform stream estimates to 0.930 (`entropy_analyze.py
--selftest` prints it), so the credited source is statistically
indistinguishable from uniform here. These are single-run measurements of a
physical source and move a little between runs -- an earlier capture gave
0.924 / 0.775 / 0.865 for the three rows -- but the pass/fail conclusions have
been identical in every run.

Both DCC sources are gathered and hashed together, but **only INTOSC1 is
credited** with entropy: INTOSC2 estimates lower and fails a chi-square
uniformity check decisively (stat 1972 against 255 degrees of freedom), so it
is defence-in-depth that the budget does not rely on. Hashing extra input can
only add entropy, never remove it. The ADC source is not used by default -- it
also fails chi-square, and it depends on a spare analog pin being left
floating, which is a board property rather than a device one.

The port then assumes **0.5 bits per raw bit** (`WOLFSSL_C2000_ENTROPY_HMIN`)
and oversamples 2x on top of that (`WOLFSSL_C2000_ENTROPY_MARGIN`), i.e. 32
raw bits gathered per output octet -- roughly a 4x cushion over the credited
source's measured 0.924. At a 256-cycle window (~25.6 us per bit) a 32-octet
conditioning chunk costs about 26 ms per source.

### Build overrides

Everything is `#ifndef`-guarded in `wolfssl/wolfcrypt/port/ti/ti-c2000-entropy.h`, so a project can retune it from its own `user_settings.h`:

| Macro | Default | Purpose |
|---|---|---|
| `WOLFSSL_C2000_ENTROPY_NUM_SRC` | 2 | Set to 1 to use the credited source only and leave the second DCC free |
| `WOLFSSL_C2000_ENTROPY_SRC0_DCC` / `_SRC1_DCC` | `DCC1_BASE` / `DCC0_BASE` | Which DCC instance each source uses |
| `WOLFSSL_C2000_ENTROPY_SRC0_CLK` / `_SRC1_CLK` | `INTOSC1` / `INTOSC2` | Slow (window) clock per source |
| `WOLFSSL_C2000_ENTROPY_REF_CLK` | `DCC_COUNT1SRC_PLL` | Fast clock being counted; `SYSCLK` works at coarser quantization |
| `WOLFSSL_C2000_ENTROPY_NO_CLK_INIT` | off | Application manages the DCC peripheral clocks itself |
| `WOLFSSL_C2000_ENTROPY_WINDOW` | 256 | Slow-clock cycles per noise bit |
| `WOLFSSL_C2000_ENTROPY_HMIN` | 50 | Assumed min-entropy per raw bit, in 1/100 bits |
| `WOLFSSL_C2000_ENTROPY_MARGIN` | 2 | Oversample factor on top of `HMIN` |
| `WOLFSSL_C2000_ENTROPY_RCT_CUTOFF` | 9 | SP800-90B 4.4.1 cutoff |
| `WOLFSSL_C2000_ENTROPY_APT_WINDOW` / `_APT_CUTOFF` | 512 / 71 | SP800-90B 4.4.2 window and cutoff |
| `WOLFSSL_C2000_ENTROPY_STARTUP_OCTETS` | 1024 | SP800-90B 4.3 startup test size per source |
| `WOLFSSL_C2000_ENTROPY_NO_LOCK` | off | Assert an external lock instead of requiring `SINGLE_THREADED` |

The hardware-selection group is what to reach for if the board already uses a DCC for clock monitoring, or the part is not an F28P55x. If you change `HMIN`, recompute both health-test cutoffs for the new assumed entropy per octet -- a cutoff that does not match either never trips or trips constantly. A build-time check rejects a startup size smaller than one APT window.

### The generic `wc_NoiseSrc_*` layer

None of the SP800-90B machinery is C2000-specific, so it lives in
`wolfcrypt/src/random.c` behind `WOLFSSL_NOISE_SRC` (declarations in
`wolfssl/wolfcrypt/random.h`) and this port configures it. A port that has a
raw noise source but no TRNG supplies one callback:

```c
int my_sample(void* ctx, int srcIdx, byte* octet);
```

fills a `wc_NoiseSrc` with the callback, a domain-separation tag, a
caller-owned work buffer, the entropy budget (`hmin`, `margin`) and the
health-test cutoffs, and gets back:

| Call | Does |
|---|---|
| `wc_NoiseSrc_Init` | Validates the config, derives the gather size, runs the SP800-90B 4.3 startup test |
| `wc_NoiseSrc_GenerateSeed` | Gathers, health-tests, SHA-256 conditions, wipes the output on any failure |
| `wc_NoiseSrc_GetRaw` | Unconditioned noise for characterization only |
| `wc_NoiseSrc_SelfTest` | Liveness: gathers must differ and must not be a constant octet |
| `wc_NoiseSrc_Free` | Zeroes state and clears the latched failure |

`WC_NOISE_RAW_PER_SRC(hmin, margin)` sizes the work buffer from the entropy
budget so the port does not duplicate the formula. Source 0 is the credited
one; any further source is hashed in as defence in depth and is not budgeted.
The layer takes no locks -- the instance is caller-owned state, so a port that
shares one across threads provides its own mutual exclusion.
`WOLFSSL_C2000_ENTROPY` turns `WOLFSSL_NOISE_SRC` on implicitly.

### Health tests

SP800-90B 4.4.1 Repetition Count and 4.4.2 Adaptive Proportion run
continuously over every octet drawn from each source, with a startup test over
a full gather before anything is released. Cutoffs are derived for 4 bits of
min-entropy per octet at alpha = 2^-30 and are overridable. A failure returns
`ENTROPY_RT_E` / `ENTROPY_APT_E` and **no seed material is produced** -- the
source fails closed rather than degrading silently, and the failure is latched
until `wc_NoiseSrc_Free()`, because a source that trips and then passes is
exactly what continuous testing exists to catch.

Latching applies to the **credited** source only. Source 0 carries the entire
entropy budget, so its failure denies output. Sources 1 and up are unaccounted
extra hash input, and the cutoffs are derived for source 0's assumed
min-entropy rather than theirs, so one of them tripping is not evidence the
seed is weak: it is dropped for the life of the instance and stops
contributing. Output stays fully seeded because the budget never counted it,
and a source the budget ignores cannot deny service. On this part that means a
failing INTOSC2 degrades the source to INTOSC1 alone -- exactly the
`WOLFSSL_C2000_ENTROPY_NUM_SRC 1` configuration -- instead of killing the RNG.

Because those paths only fire on genuinely broken hardware, `noisesrc_test()`
in `wolfcrypt/test/test.c` drives them with synthetic sources -- stuck, biased,
sampler-error, and periodic -- on the host:

```sh
./configure --enable-all CFLAGS="-DWOLFSSL_NOISE_SRC" && make check
```

Note `wolfentropy.c`'s `HAVE_ENTROPY_MEMUSE` is *not* a usable substitute
here: its noise is memory-access timing jitter, which presumes a cache, and
the C28x is in-order and cacheless with deterministic RAM timing. Its default
state array is also ~256 KW on this target against ~100 KW of RAM. Its health
tests are `static` and hardcoded to 1 bit of min-entropy per sample, so they
are not reusable at this source's cutoffs either.

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
