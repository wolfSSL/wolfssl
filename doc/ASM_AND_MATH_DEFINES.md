# Assembly and Math Build Options

This guide is for developers building wolfSSL for a specific processor and
choosing how fast, how small, or how portable that build should be. It covers
the `#define`s that select the big-number math back end, the single-precision
(SP) implementations, and the assembly used by individual algorithms.

It is written for builds that configure wolfSSL through a hand-written
`user_settings.h` and `WOLFSSL_USER_SETTINGS`, which is the usual arrangement
for embedded targets, IDE projects and custom build systems. If you build with
`./configure`, you do not normally need to set any of these by hand — autotools
derives them from `--enable-*` options and writes them into
`wolfssl/options.h`. The tables below list the equivalent option in each case,
so you can reproduce an autotools build by hand or check what your current one
selected.

To get started quickly, copy `examples/configs/user_settings_embedded.h` into
your project. It implements everything described here through a short block of
on/off switches, so in most cases you can select your CPU and the level of
acceleration you want without setting individual defines at all.

For the options that select which *algorithms* are compiled and how each one
behaves, see the companion guide `doc/ALGORITHM_DEFINES.md`.

## Contents

1. [The three independent axes](#1-the-three-independent-axes)
2. [Per-CPU quick reference](#2-per-cpu-quick-reference)
3. [Math back end](#3-math-back-end)
4. [`sp_int.c` — generic multi-precision math](#4-sp_intc--generic-multi-precision-math)
5. [SP — specialised RSA/DH/ECC](#5-sp--specialised-rsadhecc)
6. [Per-algorithm assembly](#6-per-algorithm-assembly)
7. [Hardware acceleration and offload](#7-hardware-acceleration-and-offload)
8. [FIPS builds](#8-fips-builds)
9. [Linux kernel modules](#9-linux-kernel-modules)
10. [Toolchains](#10-toolchains)
11. [Recommended configurations](#11-recommended-configurations)
12. [Verifying and measuring the result](#12-verifying-and-measuring-the-result)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. The three independent axes

Three separate things are commonly all called "assembly". You select them
independently, and enabling some but not others is perfectly normal.

| Axis | What it accelerates | Selected by | Code |
| --- | --- | --- | --- |
| **A. Math back end** | Which multi-precision integer implementation is compiled at all | `WOLFSSL_SP_MATH_ALL`, `WOLFSSL_SP_MATH`, `USE_FAST_MATH`, `USE_INTEGER_HEAP_MATH` | `sp_int.c`, `tfm.c`, `integer.c` |
| **B. SP big-number acceleration** | RSA, DH, ECC, and generic `mp_*` operations | `WOLFSSL_SP_<arch>` (inline) and `WOLFSSL_SP_<arch>_ASM` (specialised) | `sp_int.c`, `sp_<arch>.c` (plus `sp_x86_64_asm.S` on x86_64 — see § 5) |
| **C. Per-algorithm assembly** | AES, SHA-2, SHA-3, ChaCha20, Poly1305, X25519, ML-KEM, ML-DSA, SM3/SM4 | `WOLFSSL_AESNI`, `USE_INTEL_SPEEDUP`, `WOLFSSL_ARMASM`, `WOLFSSL_RISCV_ASM`, `WOLFSSL_PPC32_ASM`, `WOLFSSL_PPC64_ASM` | `*_asm.S`, `port/<arch>/*` |

Axis B has two tiers. The distinction matters when you are choosing what to
enable, so it is worth reading before you pick your defines:

* **`WOLFSSL_SP_<arch>`** (no `_ASM` suffix) — *inline* assembly macros inside
  `sp_int.c` for the word-level primitives (multiply-accumulate, divide).
  Speeds up **all** multi-precision work, including key sizes and curves that
  have no specialised implementation. Available for many CPUs. Sets the
  internal `SP_INT_ASM_AVAILABLE`.
* **`WOLFSSL_SP_<arch>_ASM`** — the *specialised* fixed-size implementations in
  `sp_<arch>.c`. Only x86_64 adds a separate `sp_x86_64_asm.S`; the ARM files
  carry their assembly inline (§ 5). Much faster, but
  only for the specific key sizes and curves compiled in (RSA/DH 2048/3072/4096,
  P-256/P-384/P-521, SM2, SAKKE). Only available for x86_64, Aarch64, ARM32,
  ARM Thumb and Cortex-M.

Defining any `WOLFSSL_SP_<arch>_ASM` implies `WOLFSSL_SP_ASM`. You will normally
want both tiers together, which is what the per-CPU table in the next section
recommends: the specialised code handles the common key sizes and curves, and
the inline code covers everything else.

Both tiers are independent switches in your own build: turning off the
specialised `WOLFSSL_SP_<arch>_ASM` does not turn off the inline
`WOLFSSL_SP_<arch>`, and on RISC-V, PowerPC, MIPS and s390x the inline tier is
the only SP assembly there is. To turn **all** assembly off, define `WOLFSSL_NO_ASM` (and `TFM_NO_ASM` if you
use the legacy `tfm.c` back end). `SP_INT_NO_ASM` disables only the axis B
inline assembly and leaves axis C alone, which is useful when narrowing down a
problem.

---

## 2. Per-CPU quick reference

Find your processor and use the column that matches what you need. "With
assembly" is the fastest supported combination for that CPU; "without
assembly" is the portable C build, which is the right starting point when
bringing up a new target. Both assume the recommended `WOLFSSL_SP_MATH_ALL`
back end.

| CPU | Without assembly | With assembly |
| --- | --- | --- |
| x86_64 / amd64 | `WOLFSSL_SP_MATH_ALL`, `WOLFSSL_X86_64_BUILD` | add `WOLFSSL_SP_X86_64`, `WOLFSSL_SP_X86_64_ASM`, `WOLFSSL_AESNI`, `USE_INTEL_SPEEDUP` |
| x86 (32-bit) | `WOLFSSL_SP_MATH_ALL`, `WOLFSSL_X86_BUILD` | add `WOLFSSL_SP_X86`, `WOLFSSL_AESNI` (no specialised SP asm) |
| Aarch64 / ARMv8-A | `WOLFSSL_SP_MATH_ALL`, `WOLFSSL_AARCH64_BUILD` | add `WOLFSSL_SP_ARM64`, `WOLFSSL_SP_ARM64_ASM`, `WOLFSSL_ARMASM` |
| ARM32 (Cortex-A, Cortex-R, ARM11 and earlier) | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_ARM32`, `WOLFSSL_SP_ARM32_ASM`, `WOLFSSL_ARMASM`, `WOLFSSL_ARM_ARCH=<n>` |
| ARM Thumb (Cortex-M0/M0+/M1) | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_ARM_THUMB`, `WOLFSSL_SP_ARM_THUMB_ASM` |
| Cortex-M3/M4/M7/M33 (Thumb-2) | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_ARM_CORTEX_M`, `WOLFSSL_SP_ARM_CORTEX_M_ASM`, `WOLFSSL_ARMASM`, `WOLFSSL_ARMASM_THUMB2`, `WOLFSSL_ARM_ARCH=7` |
| RISC-V 64 | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_RISCV64`, `WOLFSSL_RISCV_ASM` (+ extension defines) |
| RISC-V 32 | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_RISCV32` (inline SP only) |
| PowerPC 64 | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_PPC64`, `WOLFSSL_PPC64_ASM` |
| PowerPC 32 | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_PPC`, `WOLFSSL_PPC32_ASM` |
| MIPS64 / MIPS | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_MIPS64` / `WOLFSSL_SP_MIPS` (inline SP only) |
| s390x | `WOLFSSL_SP_MATH_ALL` | add `WOLFSSL_SP_S390X` (inline SP only) |
| Anything else | `WOLFSSL_SP_MATH_ALL` | — |

Notes:

* **Specialised SP assembly (`WOLFSSL_SP_<arch>_ASM`) exists only for x86_64,
  Aarch64, ARM32, ARM Thumb and Cortex-M.** For every other CPU the assembly
  available on axis B is the inline tier (`WOLFSSL_SP_<arch>`) only.
  `./configure --enable-sp-asm` errors out on unsupported CPUs.
* On x86_64, `WOLFSSL_SP_X86_64_ASM` is not supported for Windows hosts built
  with MinGW/Cygwin. Use the C SP implementation there. MSVC builds use the
  `.asm` files from the Visual Studio project instead.
* `WOLFSSL_SP_X86_64` (or `_ASM`) also auto-defines `HAVE_INTEL_AVX1`, and
  `HAVE_INTEL_AVX2` unless `NO_AVX2_SUPPORT` is defined, when 64-bit words are
  available.
* Every assembly file has a matching `.asm` (MASM/Intel syntax) alongside the
  `.S` (GNU as/AT&T syntax). Autotools and CMake build the `.S`; Visual Studio
  builds the `.asm`.
* ARM covers a wide range of profiles and architecture versions, and the right
  defines differ noticeably between them. Section 6 has a per-architecture
  table; use it rather than the summary above if your target is anything other
  than a mainstream Cortex-A or Cortex-M.

---

## 3. Math back end

Exactly one back end provides `mp_int` and the `mp_*` API. Unless you have a
specific reason to do otherwise, choose `WOLFSSL_SP_MATH_ALL`.

| Define | Implementation | `./configure` | Use when |
| --- | --- | --- | --- |
| `WOLFSSL_SP_MATH_ALL` | `sp_int.c` — all key sizes and curves | default | **Recommended for everything.** Replaces `tfm.c` and `integer.c`. |
| `WOLFSSL_SP_MATH` | `sp_int.c` — *only* the sizes SP was built for | `--enable-sp-math` | Smallest footprint. Any key size or curve not compiled in fails at run time. |
| `USE_FAST_MATH` | `tfm.c` — fixed-size stack-based | `--enable-fastmath` | Legacy. Kept for compatibility. |
| `USE_INTEGER_HEAP_MATH` | `integer.c` — heap-based | `--enable-heapmath` | Legacy, **not timing resistant**. Avoid. |

`WOLFSSL_SP_MATH_ALL` and `WOLFSSL_SP_MATH` both compile `sp_int.c`;
`WOLFSSL_SP_MATH` additionally restricts operations to what the specialised SP
code supports. `WOLFSSL_SP_MATH` requires the matching `WOLFSSL_HAVE_SP_*`
defines for whichever of RSA/DH/ECC are enabled — otherwise there is no
implementation to fall back to.

Related:

* `SP_WORD_SIZE` — force `32` or `64`. Normally derived automatically from the
  CPU define (see `sp_int.h`); set it explicitly only when the default is wrong
  for the target.
* `WOLFSSL_SP_DIV_32` — do not use 64-bit divides (implies
  `WOLFSSL_SP_DIV_WORD_HALF`). For CPUs without a hardware 64/32 divide.
* `NO_64BIT` — for a target with no 64-bit integer type. This drops
  `SP_WORD_SIZE` to 16, and the specialised RSA/DH/ECC implementations are not
  provided at that width, so the build will not link once a public key algorithm
  is enabled. It also requires a target whose `unsigned long` is 32-bit or
  smaller; on a 64-bit host the size-detection chain in `sp_int.h` reports
  `#error "Size of unsigned long not detected"`. Contact support if you need
  public key support on such a target.

### Migrating from `USE_FAST_MATH`

Fastmath (`tfm.c`) was the default for many years and a great deal of existing
`user_settings.h` carries it. SP math is now the default and the actively
developed path, and moving over is usually a matter of translating a handful of
options. Nothing in your application code changes — the `mp_*` API is the same.

| Fastmath option | SP equivalent |
| --- | --- |
| `USE_FAST_MATH` | `WOLFSSL_SP_MATH_ALL` |
| `FP_MAX_BITS` | The size defines in section 5 — `WOLFSSL_SP_NO_2048`, `WOLFSSL_SP_NO_3072`, `WOLFSSL_SP_4096` — or `SP_INT_BITS` to bound `sp_int` directly. **Watch the units**: `FP_MAX_BITS` is twice the key size, so `FP_MAX_BITS 6144` means RSA-3072, whereas the SP defines name the key size itself |
| `TFM_TIMING_RESISTANT` | Nothing to carry over. It only affects `tfm.c` and `wolfmath.c`. Hardening inside SP is on unless you define `WC_NO_HARDEN`. `ECC_TIMING_RESISTANT` and `WC_RSA_BLINDING` are independent of the back end — and are **not** set for you in a hand-written `user_settings.h`, so carry them across explicitly; see `doc/ALGORITHM_DEFINES.md` § 6 |
| `TFM_ECC256`, `TFM_ECC384`, `TFM_ECC521` | `WOLFSSL_SP_NO_256` to drop P-256, `WOLFSSL_SP_384` and `WOLFSSL_SP_521` to add the others |
| `TFM_SMALL_SET` | `WOLFSSL_SP_SMALL` |
| `TFM_HUGE_SET` | `WOLFSSL_SP_LARGE_CODE` |
| `TFM_NO_ASM` | `WOLFSSL_NO_ASM` for all assembly, or `SP_INT_NO_ASM` for just the inline tier |
| `TFM_X86_64`, `TFM_ARM`, `TFM_AARCH_64`, `TFM_PPC32`, `TFM_PPC64`, `TFM_SSE2` | The CPU defines in sections 2 and 4. Fastmath selected its assembly per architecture in the same way, but the names and the code are entirely separate |

`ALT_ECC_SIZE` carries over unchanged and is still worth setting — despite the
comment in `ecc.h` describing it in fastmath terms, it shrinks the SP
structures too.

Two things to check after the move:

* **Key sizes.** Fastmath sized one array for everything; SP compiles a
  specialised implementation per size. Make sure every size your product
  actually uses is enabled, or use `WOLFSSL_SP_MATH_ALL` so anything not
  specialised still works through the generic code.
* **Memory profile.** The two back ends allocate differently, so re-measure
  stack and heap rather than assuming your old figures hold. Section 12 covers
  how.

Fastmath remains supported for existing products, so there is no urgency, but
new designs should start on SP math.

---

## 4. `sp_int.c` — generic multi-precision math

`sp_int.c` implements the whole `mp_*` API. The options below tune it for your
target. Most builds only need the CPU define from the first table; the rest are
there for when you are trading size against speed or working within a specific
memory budget.

### CPU selection (inline assembly tier)

Define the one that matches your processor. Each enables inline assembly for
the word-level primitives when `SP_WORD_SIZE` matches.

| Define | CPU | Word size |
| --- | --- | --- |
| `WOLFSSL_SP_X86_64` | x86_64 | 64 |
| `WOLFSSL_SP_X86` | x86 | 32 |
| `WOLFSSL_SP_ARM64` | Aarch64 | 64 |
| `WOLFSSL_SP_ARM32` | ARM32 | 32 |
| `WOLFSSL_SP_ARM_THUMB` | ARM Thumb (uses `r7` explicitly) | 32 |
| `WOLFSSL_SP_ARM_CORTEX_M` | Cortex-M | 32 |
| `WOLFSSL_SP_PPC64` / `WOLFSSL_SP_PPC` | PowerPC | 64 / 32 |
| `WOLFSSL_SP_MIPS64` / `WOLFSSL_SP_MIPS` | MIPS | 64 / 32 |
| `WOLFSSL_SP_RISCV64` / `WOLFSSL_SP_RISCV32` | RISC-V | 64 / 32 |
| `WOLFSSL_SP_S390X` | s390x | 64 |

`SP_INT_NO_ASM` disables this tier even when a CPU define is set. Use it to
rule the inline assembly in or out when investigating a problem, without
changing the rest of your configuration.

Two options apply to ARM targets specifically:

* `WOLFSSL_SP_ARM32_UDIV` — use the `UDIV` instruction for word division.
  Thumb-2 cores have `UDIV` from ARMv7-M onwards, but in ARM mode it belongs to
  the integer divide extension (ARMv7VE, or `-march=armv7-a+idiv`). Enabling it
  on a plain ARMv7-A build will not assemble, so leave it off unless you know
  your core has the instruction. The C fallback is used otherwise.
* `WOLFSSL_SP_NO_UMAAL` — the CPU has no `UMAAL`. Set automatically for
  Cortex-M3 (`WOLFSSL_ARM_ARCH_7M`) when `WOLFSSL_SP_ARM_CORTEX_M_ASM` is
  defined; set it by hand for other cores that lack the instruction.

### Size and speed

| Define | Effect |
| --- | --- |
| `WOLFSSL_SP_SMALL` | Smaller code, avoids large stack variables. Costs speed. |
| `WOLFSSL_SP_LOW_MEM` | Algorithms that use less memory. |
| `WOLFSSL_SP_INT_LARGE_COMBA` | Enable large Comba multiply/square. |
| `WOLFSSL_SP_FAST_MODEXP` | Faster `mod_exp` for a small amount of extra code. |
| `WOLFSSL_SP_FAST_NCT_EXPTMOD` | Faster **non-constant-time** modular exponentiation. Public-key operations only. |
| `WOLFSSL_SP_MILLER_RABIN_CNT` | Miller-Rabin rounds for primality testing (default 8). |

Note that `sp_int.c` undefines `WOLFSSL_SP_SMALL` for itself on clang 12 and
later, to avoid a known compiler issue. The undef is local to that translation
unit, so the `sp_<arch>.c` files still see the small variants — do not rely on
the setting being uniform across the math in that combination.

### Memory placement

| Define | Effect |
| --- | --- |
| `SP_INT_BITS` | Largest number, in bits, an `sp_int` has to hold. Every `sp_int` is sized from it, so it sets the memory floor for the math. Derived in `sp_int.h` from the algorithms enabled — 3072 for general RSA/DH, 521 for ECC-only — and worth setting by hand only when something outside that derivation needs more. |
| `WOLFSSL_SMALL_STACK` | Allocate large structures from the heap instead of the stack. |
| `WOLFSSL_SP_NO_MALLOC` | Never call `XMALLOC`/`XFREE` in SP — always use the stack. |
| `WOLFSSL_SP_SMALL_STACK` | Heap-allocate SP temporaries. Auto-set by `sp_<arch>.c` when `WOLFSSL_SMALL_STACK` is set and `WOLFSSL_SP_NO_MALLOC` is not. |
| `WOLFSSL_SP_NO_DYN_STACK` | Do not use C99 variable-length stack arrays. Set this for compilers or coding standards that forbid VLAs. |

`WOLFSSL_SMALL_STACK` and `WOLFSSL_SP_NO_MALLOC` pull in opposite directions,
so choose according to what your target has:

* Heap available, stack tight → `WOLFSSL_SMALL_STACK`.
* No heap at all → `WOLFSSL_SP_NO_MALLOC` (usually with `WOLFSSL_SP_SMALL` and
  restricted key sizes so the stack frames stay bounded), plus
  `WOLFSSL_NO_MALLOC` / `WOLFSSL_STATIC_MEMORY` for the rest of the library.

### Correctness and hardening

| Define | Effect |
| --- | --- |
| `WOLFSSL_SP_INT_NEGATIVE` | Allow negative values. Required by FIPS and by some certificate paths. |
| `WOLFSSL_SP_INT_DIGIT_ALIGN` | The platform cannot do unaligned `sp_int_digit` access. |
| `WOLFSSL_SP_INT_SQR_VOLATILE` | Declare squaring intermediates `volatile`. |
| `WC_PROTECT_ENCRYPTED_MEM` | Extra protection for operations on encrypted memory. |
| `WC_NO_CACHE_RESISTANT` | Disable cache-resistant (constant-address) table access. Faster, weaker. |
| `WC_NO_HARDEN` | Disable timing-attack resistance. Faster, weaker. |
| `WOLFSSL_NO_CT_OPS` | Disable constant-time operations. |
| `WOLFSSL_CHECK_MEM_ZERO` | Check that sensitive memory is zeroed on free (debug). |

wolfSSL recommends against defining `WC_NO_HARDEN`, `WC_NO_CACHE_RESISTANT` or
`WOLFSSL_NO_CT_OPS` in any product that handles long-term private keys, unless
your threat model genuinely excludes an attacker able to observe local timing or
cache behaviour. The performance gain is small relative to the protection lost.

### Non-blocking

`WOLFSSL_SP_NONBLOCK` makes long operations return `FP_WOULDBLOCK` and expect
repeated calls until they complete, so a single-threaded application can stay
responsive during a slow key operation. It cannot be combined with the
specialised SP assembly — `./configure` rejects `--enable-sp=nonblock` together
with `--enable-sp-asm` — so use it with the C implementation. Note that
`--enable-sp=nonblock` also implies small and no-malloc SP.
`examples/configs/user_settings_eccnonblock.h` is a worked example.

---

## 5. SP — specialised RSA/DH/ECC

These select the fixed-size implementations in `sp_c32.c` / `sp_c64.c` (C) and
`sp_<arch>.c` + `sp_<arch>_asm.S` (assembly). They are what make RSA, DH and
ECC fast, and `sp_int.c` handles anything they do not cover. If public key
performance matters to your product, this is the section that will affect it
most.

### Algorithms

| Define | Enables | `./configure` |
| --- | --- | --- |
| `WOLFSSL_HAVE_SP_RSA` | SP RSA | `--enable-sp` with RSA enabled |
| `WOLFSSL_HAVE_SP_DH` | SP DH | `--enable-sp` with DH enabled |
| `WOLFSSL_HAVE_SP_ECC` | SP ECC | `--enable-sp` with ECC enabled |

### Sizes

RSA/DH 2048 and 3072 and ECC P-256 are **on by default** once the corresponding
`WOLFSSL_HAVE_SP_*` is defined. Turn them off, or add the others, explicitly:

| Define | Effect |
| --- | --- |
| `WOLFSSL_SP_NO_2048` | Drop RSA/DH 2048 |
| `WOLFSSL_SP_NO_3072` | Drop RSA/DH 3072 |
| `WOLFSSL_SP_4096` | Add RSA/DH 4096 |
| `WOLFSSL_SP_NO_256` | Drop ECC P-256 |
| `WOLFSSL_SP_384` | Add ECC P-384 (pair with `HAVE_ECC384`) |
| `WOLFSSL_SP_521` | Add ECC P-521 (pair with `HAVE_ECC521`) |
| `WOLFSSL_SP_SM2` | Add SM2 (`sp_sm2_*.c`) |
| `WOLFSSL_SP_1024` | Add 1024-bit for SAKKE |

Each size costs code space, so on a constrained target enable only the sizes
your protocol actually negotiates. Note that with `WOLFSSL_SP_MATH` (rather
than `WOLFSSL_SP_MATH_ALL`), a size you have not compiled in is not merely
slower — it is unavailable, and the operation fails at run time.

`WOLFSSL_SP_LARGE_CODE` selects larger/faster variants; `./configure` sets it
automatically on x86_64 and Aarch64 when `WOLFSSL_SP_SMALL` is not requested.

`ALT_ECC_SIZE` dimensions `ecc_point` from the curve rather than from the
largest key the math was built for. If your build has both RSA and ECC enabled,
your ECC points are otherwise sized for RSA, and defining this is usually the
single largest memory saving available in the math. Measured on the embedded template's default profile
(`WOLFSSL_SP_MATH_ALL`, ECC-only, 32-bit SP words) built for x86_64, it takes
`ecc_point` from 436 to 256 bytes and `ecc_key` from 624 to 384; the saving
scales with how much larger the math is than the curve. It needs a heap: `ecc.h` rejects it with an `#error` when
`WOLFSSL_NO_MALLOC` is set.

Remember to build the digest each curve is used with. P-384 is signed with
SHA-384 and P-521 with SHA-512, and the wolfCrypt test suite reports
`BAD_LENGTH_E` if that digest is missing from your configuration. See
`doc/ALGORITHM_DEFINES.md` for the hash options.

### Assembly

| Define | CPU | Files |
| --- | --- | --- |
| `WOLFSSL_SP_X86_64_ASM` | x86_64 | `sp_x86_64.c`, `sp_x86_64_asm.S` |
| `WOLFSSL_SP_ARM64_ASM` | Aarch64 | `sp_arm64.c` |
| `WOLFSSL_SP_ARM32_ASM` | ARM32 | `sp_arm32.c` |
| `WOLFSSL_SP_ARM_THUMB_ASM` | ARM Thumb | `sp_armthumb.c` |
| `WOLFSSL_SP_ARM_CORTEX_M_ASM` | Cortex-M | `sp_cortexm.c` |

Any of these implies `WOLFSSL_SP_ASM`. Without one of them, `sp_c32.c` or
`sp_c64.c` is compiled instead, chosen by `SP_WORD_SIZE`.

Only x86_64 needs a separate assembly file. The ARM `sp_*.c` files carry their
assembly inline, so an ARM project adds a single `.c` file and no `.S` — useful
if your toolchain or coding standard makes separate assembly files awkward.

`RSA_LOW_MEM` implies `SP_RSA_PRIVATE_EXP_D` and `WOLFSSL_SP_SMALL`. It performs
RSA private key operations with the plain private exponent instead of the
Chinese Remainder Theorem, which uses considerably less memory but is several
times slower.

None of this applies to the post-quantum algorithms. ML-KEM
(`WOLFSSL_HAVE_MLKEM`) and ML-DSA (`WOLFSSL_HAVE_MLDSA`) use polynomial
arithmetic rather than big-number math, so no SP define affects them. They are
accelerated through the per-algorithm assembly in section 6 instead:
`wc_mlkem_asm.S` and `wc_mldsa_asm.S` under `USE_INTEL_SPEEDUP`, and
`armv8-mlkem-asm.S` and `armv8-32-mlkem-asm.S` under `WOLFSSL_ARMASM`.

---

## 6. Per-algorithm assembly

These are independent of the math axes above, and are enabled per CPU family.
They accelerate the symmetric algorithms, hashes and post-quantum algorithms
rather than the public key math.

### Intel (x86_64 and x86)

| Define | Effect | `./configure` |
| --- | --- | --- |
| `WOLFSSL_AESNI` | AES-NI for AES-CBC/ECB/CTR, key expansion, GCM, XTS | `--enable-aesni` |
| `USE_INTEL_SPEEDUP` | **All** Intel speedups: AES-NI plus AVX/AVX2 SHA-2, SHA-3, ChaCha20, Poly1305, X25519, ML-KEM, ML-DSA, FrodoKEM, SM3 | `--enable-intelasm` |
| `USE_INTEL_SPEEDUP_FOR_AES` | AVX acceleration for AES only | `--enable-aesni-with-avx` |
| `AES_GCM_AESNI_NO_UNROLL` | Smaller AES-GCM assembly | `--enable-aesni=small` |
| `HAVE_INTEL_AVX1` / `HAVE_INTEL_AVX2` | Select instruction set. Auto-defined by the x86_64 SP defines; `NO_AVX2_SUPPORT` suppresses AVX2. | — |
| `WOLFSSL_X86_64_BUILD` / `WOLFSSL_X86_BUILD` | 64-/32-bit x86 target. Must also reach the assembler. | — |

`USE_INTEL_SPEEDUP` implies `WOLFSSL_AESNI`. Instruction selection happens at
run time through `cpuid.c`, so a binary built with these defines still runs on
processors that lack the instructions. The exception is code compiled with
`-maes`, `-msse4` or `-mpclmul`, which the compiler may then use unconditionally;
autotools adds those flags for the intrinsics in AES key setup. For
kernel-module builds, `WC_C_DYNAMIC_FALLBACK` keeps a C path available.

### ARM

| Define | Effect |
| --- | --- |
| `WOLFSSL_ARMASM` | Master switch: AES, SHA-256, SHA-512, SHA-3, ChaCha20, Poly1305, Curve25519, ML-KEM, FrodoKEM assembly from `port/arm/` |
| `WOLFSSL_ARMASM_INLINE` | Use the `*_asm_c.c` inline-assembly variants instead of the `.S` files. Needed when the toolchain will not assemble `.S`, and used for FIPS on ARMv7. |
| `WOLFSSL_ARMASM_NO_HW_CRYPTO` | No ARMv8 Crypto Extensions (no AES/SHA instructions) |
| `WOLFSSL_ARMASM_NO_NEON` | No NEON |
| `WOLFSSL_ARMASM_THUMB2` | Thumb-2 encoding (Cortex-M, ARMv7-M) |
| `WOLFSSL_ARM_ARCH=<n>` | Architecture level: `4`, `6`, `7`… Gates instruction availability. |
| `WOLFSSL_AARCH64_BUILD` | Aarch64 target |
| `WOLFSSL_ARMASM_CRYPTO_SHA512` and `WOLFSSL_ARMASM_CRYPTO_SHA3` | Use the Aarch64 SHA-512 / SHA-3 instructions (ARMv8.2+). `./configure` sets the pair together from `--enable-armasm=sha512-crypto` or `sha3-crypto`. |
| `WOLFSSL_ARMASM_CRYPTO_SM3` / `_SM4` | Use the Aarch64 SM3 / SM4 instructions |
| `WOLFSSL_ARMASM_SHA256_SMALL` | Smaller 32-bit ARM SHA-256 |
| `WOLFSSL_ARMASM_AES_BLOCK_INLINE` | 32-bit ARM AES block-function inlining |
| `WOLFSSL_ARMASM_BARRIER_SB` / `_BARRIER_DETECT` | Use the `SB` speculation barrier (ARMv8.5+) / detect it at run time |
| `WOLFSSL_AARCH64_NO_SQRDMLSH` | Target lacks `SQRDMLSH` |

#### Which defines for which ARM architecture

ARM spans three profiles and many architecture versions, and the correct
selection differs between them. Find your core here.

**32-bit (AArch32)** — the SP tier column is the inline `sp_int.c` assembly,
and the SP asm column is the specialised implementation:

| Architecture | Typical cores | SP tier | SP asm | Per-algorithm assembly |
| --- | --- | --- | --- | --- |
| ARMv4, ARMv5 | ARM7TDMI, ARM9 | `WOLFSSL_SP_ARM32` | `WOLFSSL_SP_ARM32_ASM` | `WOLFSSL_ARMASM` with `WOLFSSL_ARM_ARCH 4`, `WOLFSSL_ARMASM_NO_NEON`, `WOLFSSL_ARMASM_NO_HW_CRYPTO` |
| ARMv6 | ARM11, Raspberry Pi 1/Zero | `WOLFSSL_SP_ARM32` | `WOLFSSL_SP_ARM32_ASM` | as above with `WOLFSSL_ARM_ARCH 6` |
| ARMv6-M | Cortex-M0, M0+, M1 | `WOLFSSL_SP_ARM_THUMB` | `WOLFSSL_SP_ARM_THUMB_ASM` | none available — see below |
| ARMv7-M, ARMv7E-M | Cortex-M3, M4, M7 | `WOLFSSL_SP_ARM_CORTEX_M` | `WOLFSSL_SP_ARM_CORTEX_M_ASM` | `WOLFSSL_ARMASM` with `WOLFSSL_ARMASM_THUMB2`, `WOLFSSL_ARM_ARCH 7`, `WOLFSSL_ARMASM_NO_NEON`, `WOLFSSL_ARMASM_NO_HW_CRYPTO` |
| ARMv8-M baseline | Cortex-M23 | `WOLFSSL_SP_ARM_THUMB` | `WOLFSSL_SP_ARM_THUMB_ASM` | none available — see below |
| ARMv8-M mainline | Cortex-M33, M35P, M55, M85 | `WOLFSSL_SP_ARM_CORTEX_M` | `WOLFSSL_SP_ARM_CORTEX_M_ASM` | as ARMv7-M |
| ARMv7-R, ARMv8-R | Cortex-R4 to R8, R52 | `WOLFSSL_SP_ARM32` | `WOLFSSL_SP_ARM32_ASM` | `WOLFSSL_ARMASM` with `WOLFSSL_ARM_ARCH 7`; NEON if the core has it |
| ARMv7-A | Cortex-A5 to A17 | `WOLFSSL_SP_ARM32` | `WOLFSSL_SP_ARM32_ASM` | `WOLFSSL_ARMASM` with `WOLFSSL_ARM_ARCH 7`; NEON usually present, no crypto extensions |
| ARMv8-A in 32-bit mode | Cortex-A32, or A53/A72 built for AArch32 | `WOLFSSL_SP_ARM32` | `WOLFSSL_SP_ARM32_ASM` | `WOLFSSL_ARMASM` with `WOLFSSL_ARM_ARCH 7`; crypto extensions available, so omit `WOLFSSL_ARMASM_NO_HW_CRYPTO` |

Points that catch people out:

* **Cortex-M0, M0+, M1 and Cortex-M23 are Thumb-1 (ARMv6-M / ARMv8-M
  baseline), not Thumb-2.** Use the `WOLFSSL_SP_ARM_THUMB` pair, and do **not**
  define `WOLFSSL_ARMASM_THUMB2`. wolfSSL ships no Thumb-1 per-algorithm
  assembly — `wolfcrypt/src/port/arm/` contains only `armv8-*` and `thumb2-*`
  files — so on these cores you get the SP acceleration but the C
  implementations of AES, SHA and the rest.
* **Cortex-M3 has no `UMAAL`.** `settings.h` detects this through
  `__ARM_ARCH_7M__` and defines `WOLFSSL_SP_NO_UMAAL` for you when
  `WOLFSSL_SP_ARM_CORTEX_M_ASM` is set. Define it by hand for any other core
  that lacks the instruction.
* **`UDIV` is not universal in ARM mode.** See `WOLFSSL_SP_ARM32_UDIV` in
  section 4 before enabling it.
* **Cortex-R is a real-time profile but assembles as ARMv7.** Use the ARM32
  defines with `WOLFSSL_ARM_ARCH 7`.

**64-bit (AArch64).** All of these use `WOLFSSL_SP_ARM64`,
`WOLFSSL_SP_ARM64_ASM`, `WOLFSSL_AARCH64_BUILD` and `WOLFSSL_ARMASM`. What
changes with the architecture version is the instruction groups you can add:

| Architecture | Typical cores | Add | Compiler flag |
| --- | --- | --- | --- |
| ARMv8-A | Cortex-A53, A57, A72, A73 | nothing beyond the base set | `-mcpu=generic+crypto` |
| ARMv8.2-A and later | Cortex-A55, A75, A76, A78, Neoverse N1 | `WOLFSSL_ARMASM_CRYPTO_SHA512` and `WOLFSSL_ARMASM_CRYPTO_SHA3`, which `./configure` sets as a pair | `-march=armv8.2-a+crypto+sha3` |
| ARMv8.2-A with the SM extensions | cores implementing FEAT_SM3 / FEAT_SM4 | `WOLFSSL_ARMASM_CRYPTO_SM3`, `WOLFSSL_ARMASM_CRYPTO_SM4` | `-march=armv8.2-a+crypto+sm4` — one `+sm4` covers both |
| ARMv8.5-A and later | Cortex-A710, Neoverse V2 | `WOLFSSL_ARMASM_BARRIER_SB`, or `WOLFSSL_ARMASM_BARRIER_DETECT` to test for it at run time | `-march=armv8.5-a`, which you supply yourself |
| SVE or SME capable | Neoverse V1/V2 and later, Apple M4 | `WOLFSSL_FRODOKEM_SVE`, `WOLFSSL_FRODOKEM_SME` for FrodoKEM matrix work; both are selected at run time | `-march=armv9-a+sve`, which you supply yourself |
| Apple silicon | M1 to M4 | SHA-512 and SHA-3 instructions are enabled by default on Darwin | — |

Further AArch64 options:

| Define | Effect |
| --- | --- |
| `WOLFSSL_AARCH64_NO_SQRDMLSH` | The target lacks `SQRDMLSH`. `./configure` sets this whenever it selects the plain `-mcpu=generic+crypto` baseline |
| `WOLFSSL_AARCH64_PRIVILEGE_MODE` | Detect CPU features at run time by reading the ID registers (`ID_AA64ISAR0_EL1`, `ID_AA64PFR0_EL1`, `ID_AA64PFR1_EL1`) with `mrs`. Reading them needs a privileged exception level, so `settings.h` auto-defines it only for kernel-module builds — inside `#ifdef WOLFSSL_LINUXKM` — on Aarch64. See the note below |
| `WOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP` | Avoid NEON table lookups in AES, which removes a data-dependent memory access pattern |
| `WOLFSSL_ARMASM_AES_BLOCK_INLINE` | 32-bit ARM only: inline the AES block function |
| `WOLFSSL_ARMASM_SHA256_SMALL` | 32-bit ARM only: smaller SHA-256 |

Without `WOLFSSL_AARCH64_PRIVILEGE_MODE` there is no run-time detection on
Aarch64 at all: `cpuid.c` sets its feature flags from what the build was
compiled for, taking `WOLFSSL_ARMASM_NO_NEON`, `WOLFSSL_ARMASM_NO_HW_CRYPTO`,
`WOLFSSL_ARMASM_CRYPTO_SHA512` and the rest at face value. That is the right
behaviour for a fixed target, but it does mean your `-march` and
`WOLFSSL_ARMASM_*` settings must actually match the hardware — nothing checks.
Set the define by hand only where your code runs privileged enough to read the
ID registers, such as a bare-metal build at EL1 or above.

You must also tell the compiler about the instructions, with flags such as
`-march=armv8.2-a+crypto+sha3`, `-mcpu=generic+crypto`, `-mfpu=neon` and
`-mstrict-align` as appropriate for your core. `./configure` adds these for you;
in a hand-written build you need to supply them yourself.

### RISC-V (64-bit)

`WOLFSSL_RISCV_ASM` enables AES, SHA-256, SHA-512, SHA-3, ChaCha20 and Poly1305
assembly from `port/riscv64/`. Then add the defines for whichever extensions
your hardware implements:

| Define | Extension |
| --- | --- |
| `WOLFSSL_RISCV_BASE_BIT_MANIPULATION` | Zbb (`REV8`) |
| `WOLFSSL_RISCV_BASE_ADDRESS` | Zba (`SH2ADD`) |
| `WOLFSSL_RISCV_CARRYLESS` | Zbc/Zbkc (`CLMUL`, `CLMULH`) — reported only, see below |
| `WOLFSSL_RISCV_BIT_MANIPULATION` | Zbkb (`PACK`, `REV8`). `./configure` also sets the Zbb define alongside it; nothing in the library derives one from the other, so in a hand-written build set `WOLFSSL_RISCV_BASE_BIT_MANIPULATION` yourself as well |
| `WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY` | Zbt (`FSL`, `FSR`, `CMOV`, `CMIX`) |
| `WOLFSSL_RISCV_SCALAR_CRYPTO_ASM` | Zkned — scalar AES and SHA-2 |
| `WOLFSSL_RISCV_VECTOR` | V — vector extension |
| `WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION` | Zvbb/Zvkb (`VBREV8`) |
| `WOLFSSL_RISCV_VECTOR_CARRYLESS` | Zvbc (`VCLMUL`, `VCLMULH`) |
| `WOLFSSL_RISCV_VECTOR_GCM` | Zvkg (`VGMUL`, `VGHSH`) — reported only, see below |
| `WOLFSSL_RISCV_VECTOR_CRYPTO_ASM` | Zvkned — vector AES and SHA-2 |

`WOLFSSL_RISCV_ASM_INLINE` selects the `*_asm_c.c` inline variants in place of
the `.S` files, as on ARM. `WOLFSSL_RISCV_ASM_NO_UNALIGNED` builds the paths
that avoid unaligned loads and stores, for a core that does not permit them.

Three of the defines above are **reported but not selective**:
`WOLFSSL_RISCV_CARRYLESS`, `WOLFSSL_RISCV_VECTOR_CARRYLESS` and
`WOLFSSL_RISCV_VECTOR_GCM` appear only in the build capability string that
`wolfmath.c` assembles — no port file consults them. The `CLMUL` and
`VGMUL`/`VGHSH` instructions they name are emitted unconditionally by the
assembly that `WOLFSSL_RISCV_VECTOR_CRYPTO_ASM` brings in, so it is that
define, not these, which decides whether your hardware needs the extension.
The rest of the table does gate real code.

Take care to enable only the extensions your hardware actually has. Unlike the
Intel options, there is no run-time check: an extension that is not present
produces an illegal-instruction trap at run time rather than a build error.
RISC-V has no specialised SP assembly, so use `WOLFSSL_SP_RISCV64` for the
inline tier.

### PowerPC

32-bit (`port/ppc32/`, AES + SHA-256 + SHA-512 + SHA-3):

| Define | Effect |
| --- | --- |
| `WOLFSSL_PPC32_ASM` | Master switch |
| `WOLFSSL_PPC32_ASM_INLINE` | Use `*_asm_c.c` inline variants |
| `WOLFSSL_PPC32_ASM_INLINE_REG` | Selects the register-naming inline variant. In a hand-written build this define alone has no effect: compile `ppc32-*-asm_cr.c` in place of `ppc32-*-asm_c.c` and assemble with `-Wa,-mregnames`. |
| `WOLFSSL_PPC32_ASM_SMALL` | Smaller code |
| `WOLFSSL_PPC32_ASM_SPE` | Signal Processing Engine |

64-bit (`port/ppc64/`, same algorithms):

| Define | Effect |
| --- | --- |
| `WOLFSSL_PPC64_ASM` | Master switch |
| `WOLFSSL_PPC64_ASM_INLINE` | Use `*_asm_c.c` inline variants |
| `WOLFSSL_PPC64_ASM_SMALL` | Smaller code |
| `WOLFSSL_PPC64_ASM_CRYPTO` | POWER8 `vshasigmaw` SHA-256, selected at run time |
| `WOLFSSL_PPC64_ASM_POWER8` | POWER8 VSX `vrld` SHA-3, selected at run time |

The POWER8 variants mark their own sections, so you do not need a global
`-mcpu=power8` and the rest of the library stays portable across PowerPC
models.

---

## 7. Hardware acceleration and offload

Before working through the assembly options above, check whether your target
has a hardware crypto engine. On many microcontrollers and SoCs an on-chip AES
or SHA block, or a secure element, will outperform any software implementation
and free the CPU entirely — and on a part with a secure element it may also be
the only way to keep a key out of main memory.

There are three routes, and they compose with everything in this guide:

| Route | Define | What it covers |
| --- | --- | --- |
| Crypto callbacks | `WOLF_CRYPTO_CB` | A generic hook. You register a device with `wc_CryptoCb_RegisterDevice()` and handle the operations you want; anything you decline falls back to the software path built from the options above. Covers ciphers, hashes, HMAC, CMAC, KDF and public key operations |
| PKCS#11 | `HAVE_PKCS11` | Offload to a PKCS#11 token or HSM. `HAVE_PKCS11_STATIC` links the module statically instead of loading it at run time |
| Vendor ports | per-port defines | Direct support for a specific device, under `wolfcrypt/src/port/` |

The vendor ports cover, among others, Espressif, STM32, Renesas, NXP, Microchip
(ATECC), Silicon Labs, Xilinx, Infineon, Nordic, TI, Cypress/Infineon PSoC,
Raspberry Pi Pico, ARM PSA, Linux kernel crypto (KCAPI), `/dev/crypto`, and
AF_ALG. Each has its own defines and, usually, its own README under that
directory; see `wolfcrypt/src/port/` for the current list.

Two points worth knowing:

* **Offload and software assembly are not exclusive.** A device that
  accelerates AES but not ECC is common; enable the offload for AES and the SP
  assembly from this guide for the ECC.
* **Hardware is not automatically faster.** For small messages the driver call
  overhead can exceed the cost of a software implementation, particularly one
  using the CPU's own crypto instructions. Measure both on your hardware before
  committing — see section 12.

---

## 8. FIPS builds

If you build against a FIPS-validated wolfCrypt module, the options in this
guide are constrained. The validated module was certified with a particular
implementation of the math, and you cannot substitute another without
invalidating the certificate.

What `./configure` fixes for you in a FIPS build:

* `WOLFSSL_SP_INT_NEGATIVE` is defined — the FIPS code paths require negative
  value support in the math.
* On 32-bit ARM, `WOLFSSL_ARMASM_INLINE` is forced for **any** FIPS build, so
  the inline assembly-in-C variants are used rather than the `.S` files. This
  applies to the ARMv7-A and ARMv7-M host cases, and the reason given in
  `configure.ac` is a known issue with the assembly code.
* The math back end is selected for you; do not override it.

Start from `--enable-fips=<version>`, or from `user_settings_fipsv2.h` or
`user_settings_fipsv5.h` in `examples/configs/`, and change only what those
leave open. If you need assembly acceleration in a FIPS build, or are unsure
whether a given option is inside the boundary, contact **fips@wolfssl.com**
before you finalise the configuration.

---

## 9. Linux kernel modules

Building wolfSSL as a Linux kernel module (`linuxkm/`) adds one requirement to
everything above: SIMD and vector registers cannot be used freely in kernel
context, they must be saved and restored around the code that uses them.

`linuxkm/linuxkm_wc_port.h` detects this for you. When the configuration
enables x86 SIMD, or any of `WOLFSSL_ARMASM`, `WOLFSSL_SP_ARM32_ASM`,
`WOLFSSL_SP_ARM64_ASM`, `WOLFSSL_SP_ARM_THUMB_ASM` or
`WOLFSSL_SP_ARM_CORTEX_M_ASM`, it defines `WOLFSSL_LINUXKM_SIMD` and
`WOLFSSL_USE_SAVE_VECTOR_REGISTERS`, and raises an `#error` if the kernel
configuration does not actually support the architecture you asked for.

`WC_C_DYNAMIC_FALLBACK` is the companion option: it keeps a C implementation
available alongside the accelerated one, so an operation can still complete
when the vector registers are unavailable. `./configure` sets it automatically
for kernel-mode builds that enable AES-NI.

---

## 10. Toolchains

The assembly in wolfCrypt comes in two forms — separate `.S` files, and inline
assembly inside C — and toolchains differ in what they accept. This matters
most on embedded ARM, where MDK-ARM and IAR are as common as GCC.

| Toolchain | What to do |
| --- | --- |
| GCC, Clang | Nothing special. Both forms work as shipped |
| Arm Compiler / Keil MDK | Define `WOLFSSL_KEIL`. The inline assembly in `sp_int.c` has a Keil-specific form, and `__KEIL__` selects the right `__asm`/`volatile` spelling |
| IAR EWARM | No define needed for the spelling — `__IAR_SYSTEMS_ICC__` is detected and the `asm`/`volatile` keywords adjusted. If the toolchain will not assemble the `.S` files, use `WOLFSSL_ARMASM_INLINE` and compile the `*_asm_c.c` variants instead |
| Visual Studio (MSVC) | Compiles the `.asm` files rather than the `.S`; the supplied project files already reference them. Some inline paths need MSVC 2019 or later (`_MSC_VER >= 1920`) for the 64-bit division intrinsic, and fall back to the half-word implementation otherwise |

A general rule for any toolchain that cannot assemble `.S` files: ARM, RISC-V
and PowerPC all ship inline assembly-in-C alternatives, selected with
`WOLFSSL_ARMASM_INLINE`, `WOLFSSL_RISCV_ASM_INLINE`,
`WOLFSSL_PPC32_ASM_INLINE` or `WOLFSSL_PPC64_ASM_INLINE`, and the project then
compiles the matching `*_asm_c.c` file in place of the `.S`. Only x86_64 SP has
no inline alternative.

Whichever toolchain you use, the defines must reach the assembler as well as
the compiler when building `.S` files. See the first row of section 13.

Sample projects for several of these live under `IDE/` — `IDE/MDK-ARM`,
`IDE/MDK5-ARM`, `IDE/IAR-EWARM`, `IDE/GCC-ARM` and others.

---

## 11. Recommended configurations

Four starting points, covering the usual trade-offs. Copy the one closest to
your situation and adjust from the tables above.

### Fastest on a 64-bit server or desktop

```c
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_X86_64_BUILD
#define WOLFSSL_SP_X86_64
#define WOLFSSL_SP_X86_64_ASM
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_384
#define HAVE_ECC384
#define WOLFSSL_AESNI
#define USE_INTEL_SPEEDUP
```

Aarch64 equivalent: `WOLFSSL_AARCH64_BUILD`, `WOLFSSL_SP_ARM64`,
`WOLFSSL_SP_ARM64_ASM`, `WOLFSSL_ARMASM`.

### Smallest with a heap (Cortex-M4/M7, RAM available)

```c
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_THUMB2
#define WOLFSSL_ARMASM_NO_HW_CRYPTO
#define WOLFSSL_ARMASM_NO_NEON
#define WOLFSSL_ARM_ARCH 7
```

### Smallest with no heap at all

```c
#define WOLFSSL_SP_MATH          /* only the compiled sizes/curves */
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NO_MALLOC
#define WOLFSSL_SP_NO_DYN_STACK  /* no C99 VLAs */
#define WOLFSSL_NO_MALLOC
#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_2048       /* ECC only — drop the FF sizes */
#define WOLFSSL_SP_NO_3072
```

With `WOLFSSL_SP_NO_MALLOC`, every SP temporary lives on the stack. Keep the
enabled key sizes small and measure your worst-case stack usage before
shipping.

### Portable C, no assembly anywhere

```c
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_NO_ASM
#define TFM_NO_ASM
```

Use this as your reference build when bringing up a new target, then enable the
CPU defines one axis at a time.

### Bringing up a new CPU

Enabling everything at once makes a failure hard to attribute, so wolfSSL
recommends working up in stages:

1. Build with `WOLFSSL_NO_ASM` and confirm `./wolfcrypt/test/testwolfcrypt`
   passes. This establishes that the port itself is sound.
2. Add the inline SP define (`WOLFSSL_SP_<arch>`) and re-test. If something
   fails, `SP_INT_NO_ASM` will confirm whether the inline assembly is the cause.
3. Add the specialised SP assembly (`WOLFSSL_SP_<arch>_ASM`) if your CPU has it,
   and re-test.
4. Add the per-algorithm assembly (`WOLFSSL_ARMASM`, `WOLFSSL_RISCV_ASM` and so
   on) last, enabling one extension at a time on RISC-V.

Benchmark each step with `./wolfcrypt/benchmark/benchmark` so you can see what
each one is worth on your hardware. If you get stuck at any stage, contact
**support@wolfssl.com** with the defines you used and the output you saw.

---

## 12. Verifying and measuring the result

**Check what you actually built.** Configuration is layered — your defines,
what `settings.h` derives from them, and what the platform contributes — so the
set that reaches the compiler is rarely exactly the set you wrote. Ask the
preprocessor:

```
gcc -DWOLFSSL_USER_SETTINGS -I. -Ipath/to/wolfssl -dM -E - \
    < /dev/null -include wolfssl/wolfcrypt/settings.h | sort | grep -E \
    'WOLFSSL_SP|SP_WORD_SIZE|WOLFSSL_ARMASM|WOLFSSL_AESNI|USE_INTEL'
```

That prints the defines as the compiler sees them, including everything
`settings.h` implied, and is the quickest way to confirm that an option you set
took effect — or to find one you did not expect. Use your cross compiler for a
cross build, since much of the derivation depends on the target.

For an autotools build, `wolfssl/options.h` records the same information.
Note that the `HAVE_WC_INTROSPECTION` API — `wolfSSL_configure_args()` and
`wolfSSL_global_cflags()` — reports the `./configure` invocation, so it tells
you nothing useful about a hand-written `user_settings.h` build.

Then two numbers matter, and both are worth checking on your own hardware
rather than assumed from the tables in this guide.

**Speed.** `./wolfcrypt/benchmark/benchmark` reports throughput for every
algorithm compiled in. Run it before and after each change so you can see what
an option is actually worth on your part — the benefit of assembly varies
enormously between cores, and an option that doubles throughput on one target
can be worth almost nothing on another. On an embedded target, define
`BENCH_EMBEDDED` so the benchmark uses small buffers and short runs.

**Size.** Build the static library and use your toolchain's `size` on it, or
on the objects you care about:

```
size -t src/.libs/libwolfssl.a | tail -1
```

Comparing that figure across configurations tells you what each option costs.
Note that the linker discards what your application does not reference, so the
library figure is an upper bound — link your own application to see the number
that will ship. wolfSSL also publishes a per-build memory report through the
Membrowse tooling used in CI, which breaks a build down by section and symbol.

---

## 13. Troubleshooting

Common symptoms and what to do about them.

| Symptom | Cause and resolution |
| --- | --- |
| Assembler errors on `.S` files | The defines must reach the assembler, not just the compiler. Autotools uses `AM_CCASFLAGS`; hand-written builds must pass the same `-D` flags to the assembler, or use `WOLFSSL_USER_SETTINGS_ASM` with a `user_settings_asm.h` generated by `user_settings_asm.sh`. |
| `inlining failed in call to 'always_inline' '_mm_aesimc_si128'` | `WOLFSSL_AESNI` is set but the compiler was not given `-maes` (and `-msse4 -mpclmul` on Windows). Some accelerated code is intrinsics, not assembly, so the ISA flags are needed even though the assembly itself is in `.S`. The ARM equivalent is a missing `-march=...+crypto`. |
| Undefined references to `Transform_Sha256_*`, `AES_GCM_*_aesni`, … | The defines enable a code path whose assembly file is not in the build. With `./configure --enable-usersettings` no CFLAGS are added and no `--enable-*` is inferred from `user_settings.h`, so the matching `--enable-sp-asm`/`--enable-intelasm`/`--enable-armasm`/… must be given as well. In a hand-built project, add the file. |
| Undefined `Transform_Sha256_Len_base` on a Cortex-M/Thumb build | The ARM-mode port file was compiled instead of the Thumb-2 one. `./configure` selects between `armv8-32-*` and `thumb2-*` from the host triple, and a generic `arm` host gets ARM mode. Select the files in the project build instead. |
| Illegal instruction at run time | An extension define was enabled that the hardware lacks (common on RISC-V and on ARM `+crypto`). |
| Windows build misses the assembly | Visual Studio compiles the `.asm` files, not `.S`. Both exist for every accelerated primitive and are generated from the same source. |
| `--enable-sp=nonblock` rejected | `WOLFSSL_SP_NONBLOCK` cannot be combined with the specialised SP assembly. Use the C implementation for non-blocking builds. |
| SP assembly silently not used | `SP_WORD_SIZE` did not resolve to the value the assembly needs — e.g. `WOLFSSL_SP_X86_64` without a 64-bit `unsigned long`/`long long` falls back to 32 and undefines `WOLFSSL_SP_ASM`. |
| Key size or curve fails at run time | `WOLFSSL_SP_MATH` was used without the size compiled in. Use `WOLFSSL_SP_MATH_ALL`, or add the size define. |
| `#error "Size of unsigned long not detected"` from `sp_int.h` | `NO_64BIT` on a target whose `unsigned long` is 64-bit. See the note in section 3; this combination is not supported. |
| Undefined `sp_ecc_*_256` and similar after setting `NO_64BIT` | `SP_WORD_SIZE` has dropped to 16, and the specialised curves are not implemented at that width. Remove `NO_64BIT`, or contact support if your target genuinely has no 64-bit type. |
| Stack overflow after enabling SP | `WOLFSSL_SP_NO_MALLOC` moves everything to the stack. Either raise the stack, add `WOLFSSL_SP_SMALL`, or switch to `WOLFSSL_SMALL_STACK` if a heap exists. |
| Build fails on C99 VLAs | Define `WOLFSSL_SP_NO_DYN_STACK`. |

---

## See also

* `doc/ALGORITHM_DEFINES.md` — the options that select which algorithms are
  built and how each one is configured.
* `examples/configs/user_settings_embedded.h` — an editable template covering
  both guides.
* `INSTALL` — full build instructions for every supported toolchain.
* `wolfcrypt/src/sp_int.c` — the complete list of SP build options, in the
  comment block at the top of the file, including internal defines not
  described here.
* `wolfssl/wolfcrypt/settings.h` — platform detection and implied defines.

For help choosing a configuration for your hardware, or for a build that this
guide does not cover, contact **support@wolfssl.com**.
