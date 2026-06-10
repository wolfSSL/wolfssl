# Dilithium → ML-DSA migration guide

## Background

The post-quantum signature algorithm originally implemented in wolfSSL
under the pre-standardization name *Dilithium* was standardized by NIST
as **ML-DSA (Module-Lattice-based Digital Signature Algorithm) — FIPS
204** in 2024. This release renames the wolfSSL implementation of that
algorithm to its standardized name, mirroring the earlier Kyber → ML-KEM
migration in `wc_mlkem.{h,c}`.

For application code written against the legacy `dilithium_key` /
`wc_dilithium_*` / `wc_Dilithium_*` API there is **no immediate change
required**: a temporary compatibility shim translates the legacy names
into the canonical ones at compile time. The shim will be removed in a
future release; new code should adopt the canonical names directly.

## What changed

### File renames

| Old path                              | New path                                |
|---------------------------------------|-----------------------------------------|
| `wolfcrypt/src/dilithium.c`           | `wolfcrypt/src/wc_mldsa.c`              |
| `wolfssl/wolfcrypt/dilithium.h`       | `wolfssl/wolfcrypt/wc_mldsa.h`          |

The legacy `<wolfssl/wolfcrypt/dilithium.h>` path is now a thin shim
that `#include`s `wc_mldsa.h` and provides macro / inline aliases for
the legacy API.

### Symbol renames

| Old                                       | New                                          |
|-------------------------------------------|----------------------------------------------|
| `dilithium_key`                           | `MlDsaKey`                                   |
| `wc_dilithium_params`                     | `MlDsaParams`                                |
| `wc_dilithium_*` (lifecycle / sizing)     | `wc_MlDsaKey_*`                              |
| `wc_Dilithium_*` (DER encode / decode)    | `wc_MlDsaKey_*`                              |
| internal lower-case `dilithium_*` helpers | `mldsa_*`                                    |
| `DILITHIUM_*` algorithm-parameter macros  | `MLDSA_*` (matches `MLKEM_*` in `wc_mlkem.h`) |
| `DILITHIUM_LEVEL{2,3,5}_*_SIZE`, `ML_DSA_LEVEL{2,3,5}_*_SIZE`, `DILITHIUM_ML_DSA_{44,65,87}_*_SIZE` | `WC_MLDSA_{44,65,87}_*_SIZE` |
| `DEBUG_DILITHIUM`                         | `DEBUG_MLDSA`                                |

The three legacy size-constant families
(`DILITHIUM_LEVEL{2,3,5}_*_SIZE`, `ML_DSA_LEVEL{2,3,5}_*_SIZE`,
`DILITHIUM_ML_DSA_{44,65,87}_*_SIZE`) remain reachable through the
dilithium.h shim as `#define`-style aliases for the canonical
`WC_MLDSA_{44,65,87}_*_SIZE` family — eight spellings per parameter
set (`KEY_SIZE`, `PRV_KEY_SIZE`, `PUB_KEY_SIZE`, `SIG_SIZE`,
`PRV_KEY_DER_SIZE`, `PUB_KEY_DER_SIZE`, `BOTH_KEY_DER_SIZE`,
`BOTH_KEY_PEM_SIZE`). All of them are gated on
`!defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES)`.

The `WC_ML_DSA_{44,65,87}` / `WC_ML_DSA_{44,65,87}_DRAFT` / `WC_ML_DSA_DRAFT`
public level identifiers and the `PARAMS_ML_DSA_{44,65,87}_*`
per-parameter-set internal constants intentionally **keep** their
underscored `ML_DSA_` spelling — the level identifiers are established
public names and the `PARAMS_*` family is internal-only, so neither
benefits from a rename.

The `WOLFSSL_NO_ML_DSA_{44,65,87}` parameter-set disable gates are
likewise kept in their underscored form (matching the
`WOLFSSL_NO_ML_KEM_{512,768,1024}` spelling in `wc_mlkem.h`).

The 16 sign / verify / import / DER-decode entry points were also
re-ordered to put the `MlDsaKey*` first (matching the FIPS 204 / ML-KEM
convention used by `wc_MlKemKey_*`). The legacy parameter order is
preserved through static-inline wrapper functions in the shim header,
so legacy call sites compile unchanged.

`wc_MlDsaKey_Init` is a 3-argument function (`MlDsaKey*`, `void* heap`,
`int devId`) matching `wc_MlKemKey_Init`. The legacy 1-argument
`wc_dilithium_init(key)` is mapped through the shim to
`wc_MlDsaKey_Init(key, NULL, INVALID_DEVID)`.

### Build-gate renames

| Old                            | New                          |
|--------------------------------|------------------------------|
| `HAVE_DILITHIUM`               | `WOLFSSL_HAVE_MLDSA`         |
| `WOLFSSL_DILITHIUM_*` (~25)    | `WOLFSSL_MLDSA_*`            |
| `WC_DILITHIUM_CACHE_*`         | `WC_MLDSA_CACHE_*`           |
| `WC_DILITHIUM_FIXED_ARRAY`     | `WC_MLDSA_FIXED_ARRAY`       |
| `WC_DILITHIUMKEY_TYPE_DEFINED` | `WC_MLDSAKEY_TYPE_DEFINED`   |

The Autotools / CMake configure switches gain canonical aliases:

| Legacy                  | Canonical             |
|-------------------------|-----------------------|
| `--enable-dilithium`    | `--enable-mldsa`      |
| `WOLFSSL_DILITHIUM`     | `WOLFSSL_MLDSA`       |

Both spellings remain valid; the canonical form is recommended for new
projects.

The configure summary echoes `ML-DSA: yes` rather than `DILITHIUM: yes`.

### Public error-code rename

The error-code enumerator in `wolfssl/error-ssl.h` was renamed:

| Legacy                  | Canonical            | Numeric value |
|-------------------------|----------------------|---------------|
| `DILITHIUM_KEY_SIZE_E`  | `MLDSA_KEY_SIZE_E`   | `-453` (unchanged) |

The numeric value is unchanged, so any code that compares against the
literal `-453` (or stores the value) continues to work. Code that
references the symbol by name is covered by a legacy `#define
DILITHIUM_KEY_SIZE_E MLDSA_KEY_SIZE_E` alias, gated on
`!defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES)`. The error string returned
by `wolfSSL_ERR_reason_error_string` is now `"Wrong key size for
ML-DSA."`.

### Public ASN.1 / OID identifier renames

The pre-standardization `LEVEL2/3/5` spellings of the ML-DSA public ASN.1
key-type, certificate-type, and OID enumerators were renamed to match
the FIPS 204 parameter-set numbers (44 / 65 / 87), and to match the
existing `WC_MLDSA_{44,65,87}_*_SIZE` / `BENCH_ML_DSA_{44,65,87}_SIGN`
spellings:

| Legacy                       | Canonical              | Defined in |
|------------------------------|------------------------|------------|
| `ML_DSA_LEVEL{2,3,5}_TYPE`   | `ML_DSA_{44,65,87}_TYPE` | `wolfssl/wolfcrypt/asn_public.h` (`enum CertType`) |
| `ML_DSA_LEVEL{2,3,5}_KEY`    | `ML_DSA_{44,65,87}_KEY`  | `wolfssl/wolfcrypt/asn.h` (cert-gen key type) |
| `ML_DSA_LEVEL{2,3,5}k`       | `ML_DSA_{44,65,87}k`     | `wolfssl/wolfcrypt/oid_sum.h` (`enum Key_Sum`) |
| `CTC_ML_DSA_LEVEL{2,3,5}`    | `CTC_ML_DSA_{44,65,87}`  | `wolfssl/wolfcrypt/oid_sum.h` (`enum Ctc_SigType`) |

All four families keep their numeric values (e.g. `ML_DSA_44k` is still
`431`), so ABI is preserved. Source-level back-compat for unmigrated
consumers is provided by `#define`-style legacy aliases next to each
enum, gated on `!defined(WOLFSSL_NO_DILITHIUM_LEGACY_NAMES)` (the same
gate as the rest of the dilithium.h shim — see header comment in
`<wolfssl/wolfcrypt/dilithium.h>` for the gate's full coverage).

The `DILITHIUM_LEVEL{2,3,5}k` / `CTC_DILITHIUM_LEVEL{2,3,5}` /
`DILITHIUM_LEVEL{2,3,5}_TYPE` / `DILITHIUM_LEVEL{2,3,5}_KEY`
pre-standardization (NIST PQC round 3) enumerators are intentionally
**not** renamed: they identify a distinct draft-era OID surface and
coexist with the FIPS 204 entries in the same enum. For the same reason
the `"Dilithium Level {2,3,5}"` OID-name labels in
`wolfssl_object_info[]` (`src/ssl.c`) are kept under the Dilithium name
and coexist with parallel `"ML-DSA {44,65,87}"` rows.

The PEM header / footer markers used by `wc_MlDsaKey_*` PEM
import/export (`"-----BEGIN ML_DSA_LEVEL2 PRIVATE KEY-----"`, etc.) are
**intentionally unchanged** — the string contents are a serialization
format and renaming them would break PEM files written by older
wolfSSL. The C identifier names (`BEGIN_ML_DSA_LEVEL{2,3,5}_PRIV`,
`END_*`) are likewise unchanged.

### OpenSSL compatibility

The OpenSSL-compat enum value `WC_EVP_PKEY_DILITHIUM` and macro
`EVP_PKEY_DILITHIUM` are unchanged in this release. Aligning them with
OpenSSL 3.5+'s actual `NID_ML_DSA_*` values is planned for a follow-up
commit.

## How to migrate (when you are ready)

The temporary shim accepts both legacy and canonical names indefinitely
until it is removed. To migrate a consumer to canonical:

1. Replace `#include <wolfssl/wolfcrypt/dilithium.h>` with
   `#include <wolfssl/wolfcrypt/wc_mldsa.h>`.
2. Replace `dilithium_key` with `MlDsaKey`.
3. Replace each `wc_dilithium_*` / `wc_Dilithium_*` call with the
   `wc_MlDsaKey_*` form, swapping arguments to put the key first
   for the 16 affected entry points.
4. Replace `HAVE_DILITHIUM` / `WOLFSSL_DILITHIUM_*` / `WC_DILITHIUM_*`
   build-gate references with the canonical names.

Migration can be done file by file; the two spellings interoperate at
the link level (the shim's static-inline wrappers call into the
canonical exported symbols).

To suppress the legacy aliases (e.g. to surface stale references during
migration), define one or both of:

- `WOLFSSL_NO_DILITHIUM_LEGACY_NAMES` — suppresses the legacy
  `dilithium_key` / `wc_dilithium_*` / `wc_Dilithium_*` macro / inline
  aliases, the `ML_DSA_LEVEL{2,3,5}*` / `CTC_ML_DSA_LEVEL{2,3,5}` /
  `DILITHIUM_KEY_SIZE_E` enum aliases, and the legacy size-constant
  family (`DILITHIUM_LEVEL{2,3,5}_*_SIZE`, `ML_DSA_LEVEL{2,3,5}_*_SIZE`,
  `DILITHIUM_ML_DSA_{44,65,87}_*_SIZE`).
- `WOLFSSL_NO_DILITHIUM_LEGACY_GATES` — suppresses the bidirectional
  sub-config gate translations (legacy `WOLFSSL_DILITHIUM_*` /
  `WC_DILITHIUM_*` ↔ canonical `WOLFSSL_MLDSA_*` / `WC_MLDSA_*`). The
  parent gate (`HAVE_DILITHIUM` ↔ `WOLFSSL_HAVE_MLDSA`) forward arm is
  always active so that builds using only the legacy parent name still
  compile the canonical implementation file; the reverse arm honors
  this opt-out.

In-tree consumers have been migrated to the canonical names in this
release, so a build that defines `WOLFSSL_NO_DILITHIUM_LEGACY_NAMES`
(with or without `WOLFSSL_NO_DILITHIUM_LEGACY_GATES`) compiles cleanly
and `make check` passes.

### Internal API note (no back-compat aliases)

A handful of identifiers that were defined only in wolfSSL-internal
headers (no presence in `dilithium.h`, no public-API surface) were
renamed in place **without** a backwards-compatibility alias. They
affect downstream code only if it reached into `wolfssl/internal.h` or
similar internal headers:

| Legacy                                                | Canonical                                         | Defined in |
|-------------------------------------------------------|---------------------------------------------------|------------|
| `DILITHIUM_SA_MAJOR`, `DILITHIUM_LEVEL{2,3,5}_SA_{MAJOR,MINOR}` | `MLDSA_SA_MAJOR`, `MLDSA_{44,65,87}_SA_{MAJOR,MINOR}` | `wolfssl/internal.h` |
| `SIG_DILITHIUM`                                       | `SIG_MLDSA`                                       | `wolfssl/internal.h` |
| `dilithium_level{2,3,5}_sa_algo` (`enum SignatureAlgorithm`) | `mldsa_{44,65,87}_sa_algo`                    | `wolfssl/internal.h` |
| `dilithium_sign` (`enum ClientCertificateType`)       | `mldsa_sign`                                      | `wolfssl/internal.h` |
| `MIN_DILITHIUMKEY_SZ`                                 | `MIN_MLDSAKEY_SZ`                                 | `wolfssl/internal.h` |
| `minDilithiumKeySz` (struct field on `WOLFSSL_CTX`, `WOLFSSL_CERT_MANAGER`, `Options`) | `minMlDsaKeySz`           | `wolfssl/internal.h` |
| `haveDilithiumSig` (bitfield on `WOLFSSL_CTX`, `Options`) | `haveMlDsaSig`                                | `wolfssl/internal.h` |
| `peerDilithiumKey`, `peerDilithiumKeyPresent` (`WOLFSSL`) | `peerMlDsaKey`, `peerMlDsaKeyPresent`         | `wolfssl/internal.h` |
| `HYBRID_*_DILITHIUM_LEVEL*_SA_MINOR`                  | `HYBRID_*_MLDSA_{44,65,87}_SA_MINOR`              | `src/tls13.c` (file-local) |
| `dilithium` (union field on `SignatureCtx::key`)      | `mldsa`                                           | `wolfssl/wolfcrypt/asn.h` |
| `dilithium_test` (test-driver entry point)            | `mldsa_test`                                      | `wolfcrypt/test/test.{c,h}` |
| `bench_dilithium_level{2,3,5}_{key,pubkey,sig}`       | `bench_mldsa_{44,65,87}_{key,pubkey,sig}`         | `wolfssl/certs_test.h`, `wolfcrypt/benchmark/benchmark.c` |
| `bench_dilithiumKeySign`                              | `bench_mldsaKeySign`                              | `wolfcrypt/benchmark/benchmark.{c,h}` |
| `BENCH_DILITHIUM_LEVEL{2,3,5}_SIGN`                   | `BENCH_ML_DSA_{44,65,87}_SIGN` (legacy macros deleted as redundant duplicates) | `wolfcrypt/benchmark/benchmark.c` |

The benchmark CLI options `-dilithium_level{2,3,5}` are retained as
deprecated aliases for `-ml-dsa-{44,65,87}` and will be removed
alongside the dilithium.h shim.

### Test coverage

The canonical ML-DSA API is exercised by `tests/api/test_mldsa.c`
(~24 `test_mldsa_*` functions), `wolfcrypt/test/test.c::mldsa_test`,
and the TLS / X.509 paths in `tests/api.c` that exercise ML-DSA
end-to-end. These run under all build configurations including builds
that suppress the legacy alias surface.

The legacy-name shim itself is covered by
`tests/api/test_mldsa_legacy.c::test_mldsa_legacy_shim`, a single
focused regression test combining three layers of check:

- **Compile-time `wc_static_assert`** over every alias spelling — all
  three size-constant families (LEVEL, DILITHIUM_LEVEL,
  DILITHIUM_ML_DSA) at all 8 spellings per parameter set, every public
  enum alias, the error-code alias, and the FIPS 204
  algorithm-parameter macros.
- **Typed function-pointer assignments without casts** that bind each
  symbol-form alias (`wc_dilithium_init_ex`, `wc_dilithium_free`, …) to
  a pointer with the canonical signature, so a signature drift in the
  shim trips a build error.
- **Compile-time invocation of every arg-reordering macro** under
  `if (0)` so the compiler type-checks the macro expansion in every
  configuration (including verify-only builds where the runtime smoke
  test below is skipped).
- **Runtime make-key / sign / verify / export / import / DER round-trip**
  driving the arg-reordering macros with valid inputs; a same-type arg
  swap (which the compile-time invocation can't catch) shows up as a
  verification or import failure.

The runtime portion requires both sign and verify; in a verify-only
build it skips and the compile-time layers carry the coverage. A
same-type arg swap on the verify side specifically is then caught only
by the canonical KAT-driven verify tests in
`test_mldsa.c::test_mldsa_verify_*_kats`, which always run.

The whole file becomes a `TEST_SKIPPED` stub when
`WOLFSSL_NO_DILITHIUM_LEGACY_NAMES` is defined.

## ABI note

The library's exported linkage symbols are renamed: the `.so` /
`.dylib` / `.dll` now exports `wc_MlDsaKey_*` instead of
`wc_dilithium_*`. Applications that linked dynamically against the
legacy symbol names need to either recompile against the legacy header
path (the shim's static-inline wrappers resolve to the new symbols at
compile time) or switch their sources to the canonical names. Source
code that includes `<wolfssl/wolfcrypt/dilithium.h>` continues to build
without modification.
