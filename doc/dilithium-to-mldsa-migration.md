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
  aliases.
- `WOLFSSL_NO_DILITHIUM_LEGACY_GATES` — suppresses the bidirectional
  sub-config gate translations (legacy `WOLFSSL_DILITHIUM_*` /
  `WC_DILITHIUM_*` ↔ canonical `WOLFSSL_MLDSA_*` / `WC_MLDSA_*`). The
  parent gate (`HAVE_DILITHIUM` ↔ `WOLFSSL_HAVE_MLDSA`) forward arm is
  always active so that builds using only the legacy parent name still
  compile the canonical implementation file; the reverse arm honors
  this opt-out.

> **Note on `WOLFSSL_NO_DILITHIUM_LEGACY_NAMES`:** in this release the
> opt-out is only useful for builds whose consumer code (TLS, ASN.1,
> EVP, tests, benchmark, examples, ...) has already been migrated to
> the canonical names. The standard wolfSSL distribution still uses
> `wc_dilithium_*` and `dilithium_key` in `wolfcrypt/src/asn.c`,
> `src/ssl_load.c`, `src/internal.c`, `wolfcrypt/test/test.c`, and
> elsewhere; suppressing the macro / inline aliases breaks those
> translation units (e.g. `wc_dilithium_verify_ctx_msg` becomes an
> implicit declaration). The flag is intended primarily for downstream
> projects that have completed their own migration; in-tree consumers
> will be migrated in a follow-up PR.

## Internal infrastructure files migrated to canonical sub-gates

One wolfSSL-internal file outside the dilithium.h reach had its
`WOLFSSL_DILITHIUM_NO_SIGN` / `WOLFSSL_DILITHIUM_NO_VERIFY` sub-gate
references migrated to canonical `WOLFSSL_MLDSA_*` spellings:

- `wolfssl/certs_test.h` — auto-generated cert-data buffers, has zero
  `#include` directives. Reachable from external TUs (examples,
  embedded apps) that pull in only `<wolfssl/ssl.h>` and do not
  transitively include `dilithium.h`. Reads 11 sub-gate references
  (`_NO_SIGN` / `_NO_VERIFY`).

`wolfssl/wolfcrypt/memory.h` previously branched its static-pool sizing
(`LARGEST_MEM_BUCKET` / `WOLFMEM_BUCKETS` / `WOLFMEM_DIST`) on a
combination of `WOLFSSL_MLDSA_VERIFY_SMALL_MEM` /
`WOLFSSL_MLDSA_SIGN_SMALL_MEM` / `WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM` /
`WOLFSSL_MLDSA_VERIFY_ONLY`. Those branches were removed: when
`WOLFSSL_HAVE_MLDSA` is defined, the file now picks the larger sizing
unconditionally. The static-pool macros are consumed only by
`wolfcrypt/src/memory.c` and the test harnesses; production deployments
that need different sizing already override `LARGEST_MEM_BUCKET` /
`WOLFMEM_BUCKETS` / `WOLFMEM_DIST` directly. Removing the conditional
gating drops memory.h's dependency on ML-DSA sub-gates entirely.

To keep the legacy `user_settings.h` path working for `certs_test.h` —
i.e. a build that defines only `WOLFSSL_DILITHIUM_NO_SIGN` /
`WOLFSSL_DILITHIUM_NO_VERIFY` and never reaches `dilithium.h` before
the cert-buffer header is processed — the forward translations for
those two gates live in `<wolfssl/wolfcrypt/settings.h>`. settings.h is
included transitively by any TU that pulls in `certs_test.h`, so the
canonical sub-gates are always defined before they are read. The
remaining ~30 sub-gates are read only from wc\_mldsa.h / wc\_mldsa.c,
both of which transitively pull in dilithium.h first; their forward
translations stay there to keep settings.h lean. The reverse arm
(canonical → legacy) lives entirely in dilithium.h because it is only
consumed by unmigrated code, which by definition includes dilithium.h.
The generator script (`gencertbuf.pl`) was updated correspondingly.

`certs_test.h` and the `memory.h` static-pool macros are both
wolfSSL-internal infrastructure (an auto-generated cert-buffer data
file and the static allocator's default sizing), not consumer-facing
API; these changes do not require downstream code changes.

## Macro / comment cleanup inside `wc_mldsa.{c,h}`

A follow-on cleanup of the ML-DSA implementation file finished the
internal naming migration that the file/symbol rename above started:

- All algorithm-parameter macros defined in `wolfssl/wolfcrypt/wc_mldsa.h`
  (`DILITHIUM_Q`, `DILITHIUM_N`, `DILITHIUM_D`, `DILITHIUM_ETA_*`,
  `DILITHIUM_GAMMA1_*`, `DILITHIUM_K_SZ`, `DILITHIUM_MU_SZ`,
  `DILITHIUM_MAX_*`, …) were renamed to canonical `MLDSA_*` spellings
  matching the `MLKEM_*` internal constants in
  `<wolfssl/wolfcrypt/wc_mlkem.h>`. The `PARAMS_ML_DSA_{44,65,87}_*`
  per-parameter-set internal constants and the
  `WC_ML_DSA_{44,65,87}` / `WC_ML_DSA_{44,65,87}_DRAFT` /
  `WC_ML_DSA_DRAFT` public level identifiers keep their underscored
  spelling — the level identifiers are established public names and
  the `PARAMS_*` family is internal-only.
- The per-parameter-set size constants previously existed in **three**
  redundant spellings — `DILITHIUM_LEVEL{2,3,5}_*_SIZE`,
  `ML_DSA_LEVEL{2,3,5}_*_SIZE`, and
  `DILITHIUM_ML_DSA_{44,65,87}_*_SIZE`. They were consolidated to a
  single canonical family, `WC_MLDSA_{44,65,87}_*_SIZE`. All three
  legacy spellings remain reachable as aliases through the
  `<wolfssl/wolfcrypt/dilithium.h>` shim (gated by
  `WOLFSSL_NO_DILITHIUM_LEGACY_NAMES`); a duplicate `MLDSA_N`
  definition in `wc_mldsa.h` was also removed.
- All ~20 file-local macros inside `wolfcrypt/src/wc_mldsa.c`
  (`DILITHIUM_SIGN_BYTES`, `DILITHIUM_GEN_S_*`, `DILITHIUM_HASH_OID_LEN`,
  `DILITHIUM_PARAMS_CNT`, `DILITHIUM_COEFF_S*`, `DILITHIUM_QINV`,
  `DILITHIUM_NTT_ZETA_1`, `DILITHIUM_POS_OFFSET`, …) were renamed
  to `MLDSA_*`. The file-local macros are not user-visible and have no
  alias in the shim.
- The user-tunable knobs documented in the `wc_mldsa.c` file-top
  comment block — `DEBUG_DILITHIUM` and the five performance-tuning
  defines `DILITHIUM_MUL_SLOW`, `DILITHIUM_MUL_44_SLOW`,
  `DILITHIUM_MUL_11_SLOW`, `DILITHIUM_MUL_QINV_SLOW`,
  `DILITHIUM_MUL_Q_SLOW` — were renamed to `DEBUG_MLDSA` /
  `MLDSA_MUL_*_SLOW`. These are set from `user_settings.h` or `-D`,
  so a forward-translation block was added to the legacy-gates arm
  in `<wolfssl/wolfcrypt/dilithium.h>` (gated by
  `WOLFSSL_NO_DILITHIUM_LEGACY_GATES`) so consumers using the legacy
  spelling continue to get the intended code path.
- A long-standing typo, `dilitihium_get_der_length()` (5 call sites,
  `static`-scope), was corrected to `mldsa_get_der_length()`.
- All `DILITHIUM_*` legacy macro spellings remain reachable from
  unmigrated in-tree consumers (`wolfcrypt/src/asn.c`, `src/ssl_load.c`,
  `src/internal.c`, `src/tls13.c`, `src/ssl.c`, `src/x509.c`,
  `src/ssl_api_pk.c`, `src/ssl_certman.c`, `wolfssl/internal.h`,
  `wolfssl/wolfcrypt/asn.h`, `asn_public.h`, `oid_sum.h`,
  `examples/configs/user_settings_pq.h`,
  `wolfcrypt/benchmark/benchmark.c`, `wolfcrypt/test/test.c`,
  `tests/api/test_mldsa.c`) and downstream code through a new
  reverse-arm macro alias block in `<wolfssl/wolfcrypt/dilithium.h>`,
  gated by the existing `WOLFSSL_NO_DILITHIUM_LEGACY_NAMES` opt-out.
- All function and section comments inside `wc_mldsa.c` had their
  "Dilithium" / "dilithium" prose replaced with "ML-DSA" (the file-top
  credit retains a parenthetical mention of the historical name).
- Every algorithm-step citation was re-numbered against FIPS 204 Final
  (August 2024). The implementation was previously annotated with the
  draft (IPD) numbering — e.g. `Algorithm 18 skEncode`, `Algorithm 26
  ExpandA`, `Algorithm 29 Power2Round`. These were updated to the
  Final numbering (`Algorithm 24 skEncode`, `Algorithm 32 ExpandA`,
  `Algorithm 35 Power2Round`, …) and the section references were
  retargeted from the draft `§8.x` building-blocks group to the Final
  `§7.x` arrangement. SHAKE128/256 notation references were redirected
  from the IPD `§8.3` to the Final `§3.7`. Citation punctuation was
  normalized from `FIPS 204. N.M:` to `FIPS 204 §N.M,`.

These changes are contained to `wolfcrypt/src/wc_mldsa.c`,
`wolfssl/wolfcrypt/wc_mldsa.h`, and the macro-alias block in
`wolfssl/wolfcrypt/dilithium.h`. No external consumer is touched.

### Retained internal symbols

A few internal-only spellings are intentionally **not** renamed in this
PR:

- `DYNAMIC_TYPE_DILITHIUM` — heap-allocation tag string used by
  `WC_ALLOC_VAR` / `WC_FREE_VAR_EX` inside `wc_mldsa.c`. Pure
  bookkeeping, never crosses the public API surface.
- `ML_DSA_PCT_E` — internal error code returned only by the FIPS
  Pairwise Consistency Test path inside `wc_MlDsaKey_MakeKey`. Not part
  of the documented external error-code surface for this algorithm.

These are scheduled for renaming alongside the eventual removal of the
`dilithium.h` shim.

## ABI note

The library's exported linkage symbols are renamed: the `.so` /
`.dylib` / `.dll` now exports `wc_MlDsaKey_*` instead of
`wc_dilithium_*`. Applications that linked dynamically against the
legacy symbol names need to either recompile against the legacy header
path (the shim's static-inline wrappers resolve to the new symbols at
compile time) or switch their sources to the canonical names. Source
code that includes `<wolfssl/wolfcrypt/dilithium.h>` continues to build
without modification.
