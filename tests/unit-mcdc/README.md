# tests/unit-mcdc — white-box MC/DC supplements

This directory holds small, standalone white-box programs that raise **MC/DC**
(Modified Condition/Decision Coverage) on wolfcrypt/wolfssl source files by
reaching decisions that are **structurally unreachable from the public API**.

These are **not** part of the wolfSSL build and are **not** registered in
`tests/api`. They exist for the external ISO 26262 per-module coverage campaign
in `iso26262/mcdc-per-module/`. Nothing here changes library behaviour.

## Why a separate module

The `tests/api` suite drives each source file through its *public* API. A handful
of decision conditions live in `WOLFSSL_LOCAL` (link-local) or file-`static`
helpers whose "impossible" operand combinations every public caller rejects
*before* the helper runs (e.g. a `size != 0` argument paired with a `NULL`
pointer, which every `wc_*` entry point turns into `BAD_FUNC_ARG`). Such a
condition's MC/DC independence pair can never be demonstrated from the API
without editing library source.

A white-box program compiles the `.c` file in directly (`#include`), so the
static/local helpers are in scope, and calls them with **both halves of each
MC/DC independence pair** in the same binary.

## How coverage is combined

llvm-cov computes MC/DC independence **per binary**. The campaign's
`aggregate.sh` unions the "independence shown" bit **across binaries by source
`line:col`**. So each pair must be completed *within the white-box binary
itself* — it does not lean on the API tests to supply the other half. The
white-box result is unioned in as an extra `"<variant>_wb"` ledger row, one per
build variant, exactly like any other variant.

## Build contract (driven by `run-mcdc.sh`)

The campaign's `run-mcdc.sh` builds each file via `#include` with the **exact**
compile flags the instrumented library used for that translation unit (captured
from the real `libtool` command — struct layout and backend selection depend on
`-DHAVE___UINT128_T`, `user_settings.h`, `-DWOLFSSL_TEST_STATIC_BUILD`, …), then
links against that variant's `libwolfssl.a` **with the file's own object
removed** (the white-box TU supplies the single, instrumented definition). The
binary is run, exported with `llvm-cov export`, and its `aes.c` MC/DC is unioned
by `line:col`. Any failure in this path is best-effort: it logs a skip and never
affects the API variant's own coverage row.

## Files

| file | target source | reaches |
|---|---|---|
| `test_aes_whitebox.c` | `wolfcrypt/src/aes.c` | `GHASH` / `GHASH_UPDATE` internal `ptr != NULL` guards (Class 1, 13 conds) and `_AesNew_common` cross-argument `BAD_FUNC_ARG` checks (Class 2, 6 conds) |

### `test_aes_whitebox.c` — what it deliberately does **not** cover

Four aes.c union residuals remain structurally uncoverable even here and stay
justified in `iso26262/mcdc-per-module/reports/aes/RESIDUALS.md`:

- **13386:5**, **13836:5** — the two operands are exact logical **complements**
  of one parameter (`ivSz==0`/`ivSz>0`, `ivFixed==NULL`/`!=NULL`); unique-cause
  MC/DC is unsatisfiable by construction.
- **14268:0** — `roll_auth`'s `ret==0` needs an internal AES op to fail
  mid-operation, not selectable without corrupting library state.
- **15833:0** — a dead defensive branch on a loop index provably bounded to
  `[0,7)`.

## Adding a new white-box module

1. Create `test_<file>_whitebox.c` that `#include`s the target `.c` and, in
   `main()`, calls each unreachable helper with both halves of every targeted
   MC/DC pair. Keep every call memory-safe (short-circuits protect NULL derefs);
   surface setup failures as printed skips and **return 0** (a nonzero exit
   makes the campaign discard the variant).
2. Point the campaign at it (a per-module white-box source path in
   `db/modules.json`); `run-mcdc.sh`'s white-box step handles build/link/export.
3. Re-run `run-mcdc.sh <module>` then `aggregate.sh <module>`; confirm the
   targeted `line:col` keys leave `GAPS.md`.
