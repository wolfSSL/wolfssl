# Agent Instructions — wolfSSL PQC Benchmark

This work adds a self-contained PQC benchmark driver to wolfssl/wolfssl.

Working branch: `feature/pqc-benchmark`
Epic: `wolfssl-jqr`

---

## Goal

Produce a reproducible, publishable PQC benchmark that wolfSSL owns and controls.
The deliverable is a driver script + documentation in `wolfcrypt/benchmark/` that
any researcher can clone and run to reproduce the numbers.

**Not a PR into crt26/PQC-LEO.** The canonical benchmark lives here.

---

## What Already Exists in benchmark.c

`wolfcrypt/benchmark/benchmark.c` already covers PQC. Do not rewrite or duplicate it.

| Algorithm | Benchmark function | Configure flag |
|---|---|---|
| ML-KEM-512/768/1024 | `bench_mlkem(WC_ML_KEM_512\|768\|1024)` | `--enable-mlkem` (default on) |
| ML-DSA-44/65/87 | `bench_dilithium(2\|3\|5)` | `--enable-dilithium` |
| SLH-DSA-SHAKE-128s/f…256s/f | `bench_slhdsa(SLHDSA_SHAKE128S…)` | `--enable-slhdsa` |
| Falcon-512/1024 | `bench_falconKeySign(1\|5)` | `--enable-falcon --with-liboqs` |

**Relevant build-time defines:**
- `WOLFSSL_BENCHMARK_FIXED_CSV` — always emit CSV
- `GENERATE_MACHINE_PARSEABLE_REPORT` — prefix lines for grep-able parsing
- `WC_BENCH_HEAP_TRACKING` — add heap columns to output
- `WC_BENCH_STACK_TRACKING` — add stack columns to output
- Enabled automatically by: `--enable-memory --enable-trackmemory=verbose --enable-stacksize=verbose`

**Relevant runtime flags:**
- `-csv` — CSV output
- `-kyber`, `-kyber512`, `-kyber768`, `-kyber1024` — ML-KEM variants
- `-slhdsa`, `-slhdsa-shake128s`, … — SLH-DSA variants
- `-dilithium` — all ML-DSA levels (see benchmark.c ~line 1402)
- `-falcon_level1`, `-falcon_level5` — Falcon (requires liboqs build)

---

## Open Issues (epic wolfssl-jqr)

| ID | Task |
|---|---|
| `wolfssl-9jt` | Audit benchmark.c PQC CSV output format precisely |
| `wolfssl-bkx` | Write `wolfcrypt/benchmark/pqc_bench.sh` driver script |
| `wolfssl-cdu` | Decide memory measurement approach (built-in vs. Valgrind) |
| `wolfssl-4e5` | Write `wolfcrypt/benchmark/README-pqc.md` |

---

## Key Files

```
wolfcrypt/benchmark/
├── benchmark.c          # DO NOT REWRITE — extend only if genuinely needed
├── benchmark.h
├── README.md            # existing general benchmark docs
├── pqc_bench.sh         # NEW — our driver script
└── README-pqc.md        # NEW — reproducibility docs for published numbers
```

---

## PQC Algorithm Reference

**ML-KEM** (`wolfssl/wolfcrypt/wc_mlkem.h`)
- Type constants (enum): `WC_ML_KEM_512=0`, `WC_ML_KEM_768=1`, `WC_ML_KEM_1024=2`
- Key type: `MlKemKey` (aliased as `KyberKey`)
- Operations: keygen → `wc_MlKemKey_MakeKey()`, encaps → `wc_MlKemKey_Encapsulate()`, decaps → `wc_MlKemKey_Decapsulate()`

**ML-DSA / Dilithium** (`wolfssl/wolfcrypt/dilithium.h`)
- Key type: `dilithium_key`
- Level set via: `wc_dilithium_set_level(key, 2|3|5)` → ML-DSA-44/65/87
- Operations: `wc_dilithium_init()`, `wc_dilithium_make_key()`, `wc_dilithium_sign_msg()`, `wc_dilithium_verify_msg()`

**SLH-DSA** (`wolfssl/wolfcrypt/wc_slhdsa.h`)
- Key type: `SlhDsaKey`; param: `enum SlhDsaParam`
- SHAKE variants (always available with `--enable-slhdsa`):
  `SLHDSA_SHAKE128S=0`, `SLHDSA_SHAKE128F=1`, `SLHDSA_SHAKE192S=2`,
  `SLHDSA_SHAKE192F=3`, `SLHDSA_SHAKE256S=4`, `SLHDSA_SHAKE256F=5`
- SHA2 variants (need `WOLFSSL_SLHDSA_SHA2`): `SLHDSA_SHA2_128S=6` … `SLHDSA_SHA2_256F=11`
- Operations: `wc_SlhDsaKey_Init()`, `wc_SlhDsaKey_MakeKey()`, `wc_SlhDsaKey_Sign()`, `wc_SlhDsaKey_Verify()`

**Falcon** (`wolfssl/wolfcrypt/falcon.h`)
- Requires liboqs: `#error "HAVE_FALCON requires HAVE_LIBOQS."` at line 41
- Configure: `--enable-falcon --with-liboqs=/path/to/liboqs`
- Falcon is **included** in the benchmark when liboqs is available, but the driver
  must degrade gracefully when it is not (skip with a note, do not fail).

---

## PQC-LEO Reference Repo

The shallow clone at `~/WORK/PQC-LEO` (branch `upstream-main`, commit `9ea3d22`) is
kept as a **format reference only** — to verify that our CSV output columns are
compatible if someone later wants to feed our results into PQC-LEO's parsers.
Do not treat PQC-LEO as a dependency or deliverable target.

PQC-LEO CSV column order for speed results:
```
Algorithm | Operation | Operations | Seconds | ms/op | op/sec
```
Operations for KEM: `keygen`, `encaps`, `decaps`
Operations for SIG: `keypair`, `sign`, `verify`

---

## RustCrypto / Upstream PR Notes

When this is ready for upstream:
- Remote `origin` = `git@github.com:MarkAtwood/wolfssl.git` (fork)
- Remote `upstream` = `github.com:wolfssl/wolfssl`
- Pre-push: `typos wolfcrypt/benchmark/`, clang-format on any new C, check that
  existing benchmark tests still pass
- PR target: `wolfssl/wolfssl` master

---

## Non-Interactive Shell Commands

`cp`, `mv`, `rm` may be aliased to `-i` on this system. Always use:

```bash
cp -f src dst
mv -f src dst
rm -f file
rm -rf dir
apt-get install -y pkg
```

---

## Issue Tracking

Issues for this work are tracked in the **PQC-LEO repo beads database** at
`~/WORK/PQC-LEO`. Run `bd` commands from there, not here.

```bash
cd ~/WORK/PQC-LEO
bd ready --json
bd show PQC-LEO-v6o   # epic
```
