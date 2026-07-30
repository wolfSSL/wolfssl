# wolfSSL PQC Benchmark

This directory contains a self-contained benchmark suite for wolfSSL's native
Post-Quantum Cryptography (PQC) algorithm implementations.

**Algorithms covered:**

| Algorithm Family | NIST Standard | Parameter Sets |
|---|---|---|
| ML-KEM (CRYSTALS-Kyber) | FIPS 203 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| ML-DSA (CRYSTALS-Dilithium) | FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| SLH-DSA (SPHINCS+) | FIPS 205 | All 10 SHAKE parameter sets (128s/f, 192s/f, 256s/f, and SHA-2 variants) |

All algorithms are implemented natively in wolfSSL — no liboqs dependency is
required for these results.

**Tested on:** wolfSSL 5.9.1

---

## 1. Prerequisites

### System packages

**Debian/Ubuntu:**
```sh
apt-get install -y gcc make autoconf automake libtool git
```

**Amazon Linux 2023 / RHEL / Fedora:**
```sh
dnf install -y gcc gcc-c++ make autoconf automake libtool git
```

**macOS (with Homebrew):**
```sh
brew install autoconf automake libtool
```

**Python 3.6+** is required to run `pqc_parse.py`. It is available by default
on most modern systems; no third-party packages are needed.

### Tested environments

| Architecture | OS | Notes |
|---|---|---|
| x86_64 | Pop!_OS 24.04 LTS (Ubuntu-based) | Primary development platform |
| aarch64 | Amazon Linux 2023 (Graviton2, t4g.medium) | CI verification |

---

## 2. How to Build and Run

### Step 1: Clone wolfSSL

```sh
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
```

### Step 2: Run the benchmark driver

```sh
./wolfcrypt/benchmark/pqc_bench.sh
```

This single command:
1. Runs `autogen.sh` if needed to generate the `configure` script
2. Configures wolfSSL with PQC algorithms and memory/stack tracking enabled
3. Builds only the benchmark binary target (not the full library + tests)
4. Runs the benchmark for each algorithm group
5. Writes a clean CSV file to `pqc_results.csv`

A run log is written alongside the CSV as `pqc_results.log`.

### Step 3 (optional): Normalize the output

```sh
python3 wolfcrypt/benchmark/pqc_parse.py pqc_results.csv
```

This normalises algorithm names to canonical NIST form and operation labels
to a consistent vocabulary (keygen/encaps/decaps/sign/verify).

### Driver script reference

```
pqc_bench.sh — wolfSSL PQC benchmark driver

USAGE:
  ./pqc_bench.sh [OPTIONS]

OPTIONS:
  --src-dir DIR      wolfSSL source tree root (default: auto-detected)
  --output FILE      CSV output file (default: pqc_results.csv)
  --skip-build       Skip configure+make; assume binary already built
  --help             Print this help and exit
```

### Normalizer reference

```
usage: pqc_parse.py [-h] [--format {wolfssl,pqcleo}] [--library LIBRARY]
                    [--output OUTPUT] INPUT_CSV

OPTIONS:
  --format wolfssl   Normalized wolfSSL CSV with Library column (default)
  --format pqcleo    PQC-LEO pipe-delimited format for cross-library comparison
  --library NAME     Library name for wolfssl format (default: wolfSSL)
  --output FILE      Output file (default: stdout)
```

---

## 3. Output Format

### Raw CSV (from `pqc_bench.sh`)

The raw output file uses the format produced by wolfSSL's benchmark binary
with `GENERATE_MACHINE_PARSEABLE_REPORT` enabled. After noise stripping by
`pqc_bench.sh`, each data row has the following columns:

| Column | Units | Description |
|---|---|---|
| `Algorithm` | — | wolfSSL internal algorithm name (e.g., `ML-KEM 512 `) |
| `key size` | bits | Security parameter / key size |
| `operation` | — | Operation name (e.g., `key gen`, `encap`, `sign`) |
| `avg ms` | milliseconds | Average time per operation |
| `ops/sec` | 1/s | Operations per second (averaged over the timed loop) |
| `ops` | count | Number of operations completed in the timed loop |
| `secs` | seconds | Actual elapsed time of the timed loop |
| `cycles` | CPU cycles | Total CPU cycles for the loop (when RDTSC available) |
| `cycles/op` | cycles | Average CPU cycles per operation |
| `heap_bytes` | bytes | Cumulative heap bytes allocated during the timed loop |
| `heap_allocs` | count | Number of heap allocations per operation |
| `stack_bytes` | bytes | Peak stack depth during the operation |

**Note:** The `ops/sec` figure is the mean throughput over many repeated
operations (typically 1 second of work). It is not a single-shot latency
measurement.

### Normalized CSV (`--format=wolfssl`)

After normalization by `pqc_parse.py --format=wolfssl`:

| Column | Description |
|---|---|
| `Library` | Always `wolfSSL` (overridable with `--library`) |
| `Algorithm` | Canonical NIST name (e.g., `ML-KEM-512`, `ML-DSA-44`, `SLH-DSA-SHAKE-128s`) |
| `Operation` | Canonical label: `keygen`, `encaps`, `decaps`, `sign`, `verify` |
| `ops/sec` | Same as raw |
| `avg_ms` | Same as raw |
| `ops`, `secs` | Loop iteration count and elapsed time (if present in input) |
| `heap_bytes`, `heap_allocs`, `stack_bytes` | Memory columns (if present in input) |

### PQC-LEO format (`--format=pqcleo`)

Pipe-delimited format matching the PQC-LEO parser:

```
Algorithm | Operation | Operations | Seconds | ms/op | op/sec
ML-KEM-512 | keygen | 69900 | 1.001389 | 0.014 | 69803.025
...
```

Memory columns are omitted in this format — PQC-LEO memory numbers come from
Valgrind massif (see Section 5).

---

## 4. Memory Measurement

This benchmark uses wolfSSL's built-in allocator instrumentation
(`--enable-memory --enable-trackmemory=verbose --enable-stacksize=verbose`),
which produces the `heap_bytes`, `heap_allocs`, and `stack_bytes` columns.

**What `heap_bytes` measures:**
Cumulative bytes allocated across all operations in the timed loop. This is
proportional to (but not equal to) the memory footprint of a single operation.
For example, if a KEM keygen allocates 3072 bytes once per call and the timed
loop runs 70,000 operations, `heap_bytes` will be `70,000 × 3072 = 214 MB`.
The per-operation heap cost is `heap_bytes / ops`.

**What `heap_allocs` measures:**
Number of `malloc()`/`free()` calls per operation (as confirmed by inspection
of wolfSSL source).

**What `stack_bytes` measures:**
Peak stack depth during the operation, measured by a canary-based probe. This
is the per-operation peak stack usage, not an aggregate.

**Limitation:** The `heap_bytes` figure is cumulative, not a peak RSS
measurement. It cannot be directly compared with Valgrind massif results
(which measure peak resident set size for a single operation). If
apples-to-apples comparison with liboqs Valgrind numbers is required, a
separate Valgrind massif instrumentation pass is needed.

---

## 5. Methodology Notes

### Timing

The benchmark binary uses a **1-second timed loop** per operation: it runs
the operation repeatedly until at least 1 second has elapsed, then reports
the mean throughput. This provides stable averages for fast operations
(KEM, ML-DSA) while remaining feasible for slow ones (SLH-DSA keygen/sign).

### CPU frequency scaling

For reproducible results, pin the CPU governor to performance mode before
running:

```sh
# Linux (requires cpupower / linux-tools):
sudo cpupower frequency-set -g performance

# macOS: not applicable (hardware-controlled)

# Verify (Linux):
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

Revert after benchmarking:
```sh
sudo cpupower frequency-set -g powersave
```

### NUMA / CPU affinity

On multi-socket machines, pin to a single NUMA node to avoid cross-socket
memory latency:

```sh
taskset -c 0 ./wolfcrypt/benchmark/pqc_bench.sh
```

### Thermal throttling

Results on laptops and mobile processors may vary significantly due to thermal
throttling. For publication-quality numbers:
- Run on desktop hardware or a bare-metal cloud instance (e.g., AWS m6i, c7g)
- Allow the system to reach thermal equilibrium before benchmarking
- Note the hardware platform in any published results

### Cycle counts

The `cycles` and `cycles/op` columns are populated via `RDTSC` (x86) or
`CNTVCT_EL0` (aarch64, enabled by `-march=armv8-a`). They are wall-clock
cycle counts, not retired instruction counts. Values may include OS
interrupt overhead.

---

## 6. Comparison with liboqs / PQC-LEO

wolfSSL implements ML-KEM, ML-DSA, and SLH-DSA natively without any
dependency on liboqs. Comparison against liboqs numbers is valid for
these algorithms.

**Falcon** in wolfSSL requires liboqs (wolfSSL delegates Falcon to the
liboqs library via a thin shim). Falcon numbers, if present, use that path
and are not a native wolfSSL implementation measurement.

### Generating PQC-LEO-compatible output

```sh
# Run the benchmark
./wolfcrypt/benchmark/pqc_bench.sh --output pqc_results.csv

# Convert to PQC-LEO pipe-delimited format
python3 wolfcrypt/benchmark/pqc_parse.py \
  --format=pqcleo \
  --output=pqc_results_pqcleo.psv \
  pqc_results.csv

# Feed into PQC-LEO's parser (from the PQC-LEO repo):
python3 scripts/parsing_scripts/parse_results.py pqc_results_pqcleo.psv
```

Note that PQC-LEO memory numbers (`intits`, `peakBytes`, etc.) come from
Valgrind massif and are not included in wolfSSL's inline tracking output.
Cross-library memory comparison requires Option B instrumentation (see Section 4).

---

## 7. Citation

To cite wolfSSL in academic or technical work:

> wolfSSL Inc., "wolfSSL Embedded SSL/TLS Library," https://www.wolfssl.com, 2024.

For algorithm-specific citations, refer to the relevant NIST FIPS standards:

- FIPS 203 (ML-KEM): https://doi.org/10.6028/NIST.FIPS.203
- FIPS 204 (ML-DSA): https://doi.org/10.6028/NIST.FIPS.204
- FIPS 205 (SLH-DSA): https://doi.org/10.6028/NIST.FIPS.205
