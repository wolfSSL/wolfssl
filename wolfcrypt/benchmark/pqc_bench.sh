#!/bin/sh
# pqc_bench.sh — wolfSSL PQC benchmark driver
#
# Builds wolfSSL with PQC algorithms enabled and runs the benchmark binary
# for each algorithm group, producing a single CSV output file.
#
# USAGE:
#   ./pqc_bench.sh [OPTIONS]
#
# OPTIONS:
#   --src-dir DIR      wolfSSL source tree root (default: auto-detected from script location)
#   --output FILE      CSV output file (default: pqc_results.csv)
#   --skip-build       Skip configure+make; assume binary already built in --src-dir
#   --help             Print this usage and exit
#
# QUICK START:
#   git clone https://github.com/wolfSSL/wolfssl.git
#   cd wolfssl
#   cp wolfcrypt/benchmark/pqc_bench.sh .  # or run from the repo directly
#   ./wolfcrypt/benchmark/pqc_bench.sh
#
# DEPENDENCIES:
#   C compiler (gcc/clang), make, autoconf, automake, libtool
#   No external PQC libraries required — wolfSSL implements all algorithms natively.
#
# EXIT CODES:
#   0   Success
#   1   Configuration error (bad args, missing tools)
#   2   Build failure (configure or make failed)
#   3   Benchmark run failure (one or more benchmark runs failed)
#
# NOTES:
#   - On aarch64, -march=armv8-a is added to CFLAGS to enable hardware cycle counters.
#   - wolfSSL benchmark binary uses '-ml-dsa' for ML-DSA (Dilithium) as of 5.9.1;
#     the '-dilithium' alias is NOT recognized.
#   - wolfSSL does not support autotools VPATH (out-of-tree) builds; configure and
#     make run inside the source tree. Use git worktrees for parallel builds.
#
# MEMORY MEASUREMENT APPROACH (Option A — wolfSSL built-in tracking):
#
#   This script uses wolfSSL's built-in allocator instrumentation:
#     --enable-memory --enable-trackmemory=verbose --enable-stacksize=verbose
#
#   This produces heap_bytes, heap_allocs, and stack_bytes columns in the CSV.
#   heap_bytes is the cumulative heap bytes allocated over the timed loop
#   (not peak RSS per single operation). stack_bytes is peak stack depth
#   measured via a canary-based thread stack probe.
#
#   Alternative (Option B — Valgrind massif):
#     True peak RSS per single operation, directly comparable to liboqs/PQC-LEO
#     Valgrind numbers. Requires separate thin C wrapper programs per algorithm
#     and ~20x runtime overhead. File a separate issue if cross-library memory
#     comparison is required — Option A suffices for standalone wolfSSL reporting.

set -eu

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
OUTPUT_FILE="pqc_results.csv"
SKIP_BUILD=0
SRC_DIR=""   # auto-detected below after arg parsing

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    awk '/^#!/{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --src-dir)
            SRC_DIR="$2"; shift 2 ;;
        --output)
            OUTPUT_FILE="$2"; shift 2 ;;
        --skip-build)
            SKIP_BUILD=1; shift ;;
        --help|-h)
            usage ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            echo "Run '$0 --help' for usage." >&2
            exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Locate wolfssl source root
# ---------------------------------------------------------------------------
# pqc_bench.sh lives at wolfcrypt/benchmark/pqc_bench.sh, so source root
# is two levels up from the script's directory. This is the canonical
# location — the script should always be run from inside the source tree.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTO_SRC="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -z "$SRC_DIR" ]; then
    SRC_DIR="$AUTO_SRC"
fi

# Normalize to absolute path
SRC_DIR="$(cd "$SRC_DIR" && pwd)"

if [ ! -f "$SRC_DIR/configure.ac" ]; then
    echo "ERROR: '$SRC_DIR' does not look like a wolfSSL source tree (no configure.ac)" >&2
    echo "  Pass --src-dir /path/to/wolfssl or run from inside the source tree." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Resolve OUTPUT_FILE to absolute path (before any cd)
# ---------------------------------------------------------------------------
case "$OUTPUT_FILE" in
    /*) ;;
    *) OUTPUT_FILE="$(pwd)/$OUTPUT_FILE" ;;
esac

LOG_FILE="${OUTPUT_FILE%.csv}.log"

echo "wolfSSL PQC Benchmark Driver"
echo "  Source dir: $SRC_DIR"
echo "  Output CSV: $OUTPUT_FILE"
echo "  Log file:   $LOG_FILE"
echo ""

# ---------------------------------------------------------------------------
# Detect architecture for arch-specific CFLAGS
# ---------------------------------------------------------------------------
ARCH="$(uname -m)"
ARCH_CFLAGS=""
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    # -march=armv8-a enables CNTVCT_EL0 hardware cycle counter access on Graviton.
    ARCH_CFLAGS="-march=armv8-a"
    echo "Detected aarch64: adding $ARCH_CFLAGS to CFLAGS"
    echo ""
fi

# ---------------------------------------------------------------------------
# Build phase
# ---------------------------------------------------------------------------
if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "=== Phase 1: Build ==="

    # wolfSSL uses autotools and does not support VPATH (out-of-tree) builds.
    # configure and make run inside the source tree. This is intentional design.
    cd "$SRC_DIR"

    # Ensure autogen has been run (configure script must exist in source root)
    if [ ! -f "$SRC_DIR/configure" ]; then
        echo "Running autogen.sh to generate configure script..."
        ./autogen.sh || {
            echo "ERROR: autogen.sh failed (exit $?)" >&2
            exit 2
        }
    fi

    # Compile-time defines for machine-parseable output:
    #   GENERATE_MACHINE_PARSEABLE_REPORT: prefixes info lines with "###," and
    #     error lines with "!!!," so they are trivially filterable from CSV data.
    #   WOLFSSL_BENCHMARK_FIXED_CSV: forces CSV mode always (belt-and-suspenders
    #     alongside the -csv runtime flag).
    PQC_CFLAGS="-DGENERATE_MACHINE_PARSEABLE_REPORT -DWOLFSSL_BENCHMARK_FIXED_CSV"
    if [ -n "$ARCH_CFLAGS" ]; then
        PQC_CFLAGS="$PQC_CFLAGS $ARCH_CFLAGS"
    fi

    echo "Configuring wolfSSL with PQC flags..."
    ./configure \
        --enable-mlkem \
        --enable-dilithium \
        --enable-slhdsa \
        --enable-memory \
        "--enable-trackmemory=verbose" \
        "--enable-stacksize=verbose" \
        "CFLAGS=$PQC_CFLAGS" || {
        echo "ERROR: configure failed (exit $?)" >&2
        exit 2
    }

    echo ""
    echo "Building benchmark binary..."
    # Build only the benchmark binary target; no need to build the full library
    # and all examples — 'wolfcrypt/benchmark/benchmark' is the specific target.
    make -j"$(nproc)" wolfcrypt/benchmark/benchmark || {
        echo "ERROR: make failed (exit $?)" >&2
        exit 2
    }

    echo "Build complete."
    echo ""
fi

# ---------------------------------------------------------------------------
# Locate benchmark binary
# ---------------------------------------------------------------------------
BENCH="$SRC_DIR/wolfcrypt/benchmark/benchmark"
if [ ! -x "$BENCH" ]; then
    echo "ERROR: Benchmark binary not found or not executable: $BENCH" >&2
    if [ "$SKIP_BUILD" -eq 1 ]; then
        echo "  (--skip-build was set; run without --skip-build to build first)" >&2
    fi
    exit 1
fi
echo "Benchmark binary: $BENCH"
echo ""

# ---------------------------------------------------------------------------
# Benchmark runs
# ---------------------------------------------------------------------------
# Each algorithm group is a separate invocation so one failure doesn't abort
# the entire run. Stderr (progress/verbose output) is tee'd to the log file.
# Stdout (CSV data) is appended to a temporary file for assembly.
#
# NOTE: '-dilithium' is NOT recognized by wolfSSL >= 5.9.1 benchmark binary.
#       Use '-ml-dsa' (all security levels) or '-dilithium_level2/3/5' for
#       specific levels.

echo "=== Phase 2: Benchmark Runs ==="

RAW_CSV="/tmp/pqc_bench_raw_$$.csv"
trap 'rm -f "$RAW_CSV"' EXIT

BENCH_FAILURES=0

# run_bench LABEL FLAG [FLAG ...]
# Run benchmark for one group, appending CSV rows to RAW_CSV.
run_bench() {
    _label="$1"; shift
    echo "  Benchmarking: $_label ..."

    # With GENERATE_MACHINE_PARSEABLE_REPORT compiled in, non-CSV lines get
    # "###," or "!!!," prefixes. We redirect stderr to the log (it contains
    # stack/heap summaries and verbose timing) and append stdout to RAW_CSV.
    if ! "$BENCH" -csv "$@" >>"$RAW_CSV" 2>>"$LOG_FILE"; then
        echo "  WARNING: benchmark run for '$_label' exited non-zero" >&2
        BENCH_FAILURES=$((BENCH_FAILURES + 1))
    fi
}

# ML-KEM (NIST FIPS 203, formerly CRYSTALS-Kyber)
run_bench "ML-KEM-512"   -kyber512
run_bench "ML-KEM-768"   -kyber768
run_bench "ML-KEM-1024"  -kyber1024

# ML-DSA (NIST FIPS 204, formerly CRYSTALS-Dilithium)
# '-ml-dsa' benchmarks all three security levels (44/65/87) in one pass.
run_bench "ML-DSA (levels 44/65/87)" -ml-dsa

# SLH-DSA (NIST FIPS 205, formerly SPHINCS+) — all parameter sets
run_bench "SLH-DSA-SHAKE-128s"  -slhdsa-shake128s
run_bench "SLH-DSA-SHAKE-128f"  -slhdsa-shake128f
run_bench "SLH-DSA-SHAKE-192s"  -slhdsa-shake192s
run_bench "SLH-DSA-SHAKE-192f"  -slhdsa-shake192f
run_bench "SLH-DSA-SHAKE-256s"  -slhdsa-shake256s
run_bench "SLH-DSA-SHAKE-256f"  -slhdsa-shake256f

echo ""

# ---------------------------------------------------------------------------
# Assemble output CSV: one header + all data rows, no noise
# ---------------------------------------------------------------------------
# Filtering rules (in priority order):
#   1. Lines prefixed "###," or "!!!," from GENERATE_MACHINE_PARSEABLE_REPORT
#      are info/error annotations — discard.
#   2. Header line detection supports two formats produced by wolfSSL:
#        New (with GENERATE_MACHINE_PARSEABLE_REPORT):
#          "asym",Algorithm,key size,operation,...
#        Legacy (without it):
#          Algorithm,key size,operation,...
#      Keep only the first occurrence; strip the leading type field and
#      trailing comma if present.
#   3. Data rows in new format start with an unquoted type token ("asym,").
#      Legacy data rows have a numeric key size in field 2.
#      Both cases: strip leading type field and trailing comma, emit once.
#   4. All other lines (banners, "Benchmark complete", memory/stack summaries,
#      "This format allows...", section headings) are noise — drop silently.

echo "=== Phase 3: Assembling CSV ==="

awk '
BEGIN {
    header_printed = 0
}
# GENERATE_MACHINE_PARSEABLE_REPORT annotation lines — always discard
/^###/ || /^!!!/ { next }

# New format header: starts with quoted type field then "Algorithm,"
# e.g.: "asym",Algorithm,key size,operation,...
/^"[a-z]*",Algorithm,/ {
    if (!header_printed) {
        # Strip leading quoted type field and its comma, then trailing comma
        line = $0
        sub(/^"[^"]*",/, "", line)
        sub(/,$/, "", line)
        print line
        header_printed = 1
    }
    next
}

# Legacy format header: starts directly with "Algorithm,"
/^Algorithm,/ {
    if (!header_printed) {
        line = $0
        sub(/,$/, "", line)
        print line
        header_printed = 1
    }
    next
}

# New format data rows: start with unquoted type token (e.g. "asym,")
# followed by the algorithm name. The type token is a short lowercase word.
/^[a-z][a-z]*,[A-Z]/ {
    # Strip the leading type field and emit the rest (stripped of trailing comma)
    line = $0
    sub(/^[^,]*,/, "", line)
    sub(/,$/, "", line)
    print line
    next
}

# Legacy format data rows: at least 5 comma-separated fields, field 2 is
# a numeric key size (e.g. 128, 192, 256, 44, 65, 87).
{
    n = split($0, fields, ",")
    if (n >= 5 && fields[2] ~ /^[[:space:]]*[0-9][0-9]*[[:space:]]*$/) {
        line = $0
        sub(/,$/, "", line)
        print line
    }
    # All other lines (banners, totals, section headings) are silently discarded
}
' "$RAW_CSV" > "$OUTPUT_FILE"

DATA_ROWS="$(awk 'NR > 1' "$OUTPUT_FILE" | wc -l | tr -d ' ')"
echo "  CSV rows written: $DATA_ROWS data rows + 1 header"
echo "  Output: $OUTPUT_FILE"
echo "  Log:    $LOG_FILE"
echo ""

# ---------------------------------------------------------------------------
# Final status
# ---------------------------------------------------------------------------
if [ "$BENCH_FAILURES" -gt 0 ]; then
    echo "WARNING: $BENCH_FAILURES benchmark run(s) exited non-zero." >&2
    echo "  Check $LOG_FILE for details." >&2
    echo "  Partial CSV results written to $OUTPUT_FILE" >&2
    exit 3
fi

echo "All benchmarks complete. $DATA_ROWS algorithm/operation rows written to $OUTPUT_FILE"
exit 0
