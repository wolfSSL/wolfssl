#!/usr/bin/env python3
"""
pqc_parse.py — Normalize PQC benchmark output for publication.

Accepts output from wolfSSL, liboqs, OpenSSL, or CIRCL and emits
clean, publication-ready output with a consistent schema.

OUTPUT FORMATS (--format):
  wolfssl (default)
    CSV with Library column. Columns:
      Library, Algorithm, Operation, ops/sec, avg_ms
      [, ops, secs] [, heap_bytes, heap_allocs, stack_bytes]

  pqcleo
    Pipe-delimited format for PQC-LEO cross-library comparison:
      Algorithm | Operation | Operations | Seconds | ms/op | op/sec

INPUT FORMATS (--input-format):
  wolfssl (default)
    CSV produced by pqc_bench.sh. Supports 5, 8, and 12-column layouts.

  liboqs
    Text output of liboqs speed_kem / speed_sig binaries.
    Fixed-width table; algorithm name on a preceding header line.
    Example:
      ML-KEM-512
      keygen      | 12345 | 3.000 | 243.2 | ...
      encaps      | 12345 | 3.000 | 243.2 | ...
      decaps      | 12345 | 3.000 | 243.2 | ...

  openssl
    Machine-readable output of: openssl speed -mr -kem-algorithms
                                 openssl speed -mr -signature-algorithms
    Format: +R15:<count>:<alg>:<secs>  (KEM keygen)
            +R16:<count>:<alg>:<secs>  (KEM encaps)
            +R17:<count>:<alg>:<secs>  (KEM decaps)
            +R18:<count>:<alg>:<secs>  (SIG keygen)
            +R19:<count>:<alg>:<secs>  (SIG sign)
            +R20:<count>:<alg>:<secs>  (SIG verify)

  circl
    Output of: go test -bench=. -benchtime=5s ./kem/schemes/ ./sign/schemes/
    Format: BenchmarkGenerateKeyPair/ML-KEM-512   N   98765 ns/op
            BenchmarkEncapsulate/ML-KEM-512        N   98765 ns/op
            BenchmarkDecapsulate/ML-KEM-512        N   98765 ns/op
            BenchmarkGenerateKeyPair/ML-DSA-44     N   98765 ns/op
            BenchmarkSign/ML-DSA-44                N   98765 ns/op
            BenchmarkVerify/ML-DSA-44              N   98765 ns/op

USAGE:
  python3 pqc_parse.py [OPTIONS] INPUT

OPTIONS:
  --input-format FMT  Input format: wolfssl (default), liboqs, openssl, circl
  --format FMT        Output format: wolfssl (default) or pqcleo
  --library NAME      Library name override (default: auto-detected from input format)
  --output FILE       Write to FILE instead of stdout
  --help              Print this help and exit

EXAMPLES:
  python3 pqc_parse.py pqc_results.csv
  python3 pqc_parse.py --input-format=liboqs speed_kem.txt
  python3 pqc_parse.py --input-format=openssl --library=OpenSSL-3.5 openssl_speed.txt
  python3 pqc_parse.py --input-format=circl --format=pqcleo circl_bench.txt
"""

import argparse
import csv
import re
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# Canonical data record
# ---------------------------------------------------------------------------
# All input parsers produce a list of these dicts before the output
# formatters consume them.  Fields not available from a given input source
# are left as empty strings.

def make_record(
    library: str,
    algorithm: str,
    operation: str,
    ops_per_sec: str,
    avg_ms: str,
    ops: str = "",
    secs: str = "",
    heap_bytes: str = "",
    heap_allocs: str = "",
    stack_bytes: str = "",
) -> dict:
    return {
        "library":     library,
        "algorithm":   algorithm,
        "operation":   operation,
        "ops_per_sec": ops_per_sec,
        "avg_ms":      avg_ms,
        "ops":         ops,
        "secs":        secs,
        "heap_bytes":  heap_bytes,
        "heap_allocs": heap_allocs,
        "stack_bytes": stack_bytes,
    }


# ---------------------------------------------------------------------------
# Algorithm and operation name normalisation (shared across all parsers)
# ---------------------------------------------------------------------------

# wolfSSL emits "ML-KEM 512 " (space-separated, trailing space)
_WOLFSSL_MLKEM_RE  = re.compile(r"ML-KEM\s+(\d+)\s*$", re.IGNORECASE)
_WOLFSSL_MLDSA_RE  = re.compile(r"ML-DSA\s*$",         re.IGNORECASE)
_WOLFSSL_SLHDSA_RE = re.compile(r"SLH-DSA-([SF])\s*$", re.IGNORECASE)
_WOLFSSL_DILITH_RE = re.compile(r"DILITHIUM\s*$",       re.IGNORECASE)

# Canonical algorithm names already in NIST form (liboqs / OpenSSL / CIRCL)
_CANONICAL_RE = re.compile(
    r"^(ML-KEM-(512|768|1024)|ML-DSA-(44|65|87)|SLH-DSA-(SHA2|SHAKE)-(128|192|256)[sf])$",
    re.IGNORECASE,
)

def normalise_algorithm(raw_algo: str, raw_keysize: str = "") -> str:
    """
    Convert any benchmark tool's algorithm name to canonical NIST form.
    raw_keysize is only needed for wolfSSL's two-column format.
    """
    algo    = raw_algo.strip()
    keysize = raw_keysize.strip()

    # Already canonical (liboqs / OpenSSL / CIRCL emit NIST names)
    if _CANONICAL_RE.match(algo):
        return algo

    # wolfSSL internal names
    m = _WOLFSSL_MLKEM_RE.match(algo)
    if m:
        return f"ML-KEM-{m.group(1)}"

    if _WOLFSSL_MLDSA_RE.match(algo):
        return f"ML-DSA-{keysize}"

    m = _WOLFSSL_SLHDSA_RE.match(algo)
    if m:
        return f"SLH-DSA-SHAKE-{keysize}{m.group(1).lower()}"

    if _WOLFSSL_DILITH_RE.match(algo):
        return f"ML-DSA-{keysize}"

    # Pass through unknown names unchanged
    return algo


# Operation label map — normalise all source tool labels to canonical form
_OP_MAP = {
    # wolfSSL
    "key gen":   "keygen",
    "gen":       "keygen",
    "encap":     "encaps",
    "decap":     "decaps",
    "sign":      "sign",
    "verify":    "verify",
    "sign-msg":  "sign-msg",
    "vrfy-msg":  "verify-msg",
    "sign-pre":  "sign-pre",
    "vrfy-pre":  "verify-pre",
    # liboqs
    "keygen":    "keygen",
    "encaps":    "encaps",
    "decaps":    "decaps",
    "keypair":   "keygen",   # liboqs speed_sig uses "keypair"
    # OpenSSL / CIRCL already use canonical names mostly
    "generatekeypair": "keygen",
    "encapsulate":     "encaps",
    "decapsulate":     "decaps",
}

def normalise_operation(raw_op: str) -> str:
    op = raw_op.strip().lower()
    return _OP_MAP.get(op, raw_op.strip())


def _fmt_ops_per_sec(ops: float) -> str:
    return f"{ops:.3f}"

def _fmt_avg_ms(ms: float) -> str:
    return f"{ms:.3f}"


# ---------------------------------------------------------------------------
# wolfSSL input parser (existing CSV format)
# ---------------------------------------------------------------------------

def _detect_wolfssl_layout(header: list[str]) -> dict:
    h = [f.strip().lower() for f in header]

    def idx(name: str) -> Optional[int]:
        try:
            return h.index(name)
        except ValueError:
            return None

    layout = {
        "algorithm":     idx("algorithm"),
        "key_size":      idx("key size"),
        "operation":     idx("operation"),
        "avg_ms":        idx("avg ms"),
        "ops_per_sec":   idx("ops/sec"),
        "ops":           idx("ops"),
        "secs":          idx("secs"),
        "heap_bytes":    idx("heap_bytes"),
        "heap_allocs":   idx("heap_allocs"),
        "stack_bytes":   idx("stack_bytes"),
    }

    for field in ("algorithm", "key_size", "operation", "avg_ms", "ops_per_sec"):
        if layout[field] is None:
            raise ValueError(
                f"wolfSSL CSV missing required column '{field}'. Got: {header}"
            )
    return layout


def _get(row: list[str], layout: dict, field: str) -> str:
    i = layout.get(field)
    if i is None or i >= len(row):
        return ""
    return row[i].strip()


def parse_wolfssl(text: str, library: str) -> list[dict]:
    records = []
    reader = csv.reader(text.splitlines())
    header = None
    layout = None

    for row in reader:
        if not any(f.strip() for f in row):
            continue

        # New-format header: starts with quoted type + "Algorithm"
        if row[0].strip().strip('"').lower() in ("asym", "sym") and \
                len(row) > 1 and row[1].strip().lower() == "algorithm":
            # Strip leading type column
            row = row[1:]

        if header is None:
            if row[0].strip().lower() == "algorithm":
                header = [f.strip() for f in row]
                # Strip trailing comma artefact (empty last field)
                if header and header[-1] == "":
                    header = header[:-1]
                try:
                    layout = _detect_wolfssl_layout(header)
                except ValueError as e:
                    print(f"WARNING: {e}", file=sys.stderr)
                    return records
            continue

        # Data row: new format prefixes with type token, strip it
        if row[0].strip().lower() in ("asym", "sym"):
            row = row[1:]

        # Strip trailing empty field from wolfSSL's trailing-comma habit
        if row and row[-1].strip() == "":
            row = row[:-1]

        if len(row) < 5:
            continue

        algo    = normalise_algorithm(_get(row, layout, "algorithm"),
                                      _get(row, layout, "key_size"))
        op      = normalise_operation(_get(row, layout, "operation"))
        ops_sec = _get(row, layout, "ops_per_sec")
        avg_ms  = _get(row, layout, "avg_ms")

        records.append(make_record(
            library=library, algorithm=algo, operation=op,
            ops_per_sec=ops_sec, avg_ms=avg_ms,
            ops=_get(row, layout, "ops"),
            secs=_get(row, layout, "secs"),
            heap_bytes=_get(row, layout, "heap_bytes"),
            heap_allocs=_get(row, layout, "heap_allocs"),
            stack_bytes=_get(row, layout, "stack_bytes"),
        ))
    return records


# ---------------------------------------------------------------------------
# liboqs input parser
# ---------------------------------------------------------------------------
# Output format from speed_kem / speed_sig:
#
#   Started at ...
#   Operation                            | Iterations |  Total time (s) | Time (us): mean | pop. stdev | cycles/op | pop. stdev
#   ------------------------------------ | ----------:| ---------------:| ---------------:| ----------:| ---------:| ----------:
#   ML-KEM-512
#   keygen                               |      12345 |           3.000 |          243.18 |       1.23 |    ...    |    ...
#   encaps                               |      12345 |           3.000 |          243.18 |       1.23 |    ...    |    ...
#   decaps                               |      12345 |           3.000 |          243.18 |       1.23 |    ...    |    ...
#
# Algorithm name appears on its own line immediately before its operations.
# The table header line contains "Iterations" (used for detection).
# Data lines have the operation name in column 0, iteration count in col 1,
# total time (s) in col 2, mean time (us) in col 3.

_LIBOQS_HEADER_RE = re.compile(r"Iterations", re.IGNORECASE)
# A data row: starts with an operation name word, then pipe-separated numbers.
# Operation names: keygen, encaps, decaps, keypair, sign, verify, fullcycle...
_LIBOQS_DATA_RE = re.compile(
    r"^\s*(\w[\w\-]*)\s*\|\s*(\d+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)"
)
# Algorithm header line: a non-empty line that is NOT the column header,
# NOT a separator (---), and does NOT contain a pipe character.
_LIBOQS_ALG_RE = re.compile(r"^[A-Z][\w\-]+$")


def parse_liboqs(text: str, library: str) -> list[dict]:
    records = []
    current_alg = None
    in_table = False

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        # Table header
        if _LIBOQS_HEADER_RE.search(line):
            in_table = True
            continue

        # Separator line
        if re.match(r"^[-| ]+$", line):
            continue

        # Algorithm name line (no pipe, matches algo pattern)
        if "|" not in line and _LIBOQS_ALG_RE.match(line):
            current_alg = normalise_algorithm(line)
            continue

        # Data row
        if in_table and current_alg:
            m = _LIBOQS_DATA_RE.match(line)
            if m:
                op_raw      = m.group(1)
                iterations  = m.group(2)
                total_secs  = float(m.group(3))
                mean_us     = float(m.group(4))
                avg_ms      = mean_us / 1000.0
                ops_per_sec = 1_000_000.0 / mean_us if mean_us > 0 else 0.0

                op = normalise_operation(op_raw)
                # Skip fullcycle / fullcycletest rows — not a primitive operation
                if "fullcycle" in op.lower():
                    continue

                records.append(make_record(
                    library=library,
                    algorithm=current_alg,
                    operation=op,
                    ops_per_sec=_fmt_ops_per_sec(ops_per_sec),
                    avg_ms=_fmt_avg_ms(avg_ms),
                    ops=iterations,
                    secs=f"{total_secs:.3f}",
                ))

    return records


# ---------------------------------------------------------------------------
# OpenSSL input parser (-mr machine-readable output)
# ---------------------------------------------------------------------------
# +R15:<count>:<alg>:<secs>  — KEM keygen
# +R16:<count>:<alg>:<secs>  — KEM encaps
# +R17:<count>:<alg>:<secs>  — KEM decaps
# +R18:<count>:<alg>:<secs>  — SIG keygen
# +R19:<count>:<alg>:<secs>  — SIG sign
# +R20:<count>:<alg>:<secs>  — SIG verify

_OPENSSL_MR_RE = re.compile(r"^\+R(1[5-9]|20):(\d+):([^:]+):([\d.]+)")
_OPENSSL_OP_MAP = {
    "15": "keygen",   # KEM keygen
    "16": "encaps",   # KEM encaps
    "17": "decaps",   # KEM decaps
    "18": "keygen",   # SIG keygen
    "19": "sign",     # SIG sign
    "20": "verify",   # SIG verify
}


def parse_openssl(text: str, library: str) -> list[dict]:
    records = []
    for line in text.splitlines():
        m = _OPENSSL_MR_RE.match(line.strip())
        if not m:
            continue
        rtype  = m.group(1)
        count  = int(m.group(2))
        alg    = m.group(3).strip()
        secs   = float(m.group(4))

        op = _OPENSSL_OP_MAP.get(rtype, "unknown")
        avg_ms      = (secs / count * 1000.0) if count > 0 else 0.0
        ops_per_sec = count / secs if secs > 0 else 0.0
        algorithm   = normalise_algorithm(alg)

        records.append(make_record(
            library=library,
            algorithm=algorithm,
            operation=op,
            ops_per_sec=_fmt_ops_per_sec(ops_per_sec),
            avg_ms=_fmt_avg_ms(avg_ms),
            ops=str(count),
            secs=f"{secs:.3f}",
        ))
    return records


# ---------------------------------------------------------------------------
# CIRCL input parser (go test -bench output)
# ---------------------------------------------------------------------------
# Format: BenchmarkGenerateKeyPair/ML-KEM-512-8    1234    98765 ns/op
# The "-8" suffix is the GOMAXPROCS value; strip it.
# Benchmark function names map to operations:
#   BenchmarkGenerateKeyPair -> keygen
#   BenchmarkEncapsulate     -> encaps
#   BenchmarkDecapsulate     -> decaps
#   BenchmarkEncap           -> encaps  (alternate naming)
#   BenchmarkDecap           -> decaps
#   BenchmarkSign            -> sign
#   BenchmarkVerify          -> verify

_CIRCL_LINE_RE = re.compile(
    r"^Benchmark(\w+)/([^\s]+)\s+(\d+)\s+([\d.]+)\s+ns/op"
)
_CIRCL_OP_MAP = {
    "GenerateKeyPair": "keygen",
    "Encapsulate":     "encaps",
    "Decapsulate":     "decaps",
    "Encap":           "encaps",
    "Decap":           "decaps",
    "Sign":            "sign",
    "Verify":          "verify",
    "KeyGen":          "keygen",
    "KeyGenerate":     "keygen",
}
# GOMAXPROCS suffix: "-N" at end of algorithm name
_CIRCL_GOMAXPROCS_RE = re.compile(r"-\d+$")


def parse_circl(text: str, library: str) -> list[dict]:
    records = []
    for line in text.splitlines():
        m = _CIRCL_LINE_RE.match(line.strip())
        if not m:
            continue
        bench_fn = m.group(1)          # e.g. "GenerateKeyPair"
        alg_raw  = m.group(2)          # e.g. "ML-KEM-512-8"
        iters    = int(m.group(3))
        ns_per   = float(m.group(4))   # nanoseconds per operation

        # Strip GOMAXPROCS suffix from algorithm name
        alg_clean = _CIRCL_GOMAXPROCS_RE.sub("", alg_raw)
        algorithm = normalise_algorithm(alg_clean)

        op = _CIRCL_OP_MAP.get(bench_fn)
        if op is None:
            # Unknown benchmark function — skip rather than emit garbage
            continue

        avg_ms      = ns_per / 1_000_000.0
        ops_per_sec = 1_000_000_000.0 / ns_per if ns_per > 0 else 0.0

        records.append(make_record(
            library=library,
            algorithm=algorithm,
            operation=op,
            ops_per_sec=_fmt_ops_per_sec(ops_per_sec),
            avg_ms=_fmt_avg_ms(avg_ms),
            ops=str(iters),
            secs=_fmt_avg_ms(iters * ns_per / 1e9),
        ))
    return records


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

# Algorithms we care about — filter out unrelated ones when present
_PQC_ALGO_RE = re.compile(
    r"^(ML-KEM|ML-DSA|SLH-DSA)", re.IGNORECASE
)

def _is_pqc(record: dict) -> bool:
    return bool(_PQC_ALGO_RE.match(record["algorithm"]))


def write_wolfssl_format(records: list[dict], out) -> None:
    """
    Normalised wolfssl CSV.
    Columns: Library, Algorithm, Operation, ops/sec, avg_ms
             [, ops, secs] [, heap_bytes, heap_allocs, stack_bytes]
    Memory columns are included only if at least one record has them.
    """
    has_timing = any(r["ops"] for r in records)
    has_memory = any(r["heap_bytes"] for r in records)

    header = ["Library", "Algorithm", "Operation", "ops/sec", "avg_ms"]
    if has_timing:
        header += ["ops", "secs"]
    if has_memory:
        header += ["heap_bytes", "heap_allocs", "stack_bytes"]

    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)

    for r in records:
        if not _is_pqc(r):
            continue
        row = [r["library"], r["algorithm"], r["operation"],
               r["ops_per_sec"], r["avg_ms"]]
        if has_timing:
            row += [r["ops"], r["secs"]]
        if has_memory:
            row += [r["heap_bytes"], r["heap_allocs"], r["stack_bytes"]]
        writer.writerow(row)


def write_pqcleo_format(records: list[dict], out) -> None:
    """PQC-LEO pipe-delimited format."""
    sep = " | "

    def wr(fields):
        out.write(sep.join(str(f) for f in fields) + "\n")

    wr(["Algorithm", "Operation", "Operations", "Seconds", "ms/op", "op/sec"])
    for r in records:
        if not _is_pqc(r):
            continue
        wr([r["algorithm"], r["operation"], r["ops"],
            r["secs"], r["avg_ms"], r["ops_per_sec"]])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_DEFAULT_LIBRARY = {
    "wolfssl": "wolfSSL",
    "liboqs":  "liboqs",
    "openssl": "OpenSSL",
    "circl":   "CIRCL",
}


def main():
    parser = argparse.ArgumentParser(
        description="Normalize PQC benchmark output for publication.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "input", metavar="INPUT",
        help="Input file (use '-' for stdin)",
    )
    parser.add_argument(
        "--input-format",
        choices=("wolfssl", "liboqs", "openssl", "circl"),
        default="wolfssl",
        help="Input format (default: wolfssl)",
    )
    parser.add_argument(
        "--format",
        choices=("wolfssl", "pqcleo"),
        default="wolfssl",
        help="Output format (default: wolfssl)",
    )
    parser.add_argument(
        "--library",
        default=None,
        help="Library name override (default: auto from --input-format)",
    )
    parser.add_argument(
        "--output", default="-",
        help="Output file (default: stdout)",
    )
    args = parser.parse_args()

    library = args.library or _DEFAULT_LIBRARY[args.input_format]

    # Open input
    if args.input == "-":
        text = sys.stdin.read()
    else:
        try:
            with open(args.input, encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            print(f"ERROR: Cannot open input: {e}", file=sys.stderr)
            sys.exit(1)

    # Parse
    parsers = {
        "wolfssl": parse_wolfssl,
        "liboqs":  parse_liboqs,
        "openssl": parse_openssl,
        "circl":   parse_circl,
    }
    records = parsers[args.input_format](text, library)

    if not records:
        print("WARNING: no records parsed from input", file=sys.stderr)

    # Open output
    if args.output == "-":
        out = sys.stdout
        _write_and_close = False
    else:
        try:
            out = open(args.output, "w", encoding="utf-8")
            _write_and_close = True
        except OSError as e:
            print(f"ERROR: Cannot open output: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        if args.format == "wolfssl":
            write_wolfssl_format(records, out)
        else:
            write_pqcleo_format(records, out)
    finally:
        if _write_and_close:
            out.close()

    sys.exit(0)


if __name__ == "__main__":
    main()
