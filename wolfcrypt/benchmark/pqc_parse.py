#!/usr/bin/env python3
"""
pqc_parse.py — Normalize wolfSSL PQC benchmark CSV for publication.

Takes the CSV produced by pqc_bench.sh and emits clean, publication-ready
output in one of two formats:

  --format=wolfssl (default)
    Pipe-aligned CSV with a Library column prepended.
    Columns: Library, Algorithm, Operation, ops/sec, avg_ms, ops, secs
             [, heap_bytes, heap_allocs, stack_bytes]

  --format=pqcleo
    Pipe-delimited format matching PQC-LEO's parser expectations:
    Algorithm | Operation | Operations | Seconds | ms/op | op/sec
    (memory columns dropped — PQC-LEO memory is from Valgrind massif)

USAGE:
  python3 pqc_parse.py [OPTIONS] INPUT_CSV

OPTIONS:
  --format FORMAT    Output format: wolfssl (default) or pqcleo
  --library NAME     Library name for wolfssl format (default: wolfSSL)
  --output FILE      Write to FILE instead of stdout
  --help             Print this help and exit

EXAMPLES:
  python3 pqc_parse.py pqc_results.csv
  python3 pqc_parse.py --format=pqcleo --output=results.psv pqc_results.csv

INPUT FORMAT:
  The script accepts the CSV produced by pqc_bench.sh in both its supported
  output variants:
    - With GENERATE_MACHINE_PARSEABLE_REPORT + cycles columns (12 fields):
        Algorithm,key size,operation,avg ms,ops/sec,ops,secs,cycles,cycles/op,
        heap_bytes,heap_allocs,stack_bytes
    - Without cycles (8 fields, older build):
        Algorithm,key size,operation,avg ms,ops/sec,heap_bytes,heap_allocs,
        stack_bytes
    - Minimal (5 fields, no memory tracking):
        Algorithm,key size,operation,avg ms,ops/sec

  Memory columns are optional; missing columns are reported as empty strings.
"""

import argparse
import csv
import re
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# Algorithm name normalisation
# ---------------------------------------------------------------------------
# wolfSSL benchmark output uses internal names that differ from NIST names.
# These maps translate what the benchmark binary actually emits.

# ML-KEM: "ML-KEM 512 " (trailing space), key size in separate column.
# We reconstruct "ML-KEM-<keysize>" from the algorithm + key-size fields.
_MLKEM_RE = re.compile(r"ML-KEM\s+(\d+)\s*$", re.IGNORECASE)

# ML-DSA: algorithm field is "ML-DSA", key-size field is security level (44/65/87).
_MLDSA_RE = re.compile(r"ML-DSA\s*$", re.IGNORECASE)

# SLH-DSA: algorithm field is "SLH-DSA-S" (small) or "SLH-DSA-F" (fast),
# key-size field is the security category (128/192/256).
# NIST name: SLH-DSA-SHAKE-<category><size_char>
#   S → s (small), F → f (fast)
_SLHDSA_RE = re.compile(r"SLH-DSA-([SF])\s*$", re.IGNORECASE)

# Legacy Dilithium names (in case an older wolfSSL build is used):
# "DILITHIUM" with key-size field being the security level.
_DILITHIUM_RE = re.compile(r"DILITHIUM\s*$", re.IGNORECASE)


def normalise_algorithm(raw_algo: str, raw_keysize: str) -> str:
    """
    Convert wolfSSL benchmark algorithm + key-size fields to a canonical
    NIST/IETF algorithm name.

    Returns the normalised name as a string, or the original (stripped) name
    if no normalisation rule applies (future-proofing for new algorithms).
    """
    algo = raw_algo.strip()
    keysize = raw_keysize.strip()

    m = _MLKEM_RE.match(algo)
    if m:
        # benchmark already encodes the security level in the name;
        # the key-size column is the same value. Use the name field.
        return f"ML-KEM-{m.group(1)}"

    if _MLDSA_RE.match(algo):
        # key-size field is the security level (44, 65, 87)
        return f"ML-DSA-{keysize}"

    m = _SLHDSA_RE.match(algo)
    if m:
        size_char = m.group(1).lower()  # 's' or 'f'
        return f"SLH-DSA-SHAKE-{keysize}{size_char}"

    if _DILITHIUM_RE.match(algo):
        # Legacy name from older wolfSSL builds
        return f"ML-DSA-{keysize}"

    # Unknown algorithm: return stripped name unchanged so we don't silently
    # drop data from future wolfSSL versions that add new algorithms.
    return algo


# ---------------------------------------------------------------------------
# Operation label normalisation
# ---------------------------------------------------------------------------
# wolfSSL uses slightly different operation names than the PQC-LEO convention.

_OP_MAP = {
    "key gen":  "keygen",    # KEM and SIG key generation
    "gen":      "keygen",    # SLH-DSA uses 'gen' instead of 'key gen'
    "encap":    "encaps",    # KEM encapsulation
    "decap":    "decaps",    # KEM decapsulation
    "sign":     "sign",
    "verify":   "verify",
    # SLH-DSA extended operations (pre-hash and message variants)
    # Pass through with minor normalisation so the output remains valid.
    "sign-msg": "sign-msg",
    "vrfy-msg": "verify-msg",
    "sign-pre": "sign-pre",
    "vrfy-pre": "verify-pre",
}


def normalise_operation(raw_op: str) -> str:
    """Normalise a wolfSSL operation label to canonical form."""
    op = raw_op.strip()
    return _OP_MAP.get(op, op)  # unknown ops pass through unchanged


# ---------------------------------------------------------------------------
# CSV column layout detection
# ---------------------------------------------------------------------------
# pqc_bench.sh can produce two column layouts depending on build flags:
#
#   Layout A (GENERATE_MACHINE_PARSEABLE_REPORT, 12 fields):
#     Algorithm, key size, operation, avg ms, ops/sec,
#     ops, secs, cycles, cycles/op, heap_bytes, heap_allocs, stack_bytes
#
#   Layout B (plain -csv, 8 fields):
#     Algorithm, key size, operation, avg ms, ops/sec,
#     heap_bytes, heap_allocs, stack_bytes
#
#   Layout C (minimal, 5 fields, no memory tracking):
#     Algorithm, key size, operation, avg ms, ops/sec

def detect_layout(header: list[str]) -> dict:
    """
    Given the parsed header row, return a dict mapping logical field names to
    column indices.  Returns None for fields not present in this layout.

    All header matching is case-insensitive and strips whitespace.
    """
    h = [f.strip().lower() for f in header]

    def idx(name: str) -> Optional[int]:
        try:
            return h.index(name)
        except ValueError:
            return None

    layout = {
        "algorithm":   idx("algorithm"),
        "key_size":    idx("key size"),
        "operation":   idx("operation"),
        "avg_ms":      idx("avg ms"),
        "ops_per_sec": idx("ops/sec"),
        "ops":         idx("ops"),
        "secs":        idx("secs"),
        "cycles":      idx("cycles"),
        "cycles_per_op": idx("cycles/op"),
        "heap_bytes":  idx("heap_bytes"),
        "heap_allocs": idx("heap_allocs"),
        "stack_bytes": idx("stack_bytes"),
    }

    # Validate that mandatory fields are present
    mandatory = ("algorithm", "key_size", "operation", "avg_ms", "ops_per_sec")
    for field in mandatory:
        if layout[field] is None:
            raise ValueError(
                f"Input CSV is missing required column '{field}'. "
                f"Got columns: {header}"
            )

    return layout


def get_field(row: list[str], layout: dict, field: str, default: str = "") -> str:
    """Extract a field from a row using the pre-computed layout, or return default."""
    idx = layout.get(field)
    if idx is None or idx >= len(row):
        return default
    return row[idx].strip()


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def write_wolfssl_format(rows, layout: dict, library: str, out):
    """
    Write normalised wolfssl CSV format.

    Columns: Library, Algorithm, Operation, ops/sec, avg_ms, ops, secs
             [, heap_bytes, heap_allocs, stack_bytes]

    Memory columns are omitted if they were not present in the input.
    """
    has_memory = layout["heap_bytes"] is not None
    has_timing = layout["ops"] is not None

    header = ["Library", "Algorithm", "Operation", "ops/sec", "avg_ms"]
    if has_timing:
        header += ["ops", "secs"]
    if has_memory:
        header += ["heap_bytes", "heap_allocs", "stack_bytes"]

    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)

    for row in rows:
        raw_algo = get_field(row, layout, "algorithm")
        raw_keysize = get_field(row, layout, "key_size")
        raw_op = get_field(row, layout, "operation")

        algorithm = normalise_algorithm(raw_algo, raw_keysize)
        operation = normalise_operation(raw_op)
        ops_per_sec = get_field(row, layout, "ops_per_sec")
        avg_ms = get_field(row, layout, "avg_ms")

        out_row = [library, algorithm, operation, ops_per_sec, avg_ms]

        if has_timing:
            out_row.append(get_field(row, layout, "ops"))
            out_row.append(get_field(row, layout, "secs"))

        if has_memory:
            out_row.append(get_field(row, layout, "heap_bytes"))
            out_row.append(get_field(row, layout, "heap_allocs"))
            out_row.append(get_field(row, layout, "stack_bytes"))

        writer.writerow(out_row)


def write_pqcleo_format(rows, layout: dict, out):
    """
    Write PQC-LEO pipe-delimited format for cross-library comparison.

    PQC-LEO parser expects:
      Algorithm | Operation | Operations | Seconds | ms/op | op/sec

    Memory columns are dropped (PQC-LEO memory comes from Valgrind massif,
    which is incompatible with wolfSSL's inline allocation tracking).
    """
    # PQC-LEO uses pipe delimiter with spaces: " | "
    sep = " | "

    def write_row(fields):
        out.write(sep.join(str(f) for f in fields) + "\n")

    write_row(["Algorithm", "Operation", "Operations", "Seconds", "ms/op", "op/sec"])

    for row in rows:
        raw_algo = get_field(row, layout, "algorithm")
        raw_keysize = get_field(row, layout, "key_size")
        raw_op = get_field(row, layout, "operation")

        algorithm = normalise_algorithm(raw_algo, raw_keysize)
        operation = normalise_operation(raw_op)
        ops_per_sec = get_field(row, layout, "ops_per_sec")
        avg_ms = get_field(row, layout, "avg_ms")
        ops = get_field(row, layout, "ops", default="")
        secs = get_field(row, layout, "secs", default="")

        write_row([algorithm, operation, ops, secs, avg_ms, ops_per_sec])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[1].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.split("\n")[1:]),
    )
    parser.add_argument(
        "input",
        metavar="INPUT_CSV",
        help="CSV file produced by pqc_bench.sh (use '-' for stdin)",
    )
    parser.add_argument(
        "--format",
        choices=("wolfssl", "pqcleo"),
        default="wolfssl",
        help="Output format: wolfssl (default) or pqcleo",
    )
    parser.add_argument(
        "--library",
        default="wolfSSL",
        help="Library name for wolfssl format (default: wolfSSL)",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output file (default: stdout)",
    )
    args = parser.parse_args()

    # Open input
    if args.input == "-":
        in_file = sys.stdin
    else:
        try:
            in_file = open(args.input, newline="", encoding="utf-8")
        except OSError as e:
            print(f"ERROR: Cannot open input file: {e}", file=sys.stderr)
            sys.exit(1)

    # Open output
    if args.output == "-":
        out_file = sys.stdout
    else:
        try:
            out_file = open(args.output, "w", encoding="utf-8")
        except OSError as e:
            print(f"ERROR: Cannot open output file: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        reader = csv.reader(in_file)

        # Read and parse header
        try:
            header = next(reader)
        except StopIteration:
            print("ERROR: Input CSV is empty (no header row)", file=sys.stderr)
            sys.exit(1)

        try:
            layout = detect_layout(header)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        # Read all data rows (skip blank lines)
        data_rows = [row for row in reader if any(f.strip() for f in row)]

        if not data_rows:
            print("WARNING: Input CSV has a header but no data rows", file=sys.stderr)

        # Emit in requested format
        if args.format == "wolfssl":
            write_wolfssl_format(data_rows, layout, args.library, out_file)
        else:
            write_pqcleo_format(data_rows, layout, out_file)

    finally:
        if in_file is not sys.stdin:
            in_file.close()
        if out_file is not sys.stdout:
            out_file.close()

    sys.exit(0)


if __name__ == "__main__":
    main()
