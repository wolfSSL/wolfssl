#!/bin/sh
#
# test_gen_crt_bundle.sh
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# Run gen_crt_bundle.py for each Kconfig bundle mode, as the ESP-IDF
# CMakeLists.txt does, and check the certificate count in the output.
#
# Requires python with the cryptography package (e.g. after ESP-IDF export.sh).
# Usage: test_gen_crt_bundle.sh [python]

DIR=$(cd "$(dirname "$0")" && pwd)
PY=${1:-python3}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

# Number of certificates in the given PEM files.
pem_count() {
    cat "$@" | grep -c -- "-----BEGIN CERTIFICATE-----"
}

# run_mode <name> <expected count> <gen_crt_bundle.py args...>
run_mode() {
    NAME=$1
    EXPECT=$2
    shift 2
    rm -f "$WORK/x509_crt_bundle_wolfssl"
    if ! (cd "$WORK" && "$PY" "$DIR/gen_crt_bundle.py" -q "$@"); then
        echo "FAIL $NAME: gen_crt_bundle.py exited non-zero"
        FAILED=1
        return
    fi
    # The bundle starts with a big-endian 16-bit certificate count.
    # shellcheck disable=SC2046 # split od output into the two bytes
    set -- $(od -An -tu1 -N2 "$WORK/x509_crt_bundle_wolfssl")
    GOT=$(( $1 * 256 + $2 ))
    if [ "$GOT" -ne "$EXPECT" ]; then
        echo "FAIL $NAME: $GOT certificates, expected $EXPECT"
        FAILED=1
    else
        echo "ok   $NAME: $GOT certificates"
    fi
}

ALL="$DIR/cacrt_all.pem"
LOCAL="$DIR/cacrt_local.pem"
DEPRECATED="$DIR/cacrt_deprecated.pem"
CSV="$DIR/cmn_crt_authorities.csv"

N_ALL=$(pem_count "$ALL")
N_LOCAL=$(pem_count "$LOCAL")
N_DEPRECATED=$(pem_count "$DEPRECATED")
# Every distinct name in the CSV's second column must match one cert in
# cacrt_all.pem. Count them the way gen_crt_bundle.py reads them.
N_CMN=$("$PY" -c 'import csv, sys
rows = csv.reader(open(sys.argv[1], encoding="utf-8"))
next(rows)
print(len({row[1] for row in rows if row}))' "$CSV")

# The roots excluded on purpose (see README.md) must not be in any input.
# The old Firmaprofesional root shares its name with the current one; the
# host test's order check catches a duplicate name instead.
for pem in "$ALL" "$LOCAL" "$DEPRECATED"; do
    openssl crl2pkcs7 -nocrl -certfile "$pem" |
        openssl pkcs7 -print_certs -noout
done > "$WORK/subjects"
# Without every subject, a missing name below would prove nothing.
N_SUBJECTS=$(grep -c '^subject=' "$WORK/subjects")
if [ "$N_SUBJECTS" -ne $(( N_ALL + N_LOCAL + N_DEPRECATED )) ]; then
    echo "FAIL read $N_SUBJECTS certificate subjects with openssl"
    FAILED=1
fi
for cn in "emSign ECC Root CA - G3" "AAA Certificate Services" \
          "E-Tugra Global Root CA RSA v3" "E-Tugra Global Root CA ECC v3" \
          "Entrust Root Certification Authority" \
          "Entrust Root Certification Authority - G2" \
          "Entrust Root Certification Authority - EC1" \
          "Entrust Root Certification Authority - G4" \
          "Entrust.net Certification Authority (2048)" \
          "AffirmTrust Commercial" "AffirmTrust Networking" \
          "AffirmTrust Premium" "AffirmTrust Premium ECC"; do
    if grep -q "^subject=.*CN *= *$cn\$" "$WORK/subjects"; then
        echo "FAIL excluded root is back: $cn"
        FAILED=1
    else
        echo "ok   excluded: $cn"
    fi
done

run_mode "FULL" $(( N_ALL + N_LOCAL )) \
    --input "$ALL" "$LOCAL"
run_mode "FULL+DEPRECATED" $(( N_ALL + N_LOCAL + N_DEPRECATED )) \
    --input "$ALL" "$LOCAL" "$DEPRECATED"
run_mode "CMN" $(( N_CMN + N_LOCAL )) \
    --input "$ALL" "$LOCAL" --filter "$CSV"
run_mode "CMN+DEPRECATED" $(( N_CMN + N_LOCAL + N_DEPRECATED )) \
    --input "$ALL" "$LOCAL" "$DEPRECATED" --filter "$CSV"

# reject <name> <gen_crt_bundle.py args...>: generation must fail rather than
# drop roots.
reject() {
    NAME=$1
    shift
    if (cd "$WORK" && "$PY" "$DIR/gen_crt_bundle.py" -q "$@") \
            > /dev/null 2>&1; then
        echo "FAIL $NAME was accepted"
        FAILED=1
    else
        echo "ok   rejected: $NAME"
    fi
}

# One name that matches nothing, next to all the real ones.
{ cat "$CSV"; printf 'nobody,No Such Root CA\n'; } > "$WORK/bad.csv"
reject "unmatched filter name" --input "$ALL" --filter "$WORK/bad.csv"
: > "$WORK/empty.pem"
reject "PEM input with no certificate" --input "$ALL" "$WORK/empty.pem"
# Only an empty cacrt_local.pem is allowed, not one with an unreadable cert.
mkdir "$WORK/local"
sed 's/^-----BEGIN CERTIFICATE-----$/& /' "$ALL" > "$WORK/local/cacrt_local.pem"
reject "unreadable cacrt_local.pem" --input "$ALL" "$WORK/local/cacrt_local.pem"

exit $FAILED
