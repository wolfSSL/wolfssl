#!/usr/bin/env bash
#
# gen-crl-fixtures.sh
#
# Regenerates tests/api/test_certman_crl_fixtures.h: the certificates, keys and
# CRLs used by the CRL key rollover, CRL-only key, trust anchor and chain walk
# tests in tests/api/test_certman.c and tests/unit-mcdc/test_crl_whitebox.c.
#
# Needs only bash and OpenSSL 3.0 or later (for -crl_lastupdate and
# -crl_nextupdate). Everything is built in a temporary directory; the header is
# the only output. Keys are new on every run, so the whole header changes.
#
# Run from anywhere:
#   ./certs/crl/gen/gen-crl-fixtures.sh

set -euo pipefail

OPENSSL=${OPENSSL:-openssl}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../../.." && pwd)
OUT="$ROOT_DIR/tests/api/test_certman_crl_fixtures.h"

START=20260101000000Z
END=20460101000000Z
EXPIRING=20300101000000Z

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

cat > "$T/ca.cnf" <<EOF
[ ca ]
default_ca = fx

[ fx ]
dir            = $T/db
database       = \$dir/index.txt
new_certs_dir  = \$dir/new
serial         = \$dir/serial
crlnumber      = \$dir/crlnumber
default_md     = sha256
policy         = policy_any
unique_subject = no
email_in_dn    = no

[ policy_any ]
commonName = supplied

[ req ]
distinguished_name = req_dn
prompt             = no

[ req_dn ]
CN = unused

# Root or intermediate CA.
[ ext_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

# Same name as the root, signs CRLs only.
[ ext_crl_only ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

# OpenSSL 3 adds a SKID and AKID unless told "none".
[ ext_leaf ]
basicConstraints       = critical, CA:FALSE
subjectKeyIdentifier   = none
authorityKeyIdentifier = keyid:always

[ ext_leaf_skid ]
basicConstraints       = critical, CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_leaf_no_akid ]
basicConstraints       = critical, CA:FALSE
subjectKeyIdentifier   = none
authorityKeyIdentifier = none

[ crl_akid ]
authorityKeyIdentifier = keyid:always

[ crl_no_akid ]
EOF

die() {
    echo "gen-crl-fixtures.sh: $*" >&2
    exit 1
}

reset_db() {
    rm -rf "$T/db"
    mkdir -p "$T/db/new"
    : > "$T/db/index.txt"
    echo "unique_subject = no" > "$T/db/index.txt.attr"
}

newkey() {
    "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$T/$1.key"
}

# newkey_row <name> <row>
# wolfSSL puts a CA in caTable[] row (first 4 SKID bytes) % CA_TABLE_SIZE (11),
# and GetCAByName() scans rows in order. The tests rely on which same-name CA a
# name lookup finds first, so each CA key is regenerated until it lands in a
# fixed row.
newkey_row() {
    local name=$1 row=$2 skid

    while :; do
        newkey "$name"
        # Prints a header line, then the SKID as hex with colons.
        skid=$("$OPENSSL" req -new -x509 -key "$T/$name.key" -subj /CN=row \
            -config "$T/ca.cnf" -addext subjectKeyIdentifier=hash \
            -days 1 2>/dev/null \
            | "$OPENSSL" x509 -noout -ext subjectKeyIdentifier)
        skid=${skid##*$'\n'}
        skid=${skid//[[:space:]:]/}
        if [ $(( 16#${skid:0:8} % 11 )) -eq "$row" ]; then
            break
        fi
    done
}

# cert <name> <CN> <subject key> <issuer cert|-> <issuer key> <serial> <ext>
# Issuer cert "-" makes a self-signed cert. Writes $T/<name>.pem and .der.
cert() {
    local name=$1 cn=$2 key=$3 issuer=$4 ikey=$5 serial=$6 ext=$7
    local -a signer

    reset_db
    echo "$serial" > "$T/db/serial"
    "$OPENSSL" req -new -config "$T/ca.cnf" -key "$T/$key.key" \
        -subj "/CN=$cn" -out "$T/$name.csr"
    if [ "$issuer" = "-" ]; then
        signer=(-selfsign -keyfile "$T/$key.key")
    else
        signer=(-cert "$T/$issuer.pem" -keyfile "$T/$ikey.key")
    fi
    "$OPENSSL" ca -batch -notext -config "$T/ca.cnf" "${signer[@]}" \
        -in "$T/$name.csr" -extensions "$ext" \
        -startdate "$START" -enddate "$END" -out "$T/$name.pem" 2>/dev/null \
        || die "issuing $name failed"
    "$OPENSSL" x509 -in "$T/$name.pem" -outform der -out "$T/$name.der"
}

# crl <name> <issuer cert> <issuer key> <CRL number> <next update> <exts>
#     [revoked serial...]
# Serials are even-length hex. Writes $T/<name>.pem and .der.
crl() {
    local name=$1 issuer=$2 ikey=$3 num=$4 next=$5 exts=$6
    local s

    shift 6
    reset_db
    echo "$num" > "$T/db/crlnumber"
    for s in "$@"; do
        printf 'R\t460101000000Z\t260101000000Z\t%s\tunknown\t/CN=revoked\n' \
            "$s" >> "$T/db/index.txt"
    done
    "$OPENSSL" ca -batch -config "$T/ca.cnf" -gencrl \
        -cert "$T/$issuer.pem" -keyfile "$T/$ikey.key" -crlexts "$exts" \
        -crl_lastupdate "$START" -crl_nextupdate "$next" \
        -out "$T/$name.pem" 2>/dev/null || die "generating $name failed"
    "$OPENSSL" crl -in "$T/$name.pem" -outform der -out "$T/$name.der"
}

# Change one base64 character inside the CRL signature. The second-to-last
# 4-character group decodes to 3 bytes near the end of the DER, inside the
# signature's s INTEGER, so the CRL still parses but no longer verifies.
corrupt_sig() {
    local in=$1 out=$2 line b64="" i c

    while IFS= read -r line; do
        case $line in
            -----*) ;;
            *) b64+=$line ;;
        esac
    done < "$in"
    i=$(( ${#b64} - 8 ))
    c=${b64:i:1}
    if [ "$c" = "A" ]; then c=B; else c=A; fi
    b64=${b64:0:i}$c${b64:i+1}
    {
        echo "-----BEGIN X509 CRL-----"
        for (( i = 0; i < ${#b64}; i += 64 )); do
            echo "${b64:i:64}"
        done
        echo "-----END X509 CRL-----"
    } > "$out"
}

# --- Keys ---------------------------------------------------------------------

# CA rows: new root (4) before old root (5), and the CRL-only key (0) before
# both; crl-anchor-int key 2 (2) before key 3 (4) before key 1 (10).
newkey_row root_old     5
newkey_row root_new     4
newkey_row crl_only     0
newkey_row int          7
newkey_row cycle_a      3
newkey_row cycle_b      7
newkey_row cycle_c      8
newkey_row anchor_root1 2
newkey_row anchor_root2 2
newkey_row anchor_k1    10
newkey_row anchor_k2    2
newkey_row anchor_k3    4
newkey leaf
newkey stray
"$OPENSSL" ec -in "$T/leaf.key" -outform der -out "$T/fxLeafKey.der" \
    2>/dev/null

# --- Rollover: one CA name, CN=crl-rollover-root, several keys ----------------

R=crl-rollover-root
cert fxRootOld    "$R" root_old -         -        01 ext_ca
cert fxRootNew    "$R" root_new -         -        02 ext_ca
cert fxCrlOnlyKey "$R" crl_only fxRootOld root_old 03 ext_crl_only
cert fxIntCa crl-rollover-int int fxRootOld root_old 30 ext_ca
cert fxLeafOld   crl-rollover-leaf-old   leaf fxRootOld root_old 10 ext_leaf
cert fxLeafNew   crl-rollover-leaf-new   leaf fxRootNew root_new 20 ext_leaf
cert fxLeafNoAkid crl-rollover-leaf-noakid leaf fxRootOld root_old 60 \
    ext_leaf_no_akid
cert fxLeafInt localhost leaf fxIntCa int 40 ext_leaf

crl fxCrlInt          fxIntCa      int      01 "$END"      crl_akid
crl fxCrlOld4Expiring fxRootOld    root_old 04 "$EXPIRING" crl_akid
crl fxCrlOld5         fxRootOld    root_old 05 "$END"      crl_akid 10
crl fxCrlOld6         fxRootOld    root_old 06 "$END"      crl_akid 30
crl fxCrlOld7NoAkid   fxRootOld    root_old 07 "$END"      crl_no_akid
crl fxCrlOld8         fxRootOld    root_old 08 "$END"      crl_akid
crl fxCrlOld9NoAkid   fxRootOld    root_old 09 "$END"      crl_no_akid
crl fxCrlNew1         fxRootNew    root_new 01 "$END"      crl_akid 10 20
crl fxCrlNew2Expiring fxRootNew    root_new 02 "$EXPIRING" crl_akid
crl fxCrlNew6         fxRootNew    root_new 06 "$END"      crl_akid 20
crl fxCrlByCrlOnlyKey fxCrlOnlyKey crl_only 01 "$END"      crl_akid 10

# Same name, signed by a key no CA holds. The throwaway self-signed cert only
# gives openssl ca an issuer name and SKID; it is not part of the fixtures.
cert stray_ca "$R" stray - - 01 ext_ca
crl fxCrlStrayPem stray_ca stray 01 "$END" crl_akid 60

crl bad_sig fxRootOld root_old 01 "$END" crl_akid 60
corrupt_sig "$T/bad_sig.pem" "$T/fxCrlBadSigPem.pem"

# --- Cycle: keys A, B and C issue each other ----------------------------------

# Placeholder self-signed certs give openssl ca each issuer's name and SKID
# before the real cross-signed certs exist. Only the cross-signed certs are
# fixtures.
cert cyc_a crl-cycle-a cycle_a - - 01 ext_ca
cert cyc_b crl-cycle-b cycle_b - - 01 ext_ca
cert cyc_c crl-cycle-c cycle_c - - 01 ext_ca
cert fxCycleAbyB crl-cycle-a cycle_a cyc_b cycle_b 02 ext_ca
cert fxCycleAbyC crl-cycle-a cycle_a cyc_c cycle_c 03 ext_ca
cert fxCycleBbyA crl-cycle-b cycle_b cyc_a cycle_a 04 ext_ca
cert fxCycleCbyB crl-cycle-c cycle_c cyc_b cycle_b 05 ext_ca
cert fxCycleLeaf localhost leaf cyc_a cycle_a 10 ext_leaf

crl fxCycleCrlA        cyc_a cycle_a 01 "$END" crl_akid
crl fxCycleCrlB        cyc_b cycle_b 01 "$END" crl_akid
crl fxCycleCrlBRevoked cyc_b cycle_b 01 "$END" crl_akid 02
crl fxCycleCrlC        cyc_c cycle_c 01 "$END" crl_akid

# --- Trust anchors ------------------------------------------------------------

cert fxAnchorRoot1 crl-anchor-root-1 anchor_root1 - - 01 ext_ca
cert fxAnchorRoot2 crl-anchor-root-2 anchor_root2 - - 02 ext_ca
cert fxAnchorIntK1 crl-anchor-int anchor_k1 fxAnchorRoot1 anchor_root1 31 ext_ca
cert fxAnchorIntK2 crl-anchor-int anchor_k2 fxAnchorRoot1 anchor_root1 32 ext_ca
cert fxAnchorIntK3 crl-anchor-int anchor_k3 fxAnchorRoot2 anchor_root2 33 ext_ca
cert fxAnchorLeaf crl-anchor-leaf leaf fxAnchorIntK1 anchor_k1 70 \
    ext_leaf_skid

crl fxAnchorCrlK2        fxAnchorIntK2 anchor_k2 01 "$END" crl_akid
crl fxAnchorCrlK3        fxAnchorIntK3 anchor_k3 01 "$END" crl_akid
crl fxAnchorCrlK3Revoked fxAnchorIntK3 anchor_k3 02 "$END" crl_akid 70

# --- Sanity checks ------------------------------------------------------------

verify_crl() {
    "$OPENSSL" crl -in "$T/$1.pem" -noout -verify -CAfile "$T/$2.pem" \
        >/dev/null 2>&1
}

verify_crl fxCrlOld5 fxRootOld     || die "fxCrlOld5 does not verify"
verify_crl fxCrlNew1 fxRootNew     || die "fxCrlNew1 does not verify"
verify_crl fxCrlByCrlOnlyKey fxCrlOnlyKey \
    || die "fxCrlByCrlOnlyKey does not verify"
verify_crl bad_sig fxRootOld       || die "bad_sig source does not verify"
verify_crl fxCrlBadSigPem fxRootOld && die "fxCrlBadSigPem still verifies"
verify_crl fxCrlStrayPem fxRootOld  && die "fxCrlStrayPem verifies"
"$OPENSSL" crl -in "$T/fxCrlBadSigPem.pem" -noout \
    || die "fxCrlBadSigPem no longer parses"
"$OPENSSL" x509 -in "$T/fxLeafNoAkid.pem" -noout -text \
    | grep -q "Authority Key Identifier" && die "fxLeafNoAkid has an AKID"
for c in fxCrlOld7NoAkid fxCrlOld9NoAkid; do
    "$OPENSSL" crl -in "$T/$c.pem" -noout -text \
        | grep -q "Authority Key Identifier" && die "$c has an AKID"
done

# --- Header -------------------------------------------------------------------

# Print a DER file as C hex bytes, 12 per line. Pure bash: read -d '' returns
# an empty string for a NUL byte, which printf "'" turns into 0.
hex_array() {
    local LC_ALL=C c n=0 line=""

    while IFS= read -r -d '' -n 1 c; do
        printf -v c '0x%02x' "'$c"
        if [ -z "$line" ]; then
            line="    $c"
        else
            line+=", $c"
        fi
        n=$(( n + 1 ))
        if [ "$n" -eq 12 ]; then
            echo "$line,"
            line=""
            n=0
        fi
    done < "$1"
    if [ -n "$line" ]; then
        echo "$line"
    fi
}

# emit_der <name> <comment>
emit_der() {
    printf '%s\n' "$2"
    echo "WC_MAYBE_UNUSED static const unsigned char $1[] = {"
    hex_array "$T/$1.der" | sed '$ s/,$//'
    echo "};"
    echo
}

# emit_pem <name> <comment>
emit_pem() {
    local line

    printf '%s\n' "$2"
    echo "WC_MAYBE_UNUSED static const char $1[] ="
    while IFS= read -r line; do
        printf '    "%s\\n"\n' "$line"
    done < "$T/$1.pem" | sed '$ s/$/;/'
    echo
}

{
cat <<'EOF'
/* test_certman_crl_fixtures.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Generated by certs/crl/gen/gen-crl-fixtures.sh. Do not edit; change the
 * script and rerun it.
 *
 * Fixtures for the CRL key rollover, CRL-only key and chain walk tests. All
 * P-256, valid 2026-01-01 to 2046-01-01 unless noted.
 *
 * One CA name, CN=crl-rollover-root, with old and new self-signed keys, a
 * CRL-only key, an intermediate under the old key, leaves, and one CRL series
 * per key. CRLs are empty unless they list revoked serials, which are the
 * leaves' serials.
 *
 * The cycle tests use CN=crl-cycle-a/b/c, keys A, B and C issued by each
 * other. */

#ifndef WOLFSSL_TEST_CERTMAN_CRL_FIXTURES_H
#define WOLFSSL_TEST_CERTMAN_CRL_FIXTURES_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_CRL) && !defined(NO_CERTS)

EOF

emit_der fxRootOld \
    "/* Old root key, CN=crl-rollover-root, serial 1. keyCertSign |
 * cRLSign, AKID = SKID. */"
emit_der fxRootNew "/* New root key, same name, serial 2. keyCertSign | cRLSign,
 * AKID = SKID. Sorts before the old root in the CA table. */"
emit_der fxCrlOnlyKey \
    "/* Same name, serial 3, issued by the old key. CA:FALSE, cRLSign
 * only. */"
emit_der fxIntCa \
    "/* Intermediate CN=crl-rollover-int, serial 0x30, issued by the old
 * key. */"
emit_der fxLeafOld "/* Leaf serial 0x10, issued by the old key. */"
emit_der fxLeafNew "/* Leaf serial 0x20, issued by the new key. */"
emit_der fxLeafNoAkid "/* Leaf serial 0x60, issued by the old key, no AKID. */"
emit_der fxLeafInt \
    "/* Leaf serial 0x40, CN=localhost, issued by the intermediate. */"
emit_der fxLeafKey "/* Private key of every leaf. */"
emit_der fxCrlInt "/* Intermediate CRL number 1, empty. */"
emit_der fxCrlOld4Expiring \
    "/* Old key CRL number 4, empty, next update 2030-01-01. */"
emit_der fxCrlOld5 "/* Old key CRL number 5, revokes 0x10. */"
emit_der fxCrlOld6 "/* Old key CRL number 6, revokes 0x30. */"
emit_der fxCrlOld7NoAkid "/* Old key CRL number 7, no AKID, empty. */"
emit_der fxCrlOld8 "/* Old key CRL number 8, empty. */"
emit_der fxCrlOld9NoAkid "/* Old key CRL number 9, no AKID, empty. */"
emit_der fxCrlNew1 "/* New key CRL number 1, revokes 0x10 and 0x20. */"
emit_der fxCrlNew2Expiring \
    "/* New key CRL number 2, empty, next update 2030-01-01. */"
emit_der fxCrlNew6 "/* New key CRL number 6, revokes 0x20. */"
emit_der fxCrlByCrlOnlyKey "/* CRL-only key CRL number 1, revokes 0x10. */"
emit_pem fxCrlStrayPem \
    "/* Same name, signed by a key no CA holds, revokes 0x60. */"
emit_pem fxCrlBadSigPem \
    "/* Old key CRL number 1 revoking 0x60, one signature byte
 * changed. */"
emit_der fxCycleAbyB "/* CN=crl-cycle-a, key A, serial 2, issued by key B. */"
emit_der fxCycleAbyC "/* CN=crl-cycle-a, key A, serial 3, issued by key C. */"
emit_der fxCycleBbyA "/* CN=crl-cycle-b, key B, serial 4, issued by key A. */"
emit_der fxCycleCbyB "/* CN=crl-cycle-c, key C, serial 5, issued by key B. */"
emit_der fxCycleLeaf "/* Leaf serial 0x10, CN=localhost, issued by key A. */"
emit_der fxCycleCrlA "/* Key A CRL number 1, empty. */"
emit_der fxCycleCrlB "/* Key B CRL number 1, empty. */"
emit_der fxCycleCrlBRevoked \
    "/* Key B CRL number 1, revokes serial 2 (fxCycleAbyB). */"
emit_der fxCycleCrlC "/* Key C CRL number 1, empty. */"

cat <<'EOF'
/* Trust anchor fixtures. Roots crl-anchor-root-1 and -2 are separate
 * anchors. Root 1 issues CN=crl-anchor-int with keys 1 and 2, root 2
 * with key 3. The leaf is under key 1, so CRLs from keys 2 and 3 are
 * other-key CRLs: key 2's shares the leaf's anchor, key 3's does not.
 * Valid 2026-01-01 to 2046-01-01. */

EOF

emit_der fxAnchorRoot1 "/* Root CN=crl-anchor-root-1, serial 1, self-signed. */"
emit_der fxAnchorRoot2 "/* Root CN=crl-anchor-root-2, serial 2, self-signed. */"
emit_der fxAnchorIntK1 \
    "/* CN=crl-anchor-int, key 1, serial 0x31, issued by root 1. */"
emit_der fxAnchorIntK2 \
    "/* CN=crl-anchor-int, key 2, serial 0x32, issued by root 1. */"
emit_der fxAnchorIntK3 \
    "/* CN=crl-anchor-int, key 3, serial 0x33, issued by root 2. */"
emit_der fxAnchorLeaf "/* Leaf serial 0x70, issued by intermediate key 1. */"
emit_der fxAnchorCrlK2 "/* Intermediate key 2 CRL number 1, empty. */"
emit_der fxAnchorCrlK3 "/* Intermediate key 3 CRL number 1, empty. */"
emit_der fxAnchorCrlK3Revoked \
    "/* Intermediate key 3 CRL number 2, revokes 0x70. */"

cat <<'EOF'
#endif /* HAVE_CRL && !NO_CERTS */

#endif /* WOLFSSL_TEST_CERTMAN_CRL_FIXTURES_H */
EOF
} > "$OUT"

echo "Wrote $OUT"
