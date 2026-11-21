#!/bin/sh
#
# gen_test_certs.sh
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
# Regenerate the synthetic cross-sign fixtures for test_esp_crt_bundle.sh.
# Needs OpenSSL 3.4 or later (-not_before). Keys are not kept.
#
# test_roots.pem goes into the test bundle. Each x_*.pem is a chain as a
# server sends it: an intermediate, then a cross-signed top cert whose issuer
# ("Untrusted Root") is not in the bundle.

set -e
OUT=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

DAYS="-not_before 20260101000000Z -not_after 21260101000000Z"
CA_EXT="basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

key() {
    openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
}

# root <name> <subject> [extra extension lines]
root() {
    printf '%s\n%s\nsubjectKeyIdentifier=hash\n' "$CA_EXT" "$3" > "$1.ext"
    openssl req -new -key "$1.key" -subj "$2" -out "$1.csr"
    # shellcheck disable=SC2086 # DAYS is two options
    openssl x509 -req -in "$1.csr" -signkey "$1.key" $DAYS \
        -extfile "$1.ext" -set_serial 1 -out "$1.pem"
}

# sign <name> <subject> <subject key> <issuer name> [extra extension lines]
# The extra lines may replace the CA basicConstraints.
sign() {
    if printf '%s\n' "$5" | grep -q '^basicConstraints'; then
        printf 'keyUsage=critical,digitalSignature\n%s\n' "$5" > "$1.ext"
    else
        printf '%s\n%s\n' "$CA_EXT" "$5" > "$1.ext"
    fi
    grep -q '^subjectKeyIdentifier' "$1.ext" ||
        echo "subjectKeyIdentifier=hash" >> "$1.ext"
    echo "authorityKeyIdentifier=keyid" >> "$1.ext"
    openssl req -new -key "$3.key" -subj "$2" -out "$1.csr"
    # shellcheck disable=SC2086 # DAYS is two options
    openssl x509 -req -in "$1.csr" -CA "$4.pem" -CAkey "$4.key" $DAYS \
        -extfile "$1.ext" -set_serial "0x$(openssl rand -hex 8)" -out "$1.pem"
}

key untrusted; key root; key other; key plroot; key ncroot; key pcroot
key int
root untrusted "/O=wolfSSL Test/CN=Untrusted Root"
root root "/O=wolfSSL Test/CN=Test Root"
root plroot "/O=wolfSSL Test/CN=Test PathLen Root" \
    "basicConstraints=critical,CA:TRUE,pathlen:3"
root ncroot "/O=wolfSSL Test/CN=Test NameConstraints Root" \
    "nameConstraints=critical,permitted;DNS:example.com"
# Not critical: strict ASN rejects a critical policyConstraints.
root pcroot "/O=wolfSSL Test/CN=Test PolicyConstraints Root" \
    "policyConstraints=requireExplicitPolicy:0"
# Not self-issued: has Test Root's key, but is issued by Untrusted Root.
sign sub "/O=wolfSSL Test/CN=Test Sub CA" root untrusted

# A self-signed stand-in for each cross-sign's subject, key and key ID, used
# to sign the intermediate below it.
# standin <name> <key> <subject> <subject key ID>
standin() {
    # shellcheck disable=SC2086 # DAYS is two options
    openssl req -new -x509 -key "$2.key" -subj "$3" $DAYS -out "$1.pem" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=$4"
    cp "$2.key" "$1.key"
}

skid() {
    openssl x509 -in "$1" -noout -ext subjectKeyIdentifier | tail -1 |
        tr -d ' '
}

# chain <name> <cross subject> <cross key> [extra cross extension lines]
chain() {
    sign "$1_cross" "$2" "$3" untrusted "$4"
    standin "$1_standin" "$3" "$2" "$(skid "$1_cross.pem")"
    sign "$1_int" "/O=wolfSSL Test/CN=Test Intermediate" int "$1_standin"
    cat "$1_int.pem" "$1_cross.pem" > "$OUT/x_$1.pem"
}

chain ok "/O=wolfSSL Test/CN=Test Root" root
# Keeps Test Root's subject key ID, so only the key differs.
chain other_key "/O=wolfSSL Test/CN=Test Root" other \
    "subjectKeyIdentifier=$(skid root.pem)"
chain pathlen "/O=wolfSSL Test/CN=Test PathLen Root" plroot
chain name_constraints "/O=wolfSSL Test/CN=Test NameConstraints Root" ncroot
chain policy_constraints "/O=wolfSSL Test/CN=Test PolicyConstraints Root" \
    pcroot
chain not_self_issued "/O=wolfSSL Test/CN=Test Sub CA" root
chain not_ca "/O=wolfSSL Test/CN=Test Root" root \
    "basicConstraints=critical,CA:FALSE"
OTHER_SKID=01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14
chain other_skid "/O=wolfSSL Test/CN=Test Root" root \
    "subjectKeyIdentifier=$OTHER_SKID"

cat root.pem plroot.pem ncroot.pem pcroot.pem sub.pem > "$OUT/test_roots.pem"
