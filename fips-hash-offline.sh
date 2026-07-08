#!/bin/bash

# fips-hash-offline.sh
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

# This script computes the wolfCrypt FIPS in-core integrity hash at compile
# time directly from an already linked binary, and patches the result into the
# verifyCore[] array inside that binary.
#
# This reproduces, at build time and against the final ELF image, exactly what
# DoInCoreCheck() in wolfcrypt/src/fips_test.c computes at run time:
#
#   HMAC-SHA256( coreKey,
#                .text  bytes in [wolfCrypt_FIPS_first, wolfCrypt_FIPS_last)
#                ||
#                .rodata bytes in [wolfCrypt_FIPS_ro_start, wolfCrypt_FIPS_ro_end)
#                with the verifyCore[] bytes skipped )
#
# Because verifyCore[] is excluded from the digest, overwriting it with the
# computed value does not change the digest, so a single pass over the linked
# binary is sufficient -- no rebuild and no scraping of the module's reported
# hash is required.
#
# Assumptions (match the optest user-space static FIPS build):
#   - single fixed-address (ET_EXEC) image, not stripped
#   - measured .text/.rodata bracketed by the wolfCrypt_FIPS_first/last and
#     wolfCrypt_FIPS_ro_start/ro_end symbols
#   - no text-segment canonicalizer and no relocation-table indirection in
#     effect (i.e. the plain #else path of DoInCoreCheck())
#
# Usage: fips-hash-offline.sh [path-to-binary]
#   default binary: wolfcrypt/test/testwolfcrypt

set -euo pipefail

BIN="${1:-wolfcrypt/test/testwolfcrypt}"

die() { echo "fips-hash-offline: error: $*" >&2; exit 1; }

[ -w "$BIN" ] || die "binary not writable: $BIN"
command -v awk     >/dev/null 2>&1 || die "awk not found"
command -v dd      >/dev/null 2>&1 || die "dd not found"
command -v readelf >/dev/null 2>&1 || die "readelf not found"
command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v xxd     >/dev/null 2>&1 || die "xxd not found"

# Symbol lookup from the ELF symbol table.
# readelf -s columns: Num: Value Size Type Bind Vis Ndx Name
#   -> Value ($2) is hexadecimal, Size ($3) is decimal, Ndx ($7), Name ($8).
sym_val()  { readelf -sW "$BIN" | awk -v n="$1" '$8==n && $7!="UND"{print $2; exit}'; }
sym_size() { readelf -sW "$BIN" | awk -v n="$1" '$8==n && $7!="UND"{print $3; exit}'; }

# Map a virtual address to a file offset using the containing PROGBITS section.
# This avoids assuming any particular load base or section padding.
vaddr_to_off() {
    local v="$1"
    local name type addr off size a o s
    while read -r name type addr off size; do
        [ "$type" = "PROGBITS" ] || continue
        a=$((0x$addr)); o=$((0x$off)); s=$((0x$size))
        if [ "$v" -ge "$a" ] && [ "$v" -lt $((a + s)) ]; then
            echo $((o + v - a))
            return 0
        fi
    done < <(readelf -SW "$BIN" | sed 's/\[[ 0-9]*\]//' | awk '/PROGBITS/{print $1, $2, $3, $4, $5}')
    return 1
}

# Extract byte_count bytes starting at file_offset (both in bytes) to stdout.
# Uses a 1-byte block size so skip/count are byte-granular on any POSIX dd.
# dd seeks over the skip on a regular file, so the offset is not read byte
# by byte; only the small count is copied one byte at a time.
extract() {
    dd if="$BIN" bs=1 skip="$1" count="$2" 2>/dev/null
}

# --- gather the FIPS boundary and verifyCore/coreKey symbols ---
FIRST_H=$(sym_val wolfCrypt_FIPS_first)
LAST_H=$(sym_val wolfCrypt_FIPS_last)
ROSTART_H=$(sym_val wolfCrypt_FIPS_ro_start)
ROEND_H=$(sym_val wolfCrypt_FIPS_ro_end)
VC_H=$(sym_val verifyCore)
VCSZ=$(sym_size verifyCore)
KEY_H=$(sym_val coreKey)
KEYSZ=$(sym_size coreKey)

[ -n "$FIRST_H" ] && [ -n "$LAST_H" ] && [ -n "$ROSTART_H" ] && [ -n "$ROEND_H" ] \
    && [ -n "$VC_H" ] && [ -n "$VCSZ" ] && [ -n "$KEY_H" ] && [ -n "$KEYSZ" ] \
    || die "missing FIPS boundary symbols (is $BIN a non-stripped static FIPS build?)"

first=$((0x$FIRST_H))
last=$((0x$LAST_H))
rostart=$((0x$ROSTART_H))
roend=$((0x$ROEND_H))
vc=$((0x$VC_H))
keyaddr=$((0x$KEY_H))

[ "$last"  -gt "$first"   ] || die "wolfCrypt_FIPS_last <= wolfCrypt_FIPS_first"
[ "$roend" -gt "$rostart" ] || die "wolfCrypt_FIPS_ro_end <= wolfCrypt_FIPS_ro_start"

# Select the digest from the size of verifyCore[] (= digest_bytes*2 + 1).
digest_bytes=$(( (VCSZ - 1) / 2 ))
case "$digest_bytes" in
    32) ALG=sha256 ;;
    48) ALG=sha384 ;;
    *)  die "unexpected verifyCore size ($VCSZ); cannot determine digest" ;;
esac

# Read the HMAC key (coreKey) as ASCII hex straight out of the binary.
keyoff=$(vaddr_to_off "$keyaddr") || die "cannot map coreKey address to file offset"
KEYHEX=$(extract "$keyoff" $((KEYSZ - 1)))
[ "${#KEYHEX}" -eq $((digest_bytes * 2)) ] || die "coreKey length mismatch in binary"

# File offsets for the measured regions.
codeoff=$(vaddr_to_off "$first")   || die "cannot map wolfCrypt_FIPS_first"
roff=$(vaddr_to_off "$rostart")    || die "cannot map wolfCrypt_FIPS_ro_start"

vc_in_ro=0
if [ "$vc" -ge "$rostart" ] && [ "$vc" -lt "$roend" ]; then
    vc_in_ro=1
    aoff=$(vaddr_to_off $((vc + VCSZ))) || die "cannot map verifyCore tail"
fi

# Compute the digest, streaming the measured bytes in the same order and with
# the same verifyCore exclusion as DoInCoreCheck().
NEWHASH=$(
    {
        extract "$codeoff" $((last - first))
        if [ "$vc_in_ro" -eq 1 ]; then
            extract "$roff" $((vc - rostart))
            extract "$aoff" $((roend - vc - VCSZ))
        else
            extract "$roff" $((roend - rostart))
        fi
    } | openssl dgst -"$ALG" -mac HMAC -macopt hexkey:"$KEYHEX" -binary \
      | xxd -p -c 1000 | tr -d '\n' | tr 'a-f' 'A-F'
)
[ "${#NEWHASH}" -eq $((digest_bytes * 2)) ] || die "hash computation failed"

# Overwrite the first digest_bytes*2 ASCII characters of verifyCore[] in place.
# The trailing NUL terminator (byte digest_bytes*2) is left untouched.
vcoff=$(vaddr_to_off "$vc") || die "cannot map verifyCore address to file offset"
printf '%s' "$NEWHASH" | dd of="$BIN" bs=1 conv=notrunc seek="$vcoff" 2>/dev/null \
    || die "failed to write verifyCore"

# Confirm the patch landed.
CHECK=$(extract "$vcoff" $((digest_bytes * 2)))
[ "$CHECK" = "$NEWHASH" ] || die "verifyCore patch verification failed"

ALG_UC=$(echo "$ALG" | tr 'a-z' 'A-Z')
echo "fips-hash-offline: patched $BIN"
echo "  algorithm  : HMAC-$ALG_UC"
echo "  code range : [0x$FIRST_H, 0x$LAST_H)  ($((last - first)) bytes)"
echo "  ro range   : [0x$ROSTART_H, 0x$ROEND_H)  (verifyCore $([ "$vc_in_ro" -eq 1 ] && echo excluded || echo 'not in range'))"
echo "  hash       : $NEWHASH"
