#!/bin/sh
#
# test_esp_crt_bundle.sh
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
# Host test of the ESP-IDF certificate bundle verify callback in
# esp_crt_bundle.c. No network or ESP-IDF needed.
#
# - Builds a host wolfSSL from this tree twice, without and with
#   WOLFSSL_ALT_CERT_CHAINS. Run ./autogen.sh first; the tree must not be
#   configured in place.
# - Generates the bundles with gen_crt_bundle.py, so needs python with the
#   cryptography package.
# - Checks that each bundle mode is in the order the callback's binary search
#   expects, and that the chains in certs/ are accepted or rejected.
#
# Usage: test_esp_crt_bundle.sh [python]

DIR=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$DIR/../../../../../.." && pwd)
BUNDLE_DIR=$(cd "$DIR/.." && pwd)
CERTS="$DIR/certs"
PY=${1:-python3}
CC=${CC:-gcc}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

if [ ! -x "$SRC/configure" ]; then
    echo "Run ./autogen.sh in $SRC first."
    exit 1
fi
if [ -f "$SRC/config.status" ]; then
    echo "$SRC is configured in place; use a clean checkout."
    exit 1
fi

# build_lib <name> <extra CFLAGS>: static host wolfSSL with the ESP-TLS
# verify callback settings.
build_lib() {
    mkdir "$WORK/lib-$1"
    echo "Building host wolfSSL ($1)"
    if ! (cd "$WORK/lib-$1" &&
          "$SRC/configure" --enable-opensslextra --enable-sni \
              --disable-shared --disable-examples --disable-crypttests \
              --disable-benchmark \
              CFLAGS="-g -O1 -fsanitize=address \
                      -DWOLFSSL_ALWAYS_VERIFY_CB -DWOLFSSL_VERIFY_CB_ALL_CERTS \
                      -DKEEP_PEER_CERT $2" \
              LDFLAGS="-fsanitize=address" &&
          make -j"$(nproc 2>/dev/null || echo 2)") > "$WORK/lib-$1.log" 2>&1
    then
        tail -40 "$WORK/lib-$1.log"
        echo "FAIL building host wolfSSL ($1)"
        exit 1
    fi
    if ! "$CC" -g -O1 -Wall -Werror -fsanitize=address \
            -I"$DIR/stub" -I"$WORK/lib-$1" -I"$SRC" \
            "$DIR/test_esp_crt_bundle.c" -o "$WORK/test-$1" \
            "$WORK/lib-$1/src/.libs/libwolfssl.a" -lm -lpthread \
            -Wl,--wrap=time; then
        echo "FAIL building test_esp_crt_bundle ($1)"
        exit 1
    fi
}

# gen_bundle <name> <gen_crt_bundle.py args...>
gen_bundle() {
    NAME=$1
    shift
    mkdir "$WORK/$NAME"
    if ! (cd "$WORK/$NAME" &&
          "$PY" "$BUNDLE_DIR/gen_crt_bundle.py" -q "$@"); then
        echo "FAIL generating the $NAME bundle"
        exit 1
    fi
}

# check <test args...>: run the test binary, count a failure
check() {
    if ! "$@"; then
        FAILED=1
    fi
}

# ESP-IDF builds use WOLFSSL_SMALL_STACK. The default build, which has the
# cross-sign path, checks those heap paths; alt checks the stack ones.
build_lib default "-DWOLFSSL_SMALL_STACK"
build_lib alt "-DWOLFSSL_ALT_CERT_CHAINS"

ALL="$BUNDLE_DIR/cacrt_all.pem"
LOCAL="$BUNDLE_DIR/cacrt_local.pem"
DEPRECATED="$BUNDLE_DIR/cacrt_deprecated.pem"
CSV="$BUNDLE_DIR/cmn_crt_authorities.csv"

# The bundle modes as the ESP-IDF build generates them.
gen_bundle full --input "$ALL" "$LOCAL"
gen_bundle full_deprecated --input "$ALL" "$LOCAL" "$DEPRECATED"
gen_bundle cmn --input "$ALL" "$LOCAL" --filter "$CSV"
gen_bundle cmn_deprecated --input "$ALL" "$LOCAL" "$DEPRECATED" \
    --filter "$CSV"
# Plus the test roots, for the chain checks.
gen_bundle trust --input "$ALL" "$LOCAL" "$CERTS/test_roots.pem"
gen_bundle trust_deprecated --input "$ALL" "$LOCAL" "$DEPRECATED" \
    "$CERTS/test_roots.pem"

for b in full full_deprecated cmn cmn_deprecated trust trust_deprecated; do
    check "$WORK/test-default" order "$WORK/$b/x509_crt_bundle_wolfssl"
done

# where to run (both, a bundle: trust or deprecated, a library: default or
# alt, or library,bundle), chain file, expected result, text the callback
# must log
CASES="
default,trust|gts_root_r4_by_globalsign|accept|Accepted a cross-signed copy
alt,trust|gts_root_r4_by_globalsign|accept|Found in bundle: /C=US/O=Google Trust
deprecated|gts_root_r4_by_globalsign|accept|Found in bundle: /C=BE/O=GlobalSign
default,trust|gts_root_r1_by_globalsign|accept|Accepted a cross-signed copy
alt,trust|gts_root_r1_by_globalsign|accept|Found in bundle: /C=US/O=Google Trust Services LLC/CN=GTS Root R1
deprecated|gts_root_r1_by_globalsign|accept|Found in bundle: /C=BE/O=GlobalSign
default|usertrust_ecc_by_aaa|accept|Accepted a cross-signed copy
alt|usertrust_ecc_by_aaa|accept|Found in bundle: /C=US/ST=New Jersey
default|usertrust_ecc_by_aaa_with_root|reject|Not found in bundle: /C=GB/ST=Greater Manchester
alt|usertrust_ecc_by_aaa_with_root|accept|Found in bundle: /C=US/ST=New Jersey
default|x_ok|accept|Accepted a cross-signed copy
default|x_other_key|reject|Bundle root has a different public key
default|x_other_skid|reject|Bundle root has a different subject key ID
default|x_pathlen|reject|Bundle root has constraints
default|x_name_constraints|reject|Bundle root has constraints
default|x_policy_constraints|reject|Bundle root has constraints
default|x_not_self_issued|reject|Bundle cert is not a self-issued CA
default|x_not_ca|reject|Cross-signed cert is not a CA
alt|x_ok|accept|Found in bundle: /O=wolfSSL Test/CN=Test Root
alt|x_pathlen|accept|Found in bundle: /O=wolfSSL Test/CN=Test PathLen Root
alt|x_name_constraints|accept|Found in bundle: /O=wolfSSL Test/CN=Test NameConstraints Root
alt|x_policy_constraints|accept|Found in bundle: /O=wolfSSL Test/CN=Test PolicyConstraints Root
alt|x_not_self_issued|accept|Found in bundle: /O=wolfSSL Test/CN=Test Sub CA
alt|x_not_ca|reject|Not found in bundle: /O=wolfSSL Test/CN=Untrusted Root
alt|x_other_key|reject|Failed to verify cert after loading new CA
alt|x_other_skid|reject|Failed to verify cert after loading new CA
both|amazon_by_starfield_g2|accept|Found in bundle: /C=US/ST=Arizona/L=Scottsdale/O=Starfield
both|emudhra_by_emsign_ecc_g3|reject|Not found in bundle: /C=IN/O=eMudhra
both|emudhra_by_aaa|reject|Not found in bundle: /C=NL/O=eMudhra BV
"

for lib in default alt; do
    for b in trust deprecated; do
        bundle="$WORK/trust$( [ $b = deprecated ] &&
                              echo _deprecated)/x509_crt_bundle_wolfssl"
        echo "== WOLFSSL_ALT_CERT_CHAINS $( [ $lib = alt ] && echo on ||
             echo off), $b bundle"
        echo "$CASES" | while IFS='|' read -r only chain expect text; do
            [ -n "$chain" ] || continue
            [ "$only" = both ] || [ "$only" = $b ] || [ "$only" = $lib ] ||
                [ "$only" = "$lib,$b" ] || continue
            if ! "$WORK/test-$lib" chain \
                    "$bundle" "$CERTS/$chain.pem" \
                    "$expect" "$text"; then
                echo "$chain" >> "$WORK/failed"
            fi
        done
    done
done

# After GlobalSign Root CA and its GTS Root R1 and R4 cross-signs expire, the
# deprecated bundle still finds GlobalSign but can't verify through it, so
# the chains must still verify through the bundled GTS roots. R1 is RSA, R4
# is ECC.
EXPIRED=1843430400 # 2028-06-01 00:00:00 UTC
for lib in default alt; do
    echo "== WOLFSSL_ALT_CERT_CHAINS $( [ $lib = alt ] && echo on ||
         echo off), deprecated bundle, GlobalSign Root CA expired"
    for r in r1 r4; do
        if [ $lib = alt ]; then
            text="Found in bundle: /C=US/O=Google Trust"
        else
            text="Accepted a cross-signed copy"
        fi
        if ! TEST_NOW=$EXPIRED "$WORK/test-$lib" \
                chain "$WORK/trust_deprecated/x509_crt_bundle_wolfssl" \
                "$CERTS/gts_root_${r}_by_globalsign.pem" accept "$text"; then
            echo "gts_root_${r}_by_globalsign" >> "$WORK/failed"
        fi
    done
done
if [ -s "$WORK/failed" ]; then
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo "FAILED"
else
    echo "All passed"
fi
exit $FAILED
