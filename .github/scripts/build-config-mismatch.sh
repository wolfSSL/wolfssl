#!/bin/bash
# End-to-end test of the build configuration check (wc_CheckBuildConfig):
# an application built against one wolfSSL must detect, at run time, that
# the shared library it actually loaded was configured differently.
#
# Builds and installs two libraries from this tree into separate prefixes:
#   A: default configuration
#   B: a different configuration (OpenSSL compat on, SHA-3 off, AES-XTS on),
#      chosen so that feature bits, struct sizes and the options.h hash all
#      differ from A
# then builds a small application against each library's headers and runs
# it with each library loaded:
#   app(A) + lib A  ->  0, empty description
#   app(B) + lib B  ->  0, empty description
#   app(A) + lib B  ->  BUILD_CONFIG_MISMATCH_E, the expected items named
#   app(B) + lib A  ->  BUILD_CONFIG_MISMATCH_E, the same items reversed
#   app(A) built with an options.h whose hash define was removed, all else
#     equal + lib A -> 0 (the hash is only compared when both sides have one)
#   app(A) built with an options.h edited after configure (here: only its
#     hash changed) + lib A -> BUILD_CONFIG_MISMATCH_E, options hash only
#
# Usage: build-config-mismatch.sh [WORK_DIR]
# Run from the top of a git checkout that has been through ./autogen.sh.
# WORK_DIR (default: a fresh mktemp directory) receives the installs and
# the test application. The source tree is reconfigured; its previous
# configuration is not restored.

set -euo pipefail

work=${1:-$(mktemp -d)}
mkdir -p "$work"
work=$(cd "$work" && pwd)
jobs=$(nproc 2>/dev/null || echo 4)

conf_common=(--disable-examples --disable-crypttests --enable-shared
             --disable-static)
conf_a=()
conf_b=(--enable-opensslextra --disable-sha3 --enable-aesxts)

failures=0
fail() {
    echo "::error ::build-config mismatch test: $*"
    failures=$((failures + 1))
}

build() { # name, configure args...
    local name=$1
    shift
    echo "=== Building library $name: $*"
    if [ -f Makefile ]; then
        make distclean >/dev/null 2>&1 || true
    fi
    ./configure --prefix="$work/$name" "${conf_common[@]}" "$@" \
        > "$work/configure-$name.log" 2>&1 ||
        { tail -30 "$work/configure-$name.log"; exit 1; }
    make -j"$jobs" > "$work/make-$name.log" 2>&1 ||
        { tail -30 "$work/make-$name.log"; exit 1; }
    make install > "$work/install-$name.log" 2>&1 ||
        { tail -30 "$work/install-$name.log"; exit 1; }
    grep -q '#define HAVE_WC_INTROSPECTION' \
        "$work/$name/include/wolfssl/options.h" ||
        { echo "HAVE_WC_INTROSPECTION missing from library $name"; exit 1; }
}

cat > "$work/app.c" <<'EOF'
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/build_check.h>
#include <stdio.h>

int main(void)
{
    char why[4096];
    word32 mismatch = 0;
    int ret = wc_CheckBuildConfigEx(&mismatch, why, sizeof(why));

    printf("ret=%d mismatch=0x%x\n", ret, (unsigned)mismatch);
    printf("%s\n", why);
    return (ret == 0) ? 0 : 1;
}
EOF

app() { # name, headers prefix, extra cflags...
    local name=$1 prefix=$2
    shift 2
    ${CC:-cc} -Wall -Werror "$@" -I"$prefix/include" "$work/app.c" \
        -L"$prefix/lib" -lwolfssl -o "$work/$name"
}

run() { # app, library prefix -> sets out, rc
    set +e
    out=$(LD_LIBRARY_PATH="$2/lib" "$work/$1" 2>&1)
    rc=$?
    set -e
    echo "--- $1 with $(basename "$2"): exit $rc"
    echo "$out" | sed 's/; /\n    /g'
}

expect_match() { # app, library prefix
    run "$1" "$2"
    [ "$rc" -eq 0 ] || fail "$1 with $(basename "$2"): expected a match"
    echo "$out" | head -1 | grep -q '^ret=0 mismatch=0x0$' ||
        fail "$1 with $(basename "$2"): expected ret=0 mismatch=0x0"
}

expect_mismatch() { # app, library prefix, expected substrings...
    local a=$1 p=$2
    shift 2
    run "$a" "$p"
    [ "$rc" -eq 1 ] || fail "$a with $(basename "$p"): expected a mismatch"
    echo "$out" | head -1 | grep -q '^ret=-1043 mismatch=0x[0-9a-f]*e$' ||
        fail "$a with $(basename "$p"): expected BUILD_CONFIG_MISMATCH_E" \
             "with features, sizes and options hash all differing"
    local want
    for want in "$@"; do
        echo "$out" | grep -qF -- "$want" ||
            fail "$a with $(basename "$p"): description lacks \"$want\""
    done
}

build a "${conf_a[@]}"
app app_a "$work/a"
build b "${conf_b[@]}"
app app_b "$work/b"
# Modified copies of A's options.h, found ahead of the installed one.
mkdir -p "$work/nohash/wolfssl" "$work/edited/wolfssl"
grep -v 'WOLFSSL_OPTIONS_HASH' "$work/a/include/wolfssl/options.h" \
    > "$work/nohash/wolfssl/options.h"
sed 's/^#define WOLFSSL_OPTIONS_HASH .*/#define WOLFSSL_OPTIONS_HASH 0x12345678U/' \
    "$work/a/include/wolfssl/options.h" > "$work/edited/wolfssl/options.h"
cmp -s "$work/a/include/wolfssl/options.h" "$work/edited/wolfssl/options.h" &&
    { echo "options.h of library a has no WOLFSSL_OPTIONS_HASH"; exit 1; }
app app_a_nohash "$work/a" -I"$work/nohash"
app app_a_edited "$work/a" -I"$work/edited"

expect_match app_a "$work/a"
expect_match app_b "$work/b"
expect_match app_a_nohash "$work/a"
run app_a_edited "$work/a"
echo "$out" | head -1 | grep -q '^ret=-1043 mismatch=0x8$' ||
    fail "app_a_edited with a: expected only an options hash mismatch (0x8)"
echo "$out" | grep -qF 'options.h hash: app=0x12345678 lib=0x' ||
    fail "app_a_edited with a: description lacks the options hash"
expect_mismatch app_a "$work/b" \
    'OPENSSL_EXTRA: app=off lib=on' \
    'WOLFSSL_SHA3: app=on lib=off' \
    'WOLFSSL_AES_XTS: app=off lib=on' \
    'sizeof(struct WOLFSSL_EVP_MD_CTX): app=0 lib=' \
    'options.h hash: app=0x'
expect_mismatch app_b "$work/a" \
    'OPENSSL_EXTRA: app=on lib=off' \
    'WOLFSSL_SHA3: app=off lib=on' \
    'WOLFSSL_AES_XTS: app=on lib=off' \
    'sizeof(struct WOLFSSL_EVP_MD_CTX): app=' \
    'options.h hash: app=0x'

if [ "$failures" -ne 0 ]; then
    echo "build-config mismatch test: $failures failure(s)"
    exit 1
fi
echo "build-config mismatch test: OK"
