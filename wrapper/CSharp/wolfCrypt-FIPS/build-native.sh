#!/bin/sh
# Build the wolfssl_csharp_fips size helper against an installed wolfSSL FIPS
# library and place it next to libwolfssl.
#
# Usage: build-native.sh <wolfssl-install-prefix>   (default: /usr/local)
#
# The helper must be compiled against the same installed headers
# (wolfssl/options.h) as the FIPS library it will be used with.
set -e
PREFIX="${1:-/usr/local}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-cc}"

case "$(uname -s)" in
    Darwin) OUT="$PREFIX/lib/libwolfssl_csharp_fips.dylib"; SHARED="-dynamiclib" ;;
    *)      OUT="$PREFIX/lib/libwolfssl_csharp_fips.so";    SHARED="-shared" ;;
esac

if [ ! -f "$PREFIX/include/wolfssl/options.h" ]; then
    echo "error: $PREFIX/include/wolfssl/options.h not found" >&2
    exit 1
fi
if ! grep -q "HAVE_FIPS" "$PREFIX/include/wolfssl/options.h"; then
    echo "error: $PREFIX is not a FIPS build (HAVE_FIPS missing from options.h)" >&2
    exit 1
fi

$CC $SHARED -fPIC -O2 -I"$PREFIX/include" "$HERE/native/fips_sizes.c" -o "$OUT"
echo "built $OUT"
