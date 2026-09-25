#!/bin/sh
# Builds the size helper beside an installed FIPS libwolfssl, from its headers; rebuild on reinstall
# Usage: build-native.sh <wolfssl-install-prefix>   (default: /usr/local)
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

case "$(uname -s)" in
    Darwin) LIB="$PREFIX/lib/libwolfssl.dylib" ;;
    *)      LIB="$PREFIX/lib/libwolfssl.so" ;;
esac
if [ ! -f "$LIB" ]; then
    echo "error: $LIB not found (install the FIPS library first)" >&2
    exit 1
fi
# Struct sizes depend on configure options, so the helper is bound to this exact
# libwolfssl binary by its POSIX cksum (CRC + size); the wrapper refuses any other.
set -- $(cksum < "$LIB")
LIB_CRC="$1"; LIB_SIZE="$2"

$CC $SHARED -fPIC -O2 -I"$PREFIX/include" \
    -DWC_CSHARP_FIPS_BUILT_LIB_CRC="${LIB_CRC}U" -DWC_CSHARP_FIPS_BUILT_LIB_SIZE="${LIB_SIZE}" \
    "$HERE/native/fips_sizes.c" -o "$OUT"
echo "built $OUT (bound to $LIB: cksum $LIB_CRC, $LIB_SIZE bytes)"
echo "rebuild the helper after every reinstall of the library"
