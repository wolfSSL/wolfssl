#!/bin/sh
# Build the wolfssl_csharp_fips size helper against an installed wolfSSL FIPS
# library and place it next to libwolfssl. The helper is bound to that exact
# libwolfssl binary and must be rebuilt whenever the library is reinstalled.
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

case "$(uname -s)" in
    Darwin) LIB="$PREFIX/lib/libwolfssl.dylib" ;;
    *)      LIB="$PREFIX/lib/libwolfssl.so" ;;
esac
if [ ! -f "$LIB" ]; then
    echo "error: $LIB not found (install the FIPS library first)" >&2
    exit 1
fi
# Bind the helper to this exact library build: struct sizes depend on the
# library's configure options, so the wrapper refuses to use the helper with
# any other libwolfssl binary. POSIX cksum (CRC + size) of the file.
set -- $(cksum < "$LIB")
LIB_CRC="$1"; LIB_SIZE="$2"

$CC $SHARED -fPIC -O2 -I"$PREFIX/include" \
    -DWC_CSHARP_FIPS_BUILT_LIB_CRC="${LIB_CRC}U" -DWC_CSHARP_FIPS_BUILT_LIB_SIZE="${LIB_SIZE}" \
    "$HERE/native/fips_sizes.c" -o "$OUT"
echo "built $OUT (bound to $LIB: cksum $LIB_CRC, $LIB_SIZE bytes)"
echo "rebuild the helper after every reinstall of the library"
