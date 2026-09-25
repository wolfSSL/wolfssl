#!/bin/sh
# Builds the size helper, runs the binding audit and the C# FIPS tests; ACVP KATs run when
# WOLFACVP_VECTORS=<bundle>/fips/wolfACVP. DOTNET_TFM selects net10.0 (default) or net8.0,
# DOTNET_ROOT a separate runtime install. Usage: run-tests.sh <prefix> (default /usr/local)
set -e
PREFIX="${1:-/usr/local}"
HERE="$(cd "$(dirname "$0")" && pwd)"

"$HERE/build-native.sh" "$PREFIX"
case "$(uname -s)" in Darwin) LIB="$PREFIX/lib/libwolfssl.dylib" ;; *) LIB="$PREFIX/lib/libwolfssl.so" ;; esac
"$HERE/tools/fips-bind-audit.sh" "$PREFIX/include" "$LIB"
TFM="${DOTNET_TFM:-net10.0}"
TEST="$HERE/../wolfCrypt-FIPS-Test"
dotnet build "$TEST/wolfCrypt-FIPS-Test.csproj" -c Release -f "$TFM" --nologo -v quiet
# Not "dotnet run": it replaces DOTNET_ROOT with the SDK's own install and so
# ignores a separately installed runtime.
WOLFSSL_FIPS_LIB_DIR="$PREFIX/lib" "$TEST/bin/Release/$TFM/wolfCrypt-FIPS-Test"
