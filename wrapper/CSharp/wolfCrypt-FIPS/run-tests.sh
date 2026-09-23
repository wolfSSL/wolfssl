#!/bin/sh
# Build the size helper and run the C# FIPS wrapper test suite against an
# installed wolfSSL FIPS library.
#
# Usage: run-tests.sh <wolfssl-install-prefix>   (default: /usr/local)
#
# Set WOLFACVP_VECTORS to the fips/wolfACVP directory of a FIPS bundle to run
# the ACVP known-answer tests (aegisolve vectors); they report SKIP otherwise.
#
# The wrapper targets net8.0 and net10.0. DOTNET_TFM selects the build to
# run (default net10.0); it runs on the matching .NET runtime, which must be
# installed (DOTNET_ROOT may point at a separate runtime install).
set -e
PREFIX="${1:-/usr/local}"
HERE="$(cd "$(dirname "$0")" && pwd)"

"$HERE/build-native.sh" "$PREFIX"
case "$(uname -s)" in Darwin) LIB="$PREFIX/lib/libwolfssl.dylib" ;; *) LIB="$PREFIX/lib/libwolfssl.so" ;; esac
"$HERE/tools/fips-bind-audit.sh" "$PREFIX/include" "$LIB"
TFM="${DOTNET_TFM:-net10.0}"
TEST="$HERE/../wolfCrypt-FIPS-Test"
dotnet build "$TEST/wolfCrypt-FIPS-Test.csproj" -c Release -f "$TFM" --nologo -v quiet
# Run the built executable directly rather than with "dotnet run", which
# replaces DOTNET_ROOT with the SDK's own install and so ignores a separately
# installed runtime.
WOLFSSL_FIPS_LIB_DIR="$PREFIX/lib" "$TEST/bin/Release/$TFM/wolfCrypt-FIPS-Test"
