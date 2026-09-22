#!/bin/sh
# Build the size helper and run the C# FIPS wrapper test suite against an
# installed wolfSSL FIPS library.
#
# Usage: run-tests.sh <wolfssl-install-prefix>   (default: /usr/local)
#
# Set WOLFACVP_VECTORS to the fips/wolfACVP directory of a FIPS bundle to run
# the ACVP known-answer tests (aegisolve vectors); they report SKIP otherwise.
set -e
PREFIX="${1:-/usr/local}"
HERE="$(cd "$(dirname "$0")" && pwd)"

"$HERE/build-native.sh" "$PREFIX"
WOLFSSL_FIPS_LIB_DIR="$PREFIX/lib" \
    dotnet run --project "$HERE/../wolfCrypt-FIPS-Test/wolfCrypt-FIPS-Test.csproj" -c Release
