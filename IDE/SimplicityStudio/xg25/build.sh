#!/usr/bin/env bash
# Generate and build the EFR32xG25 wolfCrypt test/benchmark project headlessly.
# Requires the Silicon Labs toolchain installed via SLT (see README.md).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOARD="${BOARD:-brd4270b}"
BUILD_DIR="${BUILD_DIR:-$HERE/build}"

# Resolve the SLT-managed toolchain from its own registries rather than
# hardcoding conan hash directories, which change on reinstall.
SILABS_HOME="${SILABS_HOME:-$HOME/.silabs}"
json_path() { # json_path <file> <key>
    python3 -c "import json,sys
d=json.load(open(sys.argv[1]))
k=sys.argv[2]
print(d[k][0]['path'] if isinstance(d,dict) else
      d[0]['extensions'][0]['path'])" "$1" "$2"
}

SDK="${SDK:-$(json_path "$SILABS_HOME/sdks.json" simplicity-sdk)}"
SLC="${SLC:-$(json_path "$SILABS_HOME/tools.json" slc-cli)/slc}"
GCC_DIR="${GCC_DIR:-$(json_path "$SILABS_HOME/tools.json" gcc-arm-none-eabi)/bin}"
JAVA_DIR="$(json_path "$SILABS_HOME/tools.json" java21)/bin"

export PATH="$JAVA_DIR:$GCC_DIR:$PATH"
ARM_GCC_DIR="$(dirname "$GCC_DIR")"
export ARM_GCC_DIR

echo "SDK   : $SDK"
echo "slc   : $SLC"
echo "gcc   : $(arm-none-eabi-gcc -dumpversion)"
echo "board : $BOARD"

# BUILD_DIR is deleted below, so refuse anything that is not clearly ours.
# It must resolve beneath this example directory: that rules out "/", $HOME,
# the repository root and any unrelated project someone points the variable at.
BUILD_PARENT="$(cd "$(dirname "$BUILD_DIR")" 2>/dev/null && pwd -P || true)"
if [ -z "$BUILD_PARENT" ]; then
    echo "BUILD_DIR parent does not exist: $BUILD_DIR" >&2
    exit 1
fi
BUILD_ABS="$BUILD_PARENT/$(basename "$BUILD_DIR")"
case "$BUILD_ABS" in
    "$HERE"/?*) ;;
    *)
        echo "Refusing to delete '$BUILD_ABS'" >&2
        echo "BUILD_DIR must be inside $HERE" >&2
        exit 1
        ;;
esac

rm -rf "$BUILD_ABS"
mkdir -p "$BUILD_ABS"
BUILD_DIR="$BUILD_ABS"

"$SLC" signature trust --sdk "$SDK" >/dev/null 2>&1 || true

"$SLC" generate \
    --sdk "$SDK" \
    --project-file "$HERE/wolfcrypt_test.slcp" \
    --output-type makefile \
    --with "$BOARD" \
    --destination "$BUILD_DIR" \
    --new-project --force

# slc only emits include directories that live inside the project, so add the
# wolfSSL root here. Appending to the generated fragment keeps the SDK's own
# INCLUDES intact, which passing INCLUDES= on the make command line would not.
WOLFSSL_ROOT="$(cd "$HERE/../../.." && pwd)"
printf '\nINCLUDES += -I%s\n' "$WOLFSSL_ROOT" >> "$BUILD_DIR/wolfcrypt_test.project.mak"

make -C "$BUILD_DIR" -f wolfcrypt_test.Makefile -j"$(nproc)"

echo
echo "Artifacts:"
find "$BUILD_DIR" -name "*.hex" -o -name "*.s37" -o -name "*.bin" | sed 's/^/  /'
