#!/bin/bash
# Print the feature macros of a configured CMake build of wolfSSL, sorted,
# one per line.
#
#   cmake-config-defines.sh lib    BUILD_DIR   -D flags the library compiles
#                                              with
#   cmake-config-defines.sh header BUILD_DIR   #defines in wolfssl/options.h
#   cmake-config-defines.sh names  BUILD_DIR   names of library defines that
#                                              options.h does not export
#
# "lib" and "header" print whole definitions (name and value), so two build
# directories can be compared exactly. "names" is the check that every
# feature macro reaches applications: CMake applies WOLFSSL_DEFINITIONS to
# the library only, so a macro missing from cmake/options.h.in is silently
# absent from the generated header. Needs the Makefile generator (the
# default on Linux), which records the flags in flags.make.

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 lib|header|names BUILD_DIR" >&2
    exit 2
fi
mode=$1
dir=$2

# Build-only macros, not feature settings: they must not reach applications.
private='BUILDING_WOLFSSL|HAVE_CONFIG_H|WOLFSSL_DLL|wolfssl_EXPORTS'
private="$private|WOLFSSL_IGNORE_FILE_WARN"

lib_defs() {
    grep -h '^C_DEFINES' "$dir/CMakeFiles/wolfssl.dir/flags.make" |
        tr ' ' '\n' | grep '^-D' | sed 's/^-D//' | LC_ALL=C sort -u
}

header_defs() {
    grep '^#define' "$dir/wolfssl/options.h" | sed 's/^#define //' |
        LC_ALL=C sort -u
}

case "$mode" in
    lib)
        lib_defs
        ;;
    header)
        header_defs
        ;;
    names)
        LC_ALL=C comm -23 \
            <(lib_defs | sed 's/=.*//' | LC_ALL=C sort -u) \
            <(header_defs | sed 's/[ =].*//' | LC_ALL=C sort -u) |
            grep -v -x -E "$private" || true
        ;;
    *)
        echo "unknown mode: $mode" >&2
        exit 2
        ;;
esac
