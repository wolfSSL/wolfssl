#!/usr/bin/env bash
# Compile-check wolfssh against a locally-built wolfSSL.
# Usage: wolfssh.sh [-t <ref>] <wolfssl_install_dir> <repo> [product_configure...]
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$DIR/common.sh"
cross_build_autotools "$@"
