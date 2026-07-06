#!/usr/bin/env bash
#
# Build the wolfSSL sources in <src_dir> with the given configure flags and
# install to <install_dir>. In CI <src_dir> is this checkout (the PR merge
# commit). The resulting <install_dir> is handed to a product build script so
# it can locate wolfSSL via --with-wolfssl=<install_dir>.
#
# Compile + install only; wolfSSL's own tests are not run here.
#
# The configure flags are one string (not separate args) and are `eval`-ed so a
# quoted CFLAGS/C_EXTRA_FLAGS group survives intact, e.g.
#   --enable-all CFLAGS="-DWC_RSA_DIRECT -DHAVE_AES_ECB"
# The string comes from our own caller workflows (trusted input).
#
# Usage: build-wolfssl.sh <src_dir> <install_dir> <configure_string>

set -euxo pipefail

src="$1"
prefix="$2"
configure="${3:-}"

cd "$src"
./autogen.sh
eval "./configure --prefix='$prefix' $configure"
make "-j$(nproc)"
make install
