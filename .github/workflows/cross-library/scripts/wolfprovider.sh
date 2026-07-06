#!/usr/bin/env bash
# Compile-check wolfProvider against a locally-built wolfSSL.
#
# wolfProvider is an OpenSSL 3.x provider, so unlike the other products it also
# needs OpenSSL dev headers/libs (installed via the caller's apt_packages, e.g.
# libssl-dev) and an extra --with-openssl. NOTE: the exact flag set may need
# tuning per release; adjust the caller's wolfssl_configure / product_configure.
#
# Usage: wolfprovider.sh [-t <ref>] <wolfssl_install_dir> <repo> [product_configure...]
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$DIR/common.sh"

_prepare "$@"
set -x
if [ -x ./autogen.sh ]; then
    ./autogen.sh
fi
export PKG_CONFIG_PATH="${CL_INSTALL}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
./configure --with-wolfssl="$CL_INSTALL" --with-openssl=/usr "${CL_CONFIGURE[@]}" \
    CPPFLAGS="-I${CL_INSTALL}/include" \
    LDFLAGS="-L${CL_INSTALL}/lib -Wl,-rpath,${CL_INSTALL}/lib"
make "-j$(nproc)"
set +x
