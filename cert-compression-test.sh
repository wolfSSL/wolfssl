#!/usr/bin/env bash
# Configure wolfSSL for testing TLS 1.3 Certificate Compression (WOLFSSL_CERT_COMPRESSION).
# Extra args are passed through to ./configure, e.g.:
#   ./cert-compression-test.sh CFLAGS="-fsanitize=address -g"
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Regenerate configure if missing or configure.ac is newer.
if [ ! -x configure ] || [ configure.ac -nt configure ]; then
    ./autogen.sh
fi

./configure \
    --enable-cert-compression \
    --with-libz \
    --enable-debug \
    CFLAGS="-fsanitize=address -g" \
    "$@"
