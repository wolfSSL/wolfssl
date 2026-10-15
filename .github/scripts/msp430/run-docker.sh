#!/bin/sh
# Usage: sh .github/scripts/msp430/run-docker.sh [wolfssl-source-directory] [profiles...]
set -eu
harness=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
source_dir=${1:-$harness/../../..}
if [ "$#" -gt 0 ]; then shift; fi
source_dir=$(CDPATH='' cd -- "$source_dir" && pwd)
test -f "$source_dir/wolfcrypt/test/test.c"
output_dir=${MSP430_OUTPUT_DIR:-$source_dir/.msp430-sim-build}
cache_dir=${MSP430_CACHE_DIR:-$source_dir/.msp430-gcc-cache}
mkdir -p "$output_dir" "$cache_dir"
output_dir=$(CDPATH='' cd -- "$output_dir" && pwd)
cache_dir=$(CDPATH='' cd -- "$cache_dir" && pwd)

# This checksum is published on TI's MSP430-GCC-OPENSOURCE download page.
python3 - "$cache_dir/toolchain.tar.bz2" <<'PY'
import hashlib
from pathlib import Path
import sys
import urllib.request

archive = Path(sys.argv[1])
expected = 'b60851b61565e3ddd2193298a3fac5120c2402597174106cc5f8482b9e9986e6'
url = ('https://software-dl.ti.com/msp430/msp430_public_sw/'
       'mcu/msp430/MSPGCC/9_3_1_2/export/'
       'msp430-gcc-9.3.1.11_linux64.tar.bz2')
if not archive.exists():
    temporary = archive.with_suffix('.download')
    with urllib.request.urlopen(url, timeout=60) as response, temporary.open('wb') as out:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            out.write(block)
    temporary.replace(archive)
with archive.open('rb') as stream:
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
if digest.hexdigest() != expected:
    raise SystemExit('TI toolchain checksum mismatch: ' + str(archive))
print('TI MSP430 GCC archive SHA-256 verified', flush=True)
PY

# Keep buildx activity files in a writable location on restricted hosts.
cp "$harness/.dockerignore" "$cache_dir/.dockerignore"
BUILDX_CONFIG=${BUILDX_CONFIG:-${TMPDIR:-/tmp}/wolfssl-msp430-buildx} \
    docker build --platform linux/amd64 -t wolfssl-msp430-sim:local \
        -f "$harness/Dockerfile" "$cache_dir"
docker run --rm --platform linux/amd64 --network none \
    -e MSP430_HWMULT="${MSP430_HWMULT:-none}" \
    -e MSP430_TEST_TIMEOUT="${MSP430_TEST_TIMEOUT:-900}" \
    -v "$source_dir:/src:ro" -v "$harness:/harness:ro" \
    -v "$output_dir:/work" wolfssl-msp430-sim:local "$@"
