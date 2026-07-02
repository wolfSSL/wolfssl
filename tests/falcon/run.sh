#!/bin/sh
# run.sh
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# Build and run the Falcon keygen/sign/verify fuzzer against the in-tree
# library. Hunts for the intermittent "freshly signed message fails to verify"
# fault. Exit 0 = no failures, 1 = a mismatch was found (a *.repro artifact is
# left behind for replay), 2 = build/setup error, 77 = Falcon not built in.
#
# Run from the wolfssl repo root:  sh tests/falcon/run.sh [iters] [msgs]
set -u

ITERS="${1:-2000}"
MSGS="${2:-8}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WOLFROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

have_lib=no
[ -f "$WOLFROOT/src/.libs/libwolfssl.so" ] && have_lib=yes
[ -f "$WOLFROOT/src/.libs/libwolfssl.a" ] && have_lib=yes
if [ ! -f "$WOLFROOT/wolfssl/options.h" ] || [ "$have_lib" = no ]; then
    echo "error: $WOLFROOT is not configured/built with Falcon." >&2
    echo "  run: ./configure --enable-experimental --enable-falcon && make" >&2
    exit 2
fi

make -C "$SCRIPT_DIR" || exit 2

LD_LIBRARY_PATH="$WOLFROOT/src/.libs:${LD_LIBRARY_PATH:-}"
export LD_LIBRARY_PATH

echo "Running Falcon fuzzer: $ITERS keys/level, $MSGS msgs/key ..."
"$SCRIPT_DIR/falcon_fuzz" --level both --iters "$ITERS" --msgs "$MSGS" \
    --dump-dir "$SCRIPT_DIR"
status=$?

if [ "$status" -eq 0 ]; then
    echo "OK: no keygen/sign/verify failures detected."
elif [ "$status" -eq 1 ]; then
    echo "FAIL: a signature did not verify. See *.repro in $SCRIPT_DIR;" >&2
    echo "      replay with: $SCRIPT_DIR/falcon_fuzz --replay <file>" >&2
fi
exit $status
