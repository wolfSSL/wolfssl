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

# Regression test for the mem_track.h memLock guard misalignment that
# previously broke multi-threaded FreeRTOS-class builds with
# WOLFSSL_TRACK_MEMORY + USE_WOLFSSL_MEMORY + !WOLFSSL_STATIC_MEMORY.
#
# The bug is preprocessor-only, so the test runs on a stock Linux host:
#   -U__linux__ -U__MACH__ -U__ZEPHYR__ suppresses the host autodefines
#   that would otherwise hide it. Stub FreeRTOS.h / semphr.h satisfy the
#   wc_port.h FREERTOS_TCP mutex typedef without needing a real RTOS.
#
# Exit 0 = mem_track.h still compiles in the non-Linux multi-threaded
# config, i.e. the fix is in place. Exit non-zero = the misalignment is
# back. Run from the wolfssl repo root.
set -u
cc -DWOLFSSL_USER_SETTINGS \
    -U__linux__ -U__MACH__ -U__ZEPHYR__ \
    -I tests/freertos-mem-track-repro \
    -I . \
    -c tests/freertos-mem-track-repro/repro.c \
    -o /dev/null
status=$?
if [ $status -eq 0 ]; then
    echo "OK: mem_track.h compiles for non-Linux multi-threaded config."
else
    echo "FAIL: mem_track.h compile broken for non-Linux multi-threaded" >&2
    echo "      config - the memLock guard misalignment may be back." >&2
fi
exit $status
