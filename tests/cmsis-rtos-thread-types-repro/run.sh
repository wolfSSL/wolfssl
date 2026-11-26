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

# Regression test for the GCC CMSIS-RTOS v1/v2 build: without
# WOLFSSL_MDK_ARM, wolfssl/wolfcrypt/types.h used to fall through to its
# generic threading branch and define WOLFSSL_THREAD as the MSVC-only
# __stdcall, so any translation unit including types.h failed to compile.
#
# The bug is type-level, so the test runs on a stock Linux host: the
# WOLFSSL_CMSIS_RTOS* define selects the CMSIS branches ahead of any host
# threading branch, and stub cmsis_os.h / cmsis_os2.h satisfy the wc_port.h
# includes without needing a real RTOS. gcc is called explicitly because
# clang accepts __stdcall on every target (only warning that it is ignored),
# so it would pass against the unfixed header.
#
# Exit 0 = both CMSIS-RTOS versions compile. Run from the wolfssl repo root.
set -u
status=0
for rtos in WOLFSSL_CMSIS_RTOS WOLFSSL_CMSIS_RTOSv2; do
    if gcc -DWOLFSSL_USER_SETTINGS -D"$rtos" \
            -I tests/cmsis-rtos-thread-types-repro \
            -I . \
            -c tests/cmsis-rtos-thread-types-repro/repro.c \
            -o /dev/null; then
        echo "OK: $rtos thread types compile with GCC."
    else
        echo "FAIL: $rtos thread types do not compile with GCC" >&2
        status=1
    fi
done
exit $status
