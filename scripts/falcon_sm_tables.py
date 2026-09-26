#!/usr/bin/env python3
# falcon_sm_tables.py
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1335, USA

"""Generate and validate the constant tables of the Falcon smallest memory
signer (WOLFSSL_FALCON_SIGN_SMALLEST_MEM in wolfcrypt/src/falcon.c).

Self-adjoint FFT constants, for 1 <= k < 512 with 2^b <= k < 2^(b+1) and
phi = (4*brv_b(k - 2^b) + 1)*pi/2^(b+2), brv_b reversing b bits:
  falcon_sm_R[k] = 1/(2cos(phi))
  falcon_sm_C[k] = 4cos(phi)^2
  falcon_sm_D[k] = -tan(phi)
each rounded correctly to IEEE-754 binary64 (Decimal at 80 digits, then
float(str)). Entry 0 is unused and zero.

Negacyclic NTT twiddles mod p = 40961 for degree up to 1024, in the layout
of falcon_zetas_l5: falcon_sm_zetas_p[i] = psi^brv_10(i) and
falcon_sm_izetas_p[i] = psi^-brv_10(i), psi = g^((p-1)/2048) for the
smallest generator g of Z_p^*.

The second half of each table is only needed for Falcon-1024 and is emitted
under WOLFSSL_NO_FALCON_LEVEL5.

This script is deterministic and takes no input. Run:
    python3 scripts/falcon_sm_tables.py            # print the C tables
    python3 scripts/falcon_sm_tables.py --check    # diff against falcon.c
"""

import os
import re
import struct
import sys
from decimal import Decimal, getcontext

getcontext().prec = 80
PI = Decimal("3.14159265358979323846264338327950288419716939937510582097494"
             "459230781640628620899862803482534211706798")

TAB = 512
P = 40961
NTT_N = 1024

FALCON_C = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "wolfcrypt", "src", "falcon.c")


def cos_sin(x):
    """Taylor series for cos and sin; |x| < 2*pi, so 80 digits is ample."""
    x2 = x * x
    c = Decimal(1)
    s = x
    tc = Decimal(1)
    ts = x
    k = 1
    eps = Decimal(10) ** -78
    while True:
        tc = -tc * x2 / ((2 * k - 1) * (2 * k))
        ts = -ts * x2 / ((2 * k) * (2 * k + 1))
        if abs(tc) < eps and abs(ts) < eps:
            return c, s
        c += tc
        s += ts
        k += 1


def rev(bits, j):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (j & 1)
        j >>= 1
    return r


def to_bits(v):
    return struct.unpack("<Q", struct.pack("<d", float(str(v))))[0]


def fft_tables():
    R = [0]
    C = [0]
    D = [0]
    for k in range(1, TAB):
        b = k.bit_length() - 1
        phi = (4 * rev(b, k - (1 << b)) + 1) * PI / (Decimal(2) ** (b + 2))
        c, s = cos_sin(phi)
        R.append(to_bits(1 / (2 * c)))
        C.append(to_bits(4 * c * c))
        D.append(to_bits(-s / c))
    return R, C, D


def ntt_tables():
    assert all(P % d for d in range(2, int(P ** 0.5) + 1)), "p not prime"
    g = next(x for x in range(2, P)
             if all(pow(x, (P - 1) // f, P) != 1 for f in (2, 5)))
    psi = pow(g, (P - 1) // (2 * NTT_N), P)
    ipsi = pow(psi, P - 2, P)
    zetas = [pow(psi, rev(10, i), P) for i in range(NTT_N)]
    izetas = [pow(ipsi, rev(10, i), P) for i in range(NTT_N)]
    return zetas, izetas


def emit(ctype, name, vals, per, fmt):
    half = len(vals) // 2
    out = ["static const %s %s[] = {" % (ctype, name)]
    for lo, hi in ((0, half), (half, len(vals))):
        if lo == half:
            out.append("#ifndef WOLFSSL_NO_FALCON_LEVEL5")
        for i in range(lo, hi, per):
            out.append("    " +
                       ", ".join(fmt(v) for v in vals[i:min(i + per, hi)]) +
                       ",")
    out.append("#endif")
    out.append("};")
    return "\n".join(out)


def parse_falcon_c(path, name):
    """Return the numbers inside 'name[] = { ... };' in falcon.c."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r"\b%s\[\]\s*=\s*\{(.*?)\};" % re.escape(name), text,
                  re.S)
    if m is None:
        return None
    body = re.sub(r"^#.*$", "", m.group(1), flags=re.M)
    return [int(v.rstrip("ULul"), 0)
            for v in re.findall(r"0x[0-9A-Fa-f]+U?L*L?|\b\d+\b", body)]


def main():
    check = "--check" in sys.argv[1:]
    R, C, D = fft_tables()
    zetas, izetas = ntt_tables()
    tables = [
        ("fpr", "falcon_sm_R", R),
        ("fpr", "falcon_sm_C", C),
        ("fpr", "falcon_sm_D", D),
        ("word16", "falcon_sm_zetas_p", zetas),
        ("word16", "falcon_sm_izetas_p", izetas),
    ]

    # Spot checks: R[1] = sqrt(2)/2, C[1] = 2, D[1] = -1.
    assert R[1] == 0x3FE6A09E667F3BCD and C[1] == 0x4000000000000000
    assert D[1] == 0xBFF0000000000000

    if not check:
        print("/* Generated by scripts/falcon_sm_tables.py - do not "
              "hand-edit */")
        for ctype, name, vals in tables:
            if ctype == "fpr":
                print(emit(ctype, name, vals, 3,
                           lambda v: "0x%016XULL" % v))
            else:
                print(emit(ctype, name, vals, 11, lambda v: "%5d" % v))
        return 0

    bad = 0
    for ctype, name, vals in tables:
        got = parse_falcon_c(FALCON_C, name)
        if got is None:
            print("FAIL %s: not found in falcon.c" % name)
            bad += 1
        elif got != vals:
            first = next((i for i in range(min(len(got), len(vals)))
                          if got[i] != vals[i]), min(len(got), len(vals)))
            print("FAIL %s: %d entries in falcon.c, %d expected, first "
                  "difference at index %d" % (name, len(got), len(vals),
                                              first))
            bad += 1
        else:
            print("ok   %s (%d entries)" % (name, len(vals)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
