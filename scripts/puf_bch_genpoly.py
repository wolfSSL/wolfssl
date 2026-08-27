#!/usr/bin/env python3
# puf_bch_genpoly.py
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

"""Generate and validate BCH(127, k, t) generator polynomials and
known-answer test (KAT) vectors for the wolfCrypt SRAM PUF (puf.c).

The field is GF(2^7) built from the primitive polynomial
p(x) = x^7 + x^3 + 1 (0x89), matching the in-tree gf_exp/gf_log tables.

Output for each shipped profile:
  - bch_genpoly[] bytes in puf.c layout (64-bit big-endian, low deg bits,
    leading x^deg coefficient implicit / masked off)
  - a few message -> 127-bit systematic codeword KAT vectors

The t=10 genpoly MUST reproduce the existing in-tree constant
{0x21,0xAB,0x81,0x5B,0xC7,0xEC,0x80,0x25}; the script asserts this before
emitting any other profile, so a bad field or convention fails loudly.

This script is deterministic and takes no input. Run:
    python3 scripts/puf_bch_genpoly.py
"""

import os
import re
import sys

M = 7
N = (1 << M) - 1            # 127
PRIM = 0x89                 # x^7 + x^3 + 1

# Profiles: t -> k (n-k = deg of generator polynomial). Only valid BCH(127)
# narrow-sense designed-distance profiles. See puf.h profile table.
PROFILES = [
    (7,  78),
    (10, 64),   # default; must match in-tree constant
    (13, 50),
    (15, 36),
]

# The shipped tables live here; --check parses them out and diffs.
PUF_C = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "wolfcrypt", "src", "puf.c")


def parse_puf_c(path):
    """Extract {t: (genpoly_bytes, deg)} from the #if WC_PUF_BCH_T ladder in
    wolfcrypt/src/puf.c. Parsing the real source is the point: a hardcoded
    copy in this script would still pass if someone edited puf.c."""
    src = open(path).read()
    out = {}
    # each arm: "WC_PUF_BCH_T == <t>" .. "bch_genpoly[..] = { .. };" .. "DEG <d>"
    pat = re.compile(
        r"WC_PUF_BCH_T\s*==\s*(\d+)\s*\n"
        r".*?bch_genpoly\s*\[[^\]]*\]\s*=\s*\{(.*?)\}\s*;"
        r".*?BCH_GENPOLY_DEG\s+(\d+)",
        re.S)
    for m in pat.finditer(src):
        t = int(m.group(1))
        body = m.group(2)
        vals = [int(x, 16) for x in re.findall(r"0[xX]([0-9a-fA-F]{1,2})", body)]
        out[t] = (vals, int(m.group(3)))
    return out


def build_gf():
    """Return (exp, log) tables for GF(2^7) with primitive poly 0x89."""
    exp = [0] * (N + 1)
    log = [0] * (N + 1)
    x = 1
    for i in range(N):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & (1 << M):
            x ^= PRIM
    exp[N] = exp[0]            # alpha^127 == alpha^0 == 1 (wrap)
    return exp, log


EXP, LOG = build_gf()


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[(LOG[a] + LOG[b]) % N]


def poly_mul_gf(p, q):
    """Multiply two polynomials with GF(2^7) coefficients (lists, index =
    power of x, element 0 = constant term)."""
    r = [0] * (len(p) + len(q) - 1)
    for i, pi in enumerate(p):
        if pi == 0:
            continue
        for j, qj in enumerate(q):
            if qj == 0:
                continue
            r[i + j] ^= gf_mul(pi, qj)
    return r


def cyclotomic_coset(i):
    """The 2-cyclotomic coset of i mod 127."""
    coset = set()
    v = i % N
    while v not in coset:
        coset.add(v)
        v = (v * 2) % N
    return coset


def minimal_poly(i):
    """Minimal polynomial of alpha^i: product over its coset of (x + alpha^j).
    Result has binary coefficients (each 0x00 or 0x01 as a GF element)."""
    m = [1]                                   # start with 1
    for j in cyclotomic_coset(i):
        m = poly_mul_gf(m, [EXP[j], 1])       # (alpha^j + x)
    # coefficients must be 0 or 1 (binary); verify
    for c in m:
        if c not in (0, 1):
            raise ValueError("minimal poly has non-binary coefficient")
    return m


def gen_poly(t):
    """Narrow-sense BCH generator polynomial = lcm of minimal polynomials of
    alpha^1 .. alpha^(2t). Returned as a binary-coefficient list (index =
    power of x)."""
    used = set()
    g = [1]
    for i in range(1, 2 * t + 1):
        coset = frozenset(cyclotomic_coset(i))
        if coset in used:
            continue
        used.add(coset)
        g = poly_mul_gf(g, minimal_poly(i))
    return g


def genpoly_bytes(g):
    """Pack g(x) into puf.c's 8..16 byte layout: a big-endian integer whose
    bit i is coefficient g_i, with the leading coefficient g_deg masked off
    (implicit). Byte count = ceil(deg / 8)."""
    deg = len(g) - 1
    assert g[deg] == 1, "generator must be monic"
    val = 0
    for i in range(deg):                      # exclude leading coeff
        if g[i]:
            val |= (1 << i)
    nbytes = (deg + 7) // 8
    # 64-bit style big-endian pack sized to nbytes (matches puf.c: byte 0 is
    # the most significant, top bit of byte 0 is the implicit/masked slot).
    out = []
    for b in range(nbytes):
        shift = 8 * (nbytes - 1 - b)
        out.append((val >> shift) & 0xFF)
    return deg, out


def bch_encode_ref(msg_bits, g):
    """Reference systematic encoder matching puf.c bch_encode(): codeword =
    [msg(k) | parity(deg)] MSB-first. msg_bits is a list of k bits (MSB-first
    message bit order). Returns list of n bits (MSB-first)."""
    deg = len(g) - 1
    k = len(msg_bits)
    reg = [0] * deg                           # remainder register, reg[0]=MSB
    for bit in msg_bits:
        fb = bit ^ reg[0]
        reg = reg[1:] + [0]                   # shift left
        if fb:
            # XOR non-leading generator coefficients g_{deg-1..0} into reg
            for p in range(deg):
                # reg position p holds coefficient of x^(deg-1-p)
                if g[deg - 1 - p]:
                    reg[p] ^= 1
    return list(msg_bits) + reg               # [msg | parity], n bits


def syndromes_zero(cw_bits, t):
    """Return True iff every narrow-sense syndrome S_1..S_2t of the codeword is
    zero, i.e. the bit list is a genuine BCH codeword. Mirrors puf.c's
    bch_syndrome_eval: bit j (MSB-first) is the coefficient of x^(n-1-j), so
    S_root = c(alpha^root) = XOR of alpha^(root*(n-1-j)) over the set bits."""
    n = len(cw_bits)
    for root in range(1, 2 * t + 1):
        s = 0
        for j, b in enumerate(cw_bits):
            if b:
                s ^= EXP[(root * (n - 1 - j)) % N]
        if s != 0:
            return False
    return True


def bits_to_hex(bits):
    """Pack an MSB-first bit list into bytes, byte-rounded."""
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (7 - (i % 8))
    return list(out)


def fmt_bytes(bs):
    return "{ " + ", ".join("0x%02X" % b for b in bs) + " }"


def main():
    check = "--check" in sys.argv[1:]

    # Sanity: exp table spot checks against known values.
    assert EXP[1] == 0x02 and EXP[7] == 0x09, "GF(2^7) table mismatch"

    shipped = parse_puf_c(PUF_C) if check else {}
    if check and len(shipped) != len(PROFILES):
        raise SystemExit("--check: parsed %d tables from %s, expected %d"
                         % (len(shipped), PUF_C, len(PROFILES)))

    if not check:
        print("/* Generated by scripts/puf_bch_genpoly.py - do not hand-edit */")
        print("/* Field GF(2^7), primitive poly 0x89 (x^7 + x^3 + 1) */\n")

    bad = 0
    for t, k in PROFILES:
        g = gen_poly(t)
        deg, bs = genpoly_bytes(g)
        if deg != N - k:
            raise SystemExit(
                "t=%d: computed deg %d != n-k %d" % (t, deg, N - k))

        # KAT self-check: the reference encoder must yield a genuine BCH
        # codeword (all 2t syndromes zero), confirming both the generator
        # polynomial and the encoder algebra for this profile.
        kats = []
        for seed in (0, 1, 2):
            msg_bits = [((seed * 131 + i * 37) >> (i % 5)) & 1
                        for i in range(k)]
            cw = bch_encode_ref(msg_bits, g)
            if not syndromes_zero(cw, t):
                raise SystemExit(
                    "t=%d: KAT codeword has nonzero syndrome" % t)
            kats.append((msg_bits, cw))

        if check:
            # Diff the freshly derived table against what puf.c actually
            # ships. This is the whole point of --check: a copy of the bytes
            # kept inside this script would pass even if puf.c were edited.
            if t not in shipped:
                print("FAIL t=%d: no table found in puf.c" % t)
                bad += 1
                continue
            got, gotdeg = shipped[t]
            if got != bs:
                print("FAIL t=%d: puf.c has %s, expected %s"
                      % (t, fmt_bytes(got), fmt_bytes(bs)))
                bad += 1
            elif gotdeg != deg:
                print("FAIL t=%d: puf.c BCH_GENPOLY_DEG %d, expected %d"
                      % (t, gotdeg, deg))
                bad += 1
            else:
                print("ok   t=%d k=%d deg=%d  %s" % (t, k, deg, fmt_bytes(bs)))
            continue

        print("/* t=%d  k=%d  deg=%d  (%d parity bytes) */" %
              (t, k, deg, len(bs)))
        print("static const byte bch_genpoly_t%d[%d] =" % (t, len(bs)))
        print("    %s;" % fmt_bytes(bs))
        for msg_bits, cw in kats:
            print("/*   KAT msg=%s" % fmt_bytes(bits_to_hex(msg_bits)))
            print("        cw =%s */" % fmt_bytes(bits_to_hex(cw)))
        print()

    if check:
        if bad:
            raise SystemExit("%d generator polynomial(s) in puf.c do NOT "
                             "match; regenerate or revert." % bad)
        print("all %d shipped generator polynomials verified against %s"
              % (len(PROFILES), os.path.normpath(PUF_C)))


if __name__ == "__main__":
    main()
