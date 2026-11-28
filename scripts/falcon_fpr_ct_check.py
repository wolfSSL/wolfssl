#!/usr/bin/env python3
# falcon_fpr_ct_check.py
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

"""Check that the integer fpr emulation in wolfcrypt/src/falcon.c compiles to
branch-free code.

The block from the "Low-level helpers" banner to the "Named constants" banner
is compiled to assembly with gcc and clang for a set of 32- and 64-bit targets
at -Os and -O2. A target fails if any fpr function contains a conditional
branch, apart from the one back-edge of the fixed-count loops in fpr_div and
fpr_sqrt (and fpr_inv, which inlines fpr_div), or calls into the compiler
runtime for anything but a 64-bit multiply.

The whole file is then compiled with -g for the default and smallest memory
signers at -Os, -O2 and -O3, and a target also fails if any conditional branch
that the line table attributes to the fpr block survives inlining into the
FFT, sampler and key generation code. Stub libc headers stand in for a
sysroot, so no libc is needed.

usage: falcon_fpr_ct_check.py [--allow-missing] [path/to/falcon.c]
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

PRELUDE = r'''
#if (defined(__riscv_xlen) && __riscv_xlen == 64) || defined(__x86_64__) || \
    defined(__aarch64__)
#define WC_64BIT_CPU
#endif
typedef unsigned int word32; typedef int sword32;
typedef unsigned long long word64; typedef long long sword64; typedef word64 fpr;
#define WC_MAYBE_UNUSED __attribute__((unused))
#define WC_INLINE inline
#define FALCON_HOT_INLINE inline __attribute__((always_inline))
extern const fpr fpr_one, fpr_ptwo63;
'''

# Overridable for other toolchains, e.g. RV_GCC=riscv64-zephyr-elf-gcc.
ARM_GCC = os.environ.get('ARM_GCC', 'arm-none-eabi-gcc')
RV_GCC = os.environ.get('RV_GCC', 'riscv64-unknown-elf-gcc')
A64_GCC = os.environ.get('A64_GCC', 'aarch64-linux-gnu-gcc')
XT_GCC = os.environ.get('XT_GCC', 'xtensa-esp32-elf-gcc')
XT3_GCC = os.environ.get('XT3_GCC', 'xtensa-esp32s3-elf-gcc')

TARGETS = [
    ('clang cortex-m0', ['clang', '--target=thumbv6m-none-eabi']),
    ('clang cortex-m3', ['clang', '--target=thumbv7m-none-eabi']),
    ('clang cortex-m7', ['clang', '--target=thumbv7em-none-eabi',
                         '-mcpu=cortex-m7']),
    ('clang cortex-m33', ['clang', '--target=thumbv8m.main-none-eabi',
                          '-mcpu=cortex-m33']),
    ('clang rv32imac', ['clang', '--target=riscv32-unknown-elf',
                        '-march=rv32imac', '-mabi=ilp32']),
    ('clang rv64gc', ['clang', '--target=riscv64-unknown-elf',
                      '-march=rv64gc', '-mabi=lp64d']),
    ('clang i386', ['clang', '--target=i386-linux-gnu']),
    ('clang x86_64', ['clang', '--target=x86_64-linux-gnu']),
    ('clang aarch64', ['clang', '--target=aarch64-linux-gnu']),
    ('gcc cortex-m0plus', [ARM_GCC, '-mthumb', '-mcpu=cortex-m0plus']),
    ('gcc cortex-m33', [ARM_GCC, '-mthumb', '-mcpu=cortex-m33']),
    ('gcc cortex-m7', [ARM_GCC, '-mthumb', '-mcpu=cortex-m7']),
    ('gcc rv32imac', [RV_GCC, '-march=rv32imac', '-mabi=ilp32']),
    ('gcc rv64gc', [RV_GCC, '-march=rv64gc', '-mabi=lp64d']),
    ('gcc i386', ['gcc', '-m32']),
    ('gcc x86_64', ['gcc', '-m64']),
    ('gcc aarch64', [A64_GCC]),
    ('gcc esp32', [XT_GCC]),
    ('gcc esp32s3', [XT3_GCC]),
]
OPTS = ['-Os', '-O2']
WHOLE_OPTS = ['-Os', '-O2', '-O3']

USER_SETTINGS = """
#define HAVE_FALCON
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFCRYPT_ONLY
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
"""
PROFILES = [
    ('default', USER_SETTINGS),
    ('smallest-mem', USER_SETTINGS + '#define WOLFSSL_FALCON_SIGN_SMALLEST_MEM\n'),
]

STUBS = {
    'string.h': """#include <stddef.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
char *strncpy(char *, const char *, size_t);
char *strncat(char *, const char *, size_t);
char *strstr(const char *, const char *);
char *strchr(const char *, int);
char *strrchr(const char *, int);
""",
    'stdlib.h': """#include <stddef.h>
void *malloc(size_t);
void *realloc(void *, size_t);
void free(void *);
void abort(void);
int atoi(const char *);
long strtol(const char *, char **, int);
""",
    'time.h': """#include <stddef.h>
typedef long time_t;
typedef long clock_t;
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday,
    tm_yday, tm_isdst; };
time_t time(time_t *);
struct tm *gmtime(const time_t *);
struct tm *gmtime_r(const time_t *, struct tm *);
""",
    'limits.h': """#define CHAR_BIT __CHAR_BIT__
#define SCHAR_MAX __SCHAR_MAX__
#define SCHAR_MIN (-SCHAR_MAX - 1)
#define UCHAR_MAX (SCHAR_MAX * 2 + 1)
#ifdef __CHAR_UNSIGNED__
#define CHAR_MIN 0
#define CHAR_MAX UCHAR_MAX
#else
#define CHAR_MIN SCHAR_MIN
#define CHAR_MAX SCHAR_MAX
#endif
#define SHRT_MAX __SHRT_MAX__
#define SHRT_MIN (-SHRT_MAX - 1)
#define USHRT_MAX (SHRT_MAX * 2 + 1)
#define INT_MAX __INT_MAX__
#define INT_MIN (-INT_MAX - 1)
#define UINT_MAX (INT_MAX * 2U + 1U)
#define LONG_MAX __LONG_MAX__
#define LONG_MIN (-LONG_MAX - 1L)
#define ULONG_MAX (LONG_MAX * 2UL + 1UL)
#define LLONG_MAX __LONG_LONG_MAX__
#define LLONG_MIN (-LLONG_MAX - 1LL)
#define ULLONG_MAX (LLONG_MAX * 2ULL + 1ULL)
""",
    'assert.h': '#define assert(x) ((void)0)\n',
    'errno.h': 'extern int errno;\n',
    'signal.h': '',
    'stdio.h': '',
    'ctype.h': '',
    'unistd.h': '',
}

LOOP_FUNCS = ('fpr_div', 'fpr_sqrt', 'fpr_inv')
RUNTIME_OK = ('__aeabi_lmul', '__muldi3')

# x86 jcc, ARM/Thumb bcc and cbz, AArch64 b.cc/cbz/tbz, RISC-V bcc and the
# beqz/bgtu style pseudo instructions, Xtensa bcc/bcci/bbc/bany and loopnez.
BRANCH = re.compile(r'^\s+(j(?!mp[lq]?\b|r\b|x\b|al\b|alr\b)[a-z]+'
                    r'|b(eq|ne|cc|cs|lo|hs|mi|pl|hi|ls|ge|lt|gt|le|vs|vc)'
                    r'(\.[nw])?'
                    r'|cbn?z|tbn?z|b\.[a-z]{2}'
                    r'|b(eq|ne|lt|ge|gt|le)z(\.n)?|b(lt|ge|gt|le)u'
                    r'|b(eq|ne|lt|ge)i|b(lt|ge)ui|b(any|none|all|nall)'
                    r'|bb[cs]i?|loop(nez|gtz))\s')
CALL = re.compile(r'^\s+(bl|blx|call[lq]?|jal|tail|call(0|4|8|12)'
                  r'|jmp[lq]?|b|b\.[nw]|j)\s+([\w.$@]+)')
LABEL = re.compile(r'^([A-Za-z_][\w$.]*):')


def fpr_block(lines):
    """Return the 0-based [start, end) index range of the fpr block, from the
    rule above "Low-level helpers" to the rule above "Named constants"."""
    start = next(i for i, l in enumerate(lines)
                 if l.startswith('/* Low-level helpers')) - 1
    end = next(i for i, l in enumerate(lines)
               if l.startswith('/* Named constants')) - 1
    return start, end


def extract(lines):
    start, end = fpr_block(lines)
    return PRELUDE + '\n'.join(lines[start:end]) + '\n'


def scan(asm):
    """Return ({function: branches}, {function: runtime calls})."""
    cur, branches, calls = None, {}, {}
    for line in asm.splitlines():
        m = LABEL.match(line)
        if m and not m.group(1).startswith('.') and \
                not re.match(r'L[0-9A-Z_]', m.group(1)):
            name = m.group(1).lstrip('_')
            cur = name if name.startswith('fpr_') or name == 'FPR' else None
            continue
        if cur is None:
            continue
        if BRANCH.match(line):
            branches[cur] = branches.get(cur, 0) + 1
        m = CALL.match(line)
        if m:
            callee = m.group(m.lastindex).lstrip('_')
            if not callee.startswith('fpr_') and callee != 'FPR' and \
                    not callee.startswith('.'):
                calls.setdefault(cur, set()).add(m.group(m.lastindex))
    return branches, calls


def scan_inlined(asm, lines, name):
    """Return {source line: branches} for branches the line table puts in
    the fpr block, wherever the code was inlined to."""
    start, end = fpr_block(lines)
    loops = set(i + 1 for i in range(start, end)
                if re.match(r'\s*for \(i = 0; i < 5[45]; i\+\+\)', lines[i]))
    files, line, hits = set(), None, {}
    for asm_line in asm.splitlines():
        m = re.match(r'\s+\.file\s+(\d+)\s+(?:"[^"]*"\s+)?"([^"]*)"', asm_line)
        if m and os.path.basename(m.group(2)) == name:
            files.add(m.group(1))
        m = re.match(r'\s+\.loc\s+(\d+)\s+(\d+)', asm_line)
        if m:
            line = int(m.group(2)) if m.group(1) in files else None
        if line and start < line <= end and line not in loops and \
                BRANCH.match(asm_line):
            hits[line] = hits.get(line, 0) + 1
    return hits


def whole_file_args(cc, tmp, profile):
    inc = os.path.join(tmp, 'inc')
    stub = os.path.join(tmp, 'stub')
    args = ['-g', '-ffreestanding', '-isystem', stub, '-I', REPO, '-I',
            os.path.join(inc, profile), '-DWOLFSSL_USER_SETTINGS']
    if 'clang' in os.path.basename(cc[0]):
        args.append('-nostdlibinc')
    return args


def problems(branches, calls):
    out = []
    for fn, n in sorted(branches.items()):
        if n > (1 if fn in LOOP_FUNCS else 0):
            out.append('%s: %d conditional branch(es)' % (fn, n))
    for fn, names in sorted(calls.items()):
        bad = sorted(c for c in names if c not in RUNTIME_OK)
        if bad:
            out.append('%s: calls %s' % (fn, ' '.join(bad)))
    return out


REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def main():
    args = sys.argv[1:]
    allow_missing = '--allow-missing' in args
    args = [a for a in args if a != '--allow-missing']
    src = args[0] if args else os.path.join(REPO, 'wolfcrypt', 'src',
                                            'falcon.c')
    with open(src) as f:
        lines = f.read().splitlines()

    failed = missing = 0
    with tempfile.TemporaryDirectory() as tmp:
        c_path = os.path.join(tmp, 'fpr.c')
        s_path = os.path.join(tmp, 'fpr.s')
        with open(c_path, 'w') as f:
            f.write(extract(lines))
        os.makedirs(os.path.join(tmp, 'stub'))
        for name, text in STUBS.items():
            with open(os.path.join(tmp, 'stub', name), 'w') as f:
                f.write(text)
        for profile, text in PROFILES:
            os.makedirs(os.path.join(tmp, 'inc', profile))
            with open(os.path.join(tmp, 'inc', profile, 'user_settings.h'),
                      'w') as f:
                f.write(text)
        for label, cc in TARGETS:
            if shutil.which(cc[0]) is None:
                print('MISSING %s (%s not found)' % (label, cc[0]))
                missing += 1
                continue
            for opt in OPTS:
                res = subprocess.run(cc + [opt, '-S', '-w', '-o', s_path,
                                           c_path],
                                     capture_output=True, text=True)
                if res.returncode != 0:
                    print('FAIL %s %s: compiler error\n%s' %
                          (label, opt, res.stderr))
                    failed += 1
                    continue
                with open(s_path) as f:
                    found = problems(*scan(f.read()))
                if found:
                    print('FAIL %s %s: %s' % (label, opt, '; '.join(found)))
                    failed += 1
                else:
                    print('ok   %s %s' % (label, opt))
            for profile, _ in PROFILES:
                for opt in WHOLE_OPTS:
                    res = subprocess.run(
                        cc + [opt, '-S', '-w', '-o', s_path] +
                        whole_file_args(cc, tmp, profile) + [src],
                        capture_output=True, text=True)
                    what = '%s %s %s inlined' % (label, profile, opt)
                    if res.returncode != 0:
                        print('FAIL %s: compiler error\n%s' %
                              (what, res.stderr))
                        failed += 1
                        continue
                    with open(s_path) as f:
                        hits = scan_inlined(f.read(), lines,
                                            os.path.basename(src))
                    if hits:
                        print('FAIL %s: %s' % (what, '; '.join(
                            'line %d: %d conditional branch(es)' % (k, v)
                            for k, v in sorted(hits.items()))))
                        failed += 1
                    else:
                        print('ok   %s' % what)

    if missing and not allow_missing:
        print('%d toolchain(s) missing' % missing)
        return 1
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
