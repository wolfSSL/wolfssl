#!/usr/bin/env python3
"""Generate an SBOM for a Zephyr module from a west build.

A Zephyr module compiles its sources into a Zephyr application through
`zephyr_library_sources(...)`, built by Zephyr/west rather than by the
product's own Makefile or CMake. So neither the Make nor the CMake SBOM target
sees those sources.

The most accurate route is to call the CMake helper from the module's own
CMakeLists after its last `zephyr_library_sources()`,
`wolfssl_compliance_tooling_add_sbom(TARGETS ${ZEPHYR_CURRENT_LIBRARY} ...)`.
Without that hook, this frontend reads the compile_commands.json that CMake
writes when west configures the build. The module's sources are the entries
under `--root` whose object Zephyr placed in the module's library directory,
`<build>/modules/<module name>/`. That set follows Kconfig and any CMake logic
the module uses, and it leaves out application files inside the module tree.

The configuration is Kconfig-driven, so by default this produces a
source-inventory SBOM. `--user-settings` records the module's -D flags and the
macros its settings header defines, preprocessed by the build's own compiler
with the module's compile command. `--options-h` records a flat `#define`
header instead.

Usage:
  zephyr_sbom.py --name NAME --compdb build/compile_commands.json \\
                 --root MODULE [--user-settings HEADER] [options]
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DRIVER = os.path.join(os.path.dirname(SCRIPT_DIR), "sbom-driver")

SRC_EXTS = ('.c', '.cc', '.cpp', '.cxx', '.s', '.asm')
_ARG_OPTS = ('-D', '-U', '-I', '-iquote', '-isystem', '-idirafter',
             '-imacros', '-include', '-o', '-MF', '-MT', '-MQ', '-x')
_NO_DUMP = ('-o', '-MF', '-MT', '-MQ', '-x', '-c', '-M', '-MM', '-MD', '-MMD',
            '-MP')
_HOST_OPTS = ('-D', '-U', '-I', '-iquote')


class ParseError(Exception):
    pass


def module_name(root):
    """The Zephyr module name: module.yml's name, else the directory name."""
    for yml in ('module.yml', 'module.yaml'):
        path = os.path.join(root, 'zephyr', yml)
        if os.path.isfile(path):
            try:
                with open(path, encoding='utf-8') as f:
                    lines = f.readlines()
            except (OSError, UnicodeDecodeError) as e:
                raise ParseError(f"cannot read {path}: {e}")
            for line in lines:
                m = re.match(r'name:\s*([^\s#]+)', line)
                if m:
                    return m.group(1).strip('"\'')
            break
    return os.path.basename(os.path.normpath(root))


def compdb_entries(compdb, root, name):
    """Return the module library's compile commands as [(source, entry)]
    for sources under root, plus the library sources outside it."""
    try:
        with open(compdb) as f:
            db = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ParseError(f"cannot read {compdb}: {e}")
    root = os.path.realpath(root) + os.sep
    picked, outside, seen = [], [], set()
    for e in db:
        if 'output' not in e:
            raise ParseError(f"{compdb} has no 'output' field; it needs "
                             "CMake 3.20 or later")
        if not e.get('file'):
            continue
        directory = e.get('directory', '')
        lib_dir = os.path.normpath(
            os.path.join(directory, 'modules', name)) + os.sep
        out = os.path.normpath(os.path.join(directory, e['output']))
        src = os.path.normpath(os.path.join(directory, e['file']))
        if (not out.startswith(lib_dir)
                or not src.lower().endswith(SRC_EXTS)):
            continue
        if os.path.realpath(src).startswith(root):
            picked.append((src, e))
        elif src not in seen:
            seen.add(src)
            outside.append(src)
    return picked, outside


def split_windows_command(cmd):
    """Split a command line the way CommandLineToArgvW does."""
    args, cur, have, quoted, i = [], [], False, False, 0
    while i < len(cmd):
        c = cmd[i]
        if c == '\\':
            n = len(cmd[i:]) - len(cmd[i:].lstrip('\\'))
            i += n
            if cmd[i:i + 1] == '"':
                cur.append('\\' * (n // 2))
                if n % 2:
                    cur.append('"')
                    i += 1
            else:
                cur.append('\\' * n)
            have = True
        elif c == '"':
            quoted, have, i = not quoted, True, i + 1
        elif c in ' \t' and not quoted:
            if have:
                args.append(''.join(cur))
                cur, have = [], False
            i += 1
        else:
            cur.append(c)
            have, i = True, i + 1
    if have:
        args.append(''.join(cur))
    return args


def _entry_tokens(entry):
    if entry.get('arguments'):
        toks = list(entry['arguments'])
    else:
        cmd = entry.get('command', '')
        try:
            toks = (split_windows_command(cmd) if os.name == 'nt'
                    else shlex.split(cmd))
        except ValueError as e:
            raise ParseError(f"cannot split the compile command of "
                             f"{entry.get('file')}: {e}")
    if not toks:
        raise ParseError(f"empty compile command for {entry.get('file')}")
    return toks


def _dump_macros(cc, flags, directory):
    try:
        r = subprocess.run([cc, '-dM', '-E', *flags, '-x', 'c', os.devnull],
                           cwd=directory or None, capture_output=True,
                           text=True)
    except OSError as e:
        raise ParseError(f"cannot run '{cc}': {e}")
    if r.returncode:
        raise ParseError(f"'{cc} -dM -E' failed:\n{r.stderr.strip()}")
    macros = {}
    for line in r.stdout.splitlines():
        m = re.match(r'#define (\S+)', line)
        if m:
            macros[m.group(1)] = line
    return macros


def _options(entry):
    """Yield (option, argument) pairs of a compile command after the
    compiler, with argument None for a flag and option None for a source."""
    toks = _entry_tokens(entry)
    i = 1
    while i < len(toks):
        t = toks[i]
        if t.startswith('@'):
            raise ParseError(f"response file {t} in the compile command of "
                             f"{entry.get('file')} is not supported")
        if t in _ARG_OPTS and i + 1 < len(toks):
            yield t, toks[i + 1]
            i += 2
            continue
        joined = next((o for o in _ARG_OPTS
                       if t.startswith(o) and t != o), None)
        if joined:
            yield joined, t[len(joined):]
        elif t.startswith('-'):
            yield t, None
        else:
            yield None, t
        i += 1


def _same_file(path, directory, settings_h):
    full = os.path.join(directory or '', path)
    return os.path.realpath(full) == os.path.realpath(settings_h)


def _defines(entries):
    """Merge the net -D/-U state of every entry into one -D/-U list, or
    raise ParseError when two entries disagree on a macro."""
    merged = {}
    for src, entry in entries:
        state = {}
        for opt, arg in _options(entry):
            if arg is None:
                continue
            if opt == '-D':
                name = re.split(r'[=(]', arg, maxsplit=1)[0]
                state[name] = arg if '=' in arg else arg + '=1'
            elif opt == '-U':
                state[arg] = None
        for name, value in state.items():
            if name in merged and merged[name][0] != value:
                raise ParseError(
                    f"the module's compile commands disagree on {name}: "
                    f"{merged[name][1]} and {src}")
            merged.setdefault(name, (value, src))
    flags = []
    for name in sorted(merged):
        value = merged[name][0]
        flags += ['-U', name] if value is None else ['-D', value]
    return flags


def capture_user_settings(entries, settings_h, hostcc=None):
    """Return the #define lines the module's -D flags and settings_h add.

    The capture runs the first C entry's compiler and flags, with the -D and
    -U flags merged across all C entries. With hostcc it runs that compiler
    with only the -D, -U, -I, -iquote and autoconf.h flags."""
    c_entries = [(src, e) for src, e in entries
                 if not src.lower().endswith(('.s', '.asm'))] or entries
    entry = c_entries[0][1]
    directory = entry.get('directory')
    base = []
    for opt, arg in _options(entry):
        if opt is None or opt in _NO_DUMP or opt in ('-D', '-U'):
            continue
        if opt in ('-include', '-imacros') and _same_file(arg, directory,
                                                          settings_h):
            continue
        if hostcc and opt not in _HOST_OPTS and not (
                opt == '-imacros' and os.path.basename(arg) == 'autoconf.h'):
            continue
        base += [opt] if arg is None else [opt, arg]
    cc = hostcc or _entry_tokens(entry)[0]
    defs = _defines(c_entries)
    before = _dump_macros(cc, base, directory)
    with_defs = _dump_macros(cc, base + defs, directory)
    after = _dump_macros(
        cc, base + defs + ['-include', os.path.abspath(settings_h)],
        directory)
    if after == with_defs:
        raise ParseError(f"{settings_h} adds no macros; the compile command "
                         f"may already include it or a copy of it")
    return sorted(line for name, line in after.items()
                  if before.get(name) != line)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--name', required=True, help='Package name for the SBOM.')
    ap.add_argument('--compdb', required=True,
                    help="The west build's compile_commands.json.")
    ap.add_argument('--root', required=True, help='The module directory.')
    ap.add_argument('--module-name', default=None,
                    help='Zephyr module name. Default: the name in '
                         'zephyr/module.yml, else the --root directory name.')
    ap.add_argument('--user-settings', default=None,
                    help="The module's settings header, captured with the "
                         "module's compile flags.")
    ap.add_argument('--hostcc', default=None,
                    help='Capture --user-settings with this host compiler '
                         'instead of the build\'s compiler and target flags.')
    ap.add_argument('--options-h', default=None,
                    help='Flat #define header to record as the build '
                         'configuration, instead of --source-only.')
    ap.add_argument('--driver', default=DEFAULT_DRIVER)
    ap.add_argument('--gen-sbom', default=None)
    ap.add_argument('--version', default=None)
    ap.add_argument('--version-file', default=None)
    ap.add_argument('--version-macro', default=None)
    ap.add_argument('--supplier', default=None)
    ap.add_argument('--component-type', default=None)
    ap.add_argument('--license-file', default=None)
    ap.add_argument('--copyright-start', default=None)
    ap.add_argument('--license-override', default=None)
    ap.add_argument('--license-text', default=None)
    ap.add_argument('--dep-wolfssl', default=None)
    ap.add_argument('--dep-wolfcrypt', default=None)
    ap.add_argument('--dep-openssl', default=None)
    ap.add_argument('--dep-version', action='append', default=[],
                    help='Dependency version, e.g. wolfssl=5.9.2 '
                         '(repeatable).')
    # In source-only mode the generator cannot read WOLFCRYPT_ONLY and will
    # say so unless the operator states it here.
    ap.add_argument('--crypto-only', default=None,
                    help='auto|yes|no, forwarded to the generator.')
    ap.add_argument('--cdx-out', default=None)
    ap.add_argument('--spdx-out', default=None)
    ap.add_argument('--srcs-out', default=None)
    ap.add_argument('--print-only', action='store_true')
    args = ap.parse_args()

    if args.user_settings and args.options_h:
        sys.exit("ERROR: pass only one of --user-settings and --options-h.")
    if args.hostcc and not args.user_settings:
        sys.exit("ERROR: --hostcc only applies to --user-settings.")
    for path, what in ((args.compdb, 'compilation database'),
                       (args.user_settings, '--user-settings')):
        if path and not os.path.isfile(path):
            sys.exit(f"ERROR: {what} not found: {path}")

    settings = None
    try:
        name = args.module_name or module_name(args.root)
        entries, outside = compdb_entries(args.compdb, args.root, name)
        if not entries:
            sys.exit(f"ERROR: {args.compdb} has no compile commands for "
                     f"module '{name}' from sources under {args.root}; "
                     f"check --root and --module-name.")
        if args.user_settings:
            settings = capture_user_settings(entries, args.user_settings,
                                             args.hostcc)
    except ParseError as e:
        sys.exit(f"ERROR: {e}")
    if outside:
        sys.stderr.write(
            f"WARNING: {len(outside)} source(s) of module '{name}' lie "
            f"outside --root (excluded):\n")
        for s in outside:
            sys.stderr.write(f"  - {s}\n")
    srcs = list(dict.fromkeys(src for src, _ in entries))

    if args.print_only:
        print(f"# {args.name}: {len(srcs)} sources")
        for s in srcs:
            print(f"  {s}")
        if settings is not None:
            print(f"\n# {len(settings)} macros from {args.user_settings}")
            for line in settings:
                print(f"  {line}")
        return

    tmps = []
    try:
        srcs_out = args.srcs_out
        if not srcs_out:
            fd, srcs_out = tempfile.mkstemp(
                prefix='wolfssl-compliance-tooling-zephyr-srcs-',
                suffix='.txt')
            os.close(fd)
            tmps.append(srcs_out)
        try:
            with open(srcs_out, 'w') as f:
                f.write('\n'.join(srcs) + '\n')
        except OSError as e:
            sys.exit(f"ERROR: cannot write {srcs_out}: {e}")

        cmd = [args.driver, '--srcs-file', srcs_out, '--name', args.name,
               '--root', args.root]
        if settings is not None:
            fd, opts = tempfile.mkstemp(
                prefix='wolfssl-compliance-tooling-zephyr-defs-', suffix='.h')
            tmps.append(opts)
            with os.fdopen(fd, 'w') as f:
                f.write('\n'.join(settings) + '\n')
            cmd += ['--options-h', opts]
        elif args.options_h:
            cmd += ['--options-h', args.options_h]
        else:
            cmd += ['--source-only']
        for flag, val in (('--version', args.version),
                          ('--version-file', args.version_file),
                          ('--version-macro', args.version_macro),
                          ('--supplier', args.supplier),
                          ('--component-type', args.component_type),
                          ('--license-file', args.license_file),
                          ('--copyright-start', args.copyright_start),
                          ('--license-override', args.license_override),
                          ('--license-text', args.license_text),
                          ('--dep-wolfssl', args.dep_wolfssl),
                          ('--dep-wolfcrypt', args.dep_wolfcrypt),
                          ('--dep-openssl', args.dep_openssl),
                          ('--crypto-only', args.crypto_only),
                          ('--gen-sbom', args.gen_sbom),
                          ('--cdx-out', args.cdx_out),
                          ('--spdx-out', args.spdx_out)):
            if val:
                cmd += [flag, val]
        for dv in args.dep_version:
            cmd += ['--dep-version', dv]

        kind = ("user-settings" if settings is not None
                else "options-h" if args.options_h else "source-inventory")
        print(f"Zephyr module SBOM: {len(srcs)} sources ({kind})")
        try:
            rc = subprocess.call(cmd)
        except OSError as e:
            sys.exit(f"ERROR: cannot run {args.driver}: {e}")
    finally:
        for t in tmps:
            if os.path.exists(t):
                os.remove(t)
    sys.exit(rc)


if __name__ == '__main__':
    main()
