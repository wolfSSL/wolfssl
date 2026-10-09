#!/usr/bin/env python3
"""Generate an SBOM from an IAR Embedded Workbench project (.ewp).

This is the product-neutral form of wolfBoot's iar_sbom.py. IAR builds happen
inside the IDE and never touch a Makefile or CMake, so the compiled source set
and the preprocessor configuration live in the .ewp project file. This extractor
reads them out of the .ewp and feeds them to the shared driver (sbom-driver), so
an IAR-built product gets the same CycloneDX 1.6 + SPDX 2.3 SBOM as a Make- or
CMake-built one.

It parses:
  * the C compiler preprocessor defines (ICCARM -> CCDefines <state> entries)
  * the compiled source files (<file><name> ...), resolving $PROJ_DIR$

Usage:
  iar_sbom.py --name NAME path/to/project.ewp [options]
"""

import argparse
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SRC_EXTS = ('.c', '.cc', '.cpp', '.cxx', '.s', '.asm')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# The shared driver is the sibling of this frontends/ directory.
DEFAULT_DRIVER = os.path.join(os.path.dirname(SCRIPT_DIR), "sbom-driver")


def resolve_proj_dir(raw, proj_dir):
    """Resolve an IAR $PROJ_DIR$-relative, backslash path to an absolute path."""
    p = raw.replace('$PROJ_DIR$', proj_dir).replace('\\', '/')
    if not os.path.isabs(p):
        p = os.path.join(proj_dir, p)
    return os.path.normpath(p)


def parse_configs(root):
    """Return {config_name: [define, ...]} from each ICCARM CCDefines option."""
    configs = {}
    for cfg in root.findall('configuration'):
        name_el = cfg.find('name')
        cfg_name = name_el.text if name_el is not None else '(unnamed)'
        defines = []
        for settings in cfg.findall('settings'):
            sname = settings.find('name')
            if sname is None or sname.text != 'ICCARM':
                continue
            for data in settings.findall('data'):
                for option in data.findall('option'):
                    oname = option.find('name')
                    if oname is None or oname.text != 'CCDefines':
                        continue
                    for state in option.findall('state'):
                        if state.text:
                            defines.append(state.text.strip())
        configs[cfg_name] = defines
    return configs


def _excluded_from(el, cfg_name):
    """True if a <file> or <group> carries an <excluded> block naming
    cfg_name -- IAR drops it from that build configuration, so it is not
    compiled in."""
    excluded = el.find('excluded')
    if excluded is None:
        return False
    return any((c.text or '').strip() == cfg_name
               for c in excluded.findall('configuration'))


def _compiled_files(el, cfg_name):
    """Yield the <file> elements under el (the project or a <group>) that are
    not excluded from cfg_name.  An excluded <group> drops every file in it
    and in its nested groups."""
    for child in el:
        if _excluded_from(child, cfg_name):
            continue
        if child.tag == 'group':
            yield from _compiled_files(child, cfg_name)
        elif child.tag == 'file':
            yield child


def collect_sources(root, proj_dir, cfg_name):
    """Return (present, missing) absolute paths of the source files compiled in
    configuration cfg_name.  Files and groups IAR marks <excluded> for
    cfg_name are dropped; listing them would over-report the compiled source
    set."""
    srcs = []
    for file_el in _compiled_files(root, cfg_name):
        name_el = file_el.find('name')
        if name_el is None or not name_el.text:
            continue
        raw = name_el.text.strip()
        if not raw.lower().endswith(SRC_EXTS):
            continue
        srcs.append(resolve_proj_dir(raw, proj_dir))
    seen, present, missing = set(), [], []
    for s in srcs:
        if s in seen:
            continue
        seen.add(s)
        (present if os.path.isfile(s) else missing).append(s)
    return present, missing


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('ewp', help='Path to the IAR .ewp project file')
    ap.add_argument('--name', required=True, help='Package name for the SBOM.')
    ap.add_argument('--config', help='IAR configuration name (default: richest)')
    ap.add_argument('--driver', default=DEFAULT_DRIVER)
    ap.add_argument('--gen-sbom', default=None)
    ap.add_argument('--version', default=None)
    ap.add_argument('--version-file', default=None)
    ap.add_argument('--version-macro', default=None)
    ap.add_argument('--root', default=None)
    ap.add_argument('--license-file', default=None)
    # The .ewp records the -D tokens ICCARM was given, not the macros a
    # settings header derives from them. Without these two the capture reads
    # an empty translation unit and the recorded configuration is the -D list
    # alone.
    ap.add_argument('--settings-h', default=None,
                    help='Settings header to -include during macro capture '
                         '(e.g. wolfssl/wolfcrypt/settings.h).')
    ap.add_argument('--include-dir', action='append', default=[],
                    help='Include directory for the capture (repeatable), '
                         'typically the directory holding user_settings.h.')
    ap.add_argument('--crypto-only', default=None,
                    help='auto|yes|no, forwarded to the generator.')
    ap.add_argument('--cdx-out', default=None)
    ap.add_argument('--spdx-out', default=None)
    ap.add_argument('--srcs-out', default=None)
    ap.add_argument('--print-only', action='store_true')
    args = ap.parse_args()

    if not os.path.isfile(args.ewp):
        sys.exit(f"ERROR: .ewp not found: {args.ewp}")
    proj_dir = os.path.dirname(os.path.abspath(args.ewp))

    try:
        root = ET.parse(args.ewp).getroot()
    except ET.ParseError as e:
        sys.exit(f"ERROR: cannot parse {args.ewp}: {e}")

    configs = parse_configs(root)
    if not configs:
        sys.exit("ERROR: no <configuration> with ICCARM CCDefines found in .ewp")

    if args.config:
        if args.config not in configs:
            sys.exit(f"ERROR: config {args.config!r} not found. "
                     f"Available: {', '.join(configs)}")
        cfg_name = args.config
    else:
        # The configuration with the most defines is the real build config.
        cfg_name = max(configs, key=lambda k: len(configs[k]))

    defines = configs[cfg_name]
    srcs, missing = collect_sources(root, proj_dir, cfg_name)
    if not srcs:
        sys.exit("ERROR: no existing source files found in .ewp")
    if missing:
        sys.stderr.write(
            f"WARNING: {len(missing)} source(s) listed in the .ewp were not "
            f"found on disk and are excluded (e.g. build-time generated "
            f"files):\n")
        for m in missing:
            sys.stderr.write(f"  - {m}\n")

    cflags = ' '.join(f'-D{d}' for d in defines)

    if args.print_only:
        print(f"# IAR configuration: {cfg_name}")
        print(f"# {len(srcs)} sources, {len(defines)} defines")
        print("\n[defines]")
        for d in defines:
            print(f"  -D{d}")
        print("\n[sources]")
        for s in srcs:
            print(f"  {s}")
        return

    srcs_out, tmp = args.srcs_out, None
    if not srcs_out:
        fd, srcs_out = tempfile.mkstemp(prefix='wolfssl-compliance-tooling-iar-srcs-', suffix='.txt')
        os.close(fd)
        tmp = srcs_out
    with open(srcs_out, 'w') as f:
        f.write('\n'.join(srcs) + '\n')

    cmd = [args.driver, '--srcs-file', srcs_out, f'--cflags={cflags}',
           '--name', args.name]
    for flag, val in (('--version', args.version),
                      ('--version-file', args.version_file),
                      ('--version-macro', args.version_macro),
                      ('--root', args.root),
                      ('--license-file', args.license_file),
                      ('--settings-h', args.settings_h),
                      ('--crypto-only', args.crypto_only),
                      ('--gen-sbom', args.gen_sbom),
                      ('--cdx-out', args.cdx_out),
                      ('--spdx-out', args.spdx_out)):
        if val:
            cmd += [flag, val]
    for inc in args.include_dir:
        cmd += ['--include-dir', inc]

    print(f"IAR SBOM: configuration={cfg_name} "
          f"({len(srcs)} sources, {len(defines)} defines)")
    try:
        rc = subprocess.call(cmd)
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
    sys.exit(rc)


if __name__ == '__main__':
    main()
